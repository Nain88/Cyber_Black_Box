from datetime import datetime, timedelta, timezone
import json
import zipfile

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from cbb import db as D
from cbb.evidence_health import evidence_health
from cbb.verify import verify_package
from cbb.witness import create_witness
from test_core import service, ingest, wire
from test_api import app_client


def test_malformed_import_has_no_collector_side_effect(app_client):
    _, client = app_client
    case = client.get("/api/v1/cases").json()[0]
    before = client.get("/api/v1/collectors").json()
    response = client.post("/api/v1/imports", json={"case_id": case["id"], "format": "jsonl",
                                                    "source_type": "lab.fixture", "content": "bad JSON"})
    assert response.status_code == 422
    assert client.get("/api/v1/collectors").json() == before


def test_health_recovers_and_is_admin_only(app_client):
    app, client = app_client
    enrollment = client.post("/api/v1/enrollments", json={"name": "Health fixture"}).json()
    collector = client.post("/api/v1/collectors/enroll", json={"token": enrollment["token"]}).json()
    current = datetime.now(timezone.utc)
    srv = app.state.service
    with srv.db.tx() as conn:
        conn.execute(update(D.collectors).where(D.collectors.c.id == collector["collector_id"])
                     .values(last_heartbeat=(current - timedelta(seconds=100)).isoformat()))
        job = srv.create_job(conn, "analyze", None, {})
        conn.execute(update(D.jobs).where(D.jobs.c.id == job)
                     .values(created_at=(current - timedelta(seconds=130)).isoformat()))
    health = client.get("/api/v1/health/evidence").json()
    assert health["analysis_delayed"] and len(health["issues"]) == 2
    assert health["staged_receipts"] == 0
    assert client.post("/api/v1/collectors/heartbeat", headers={"Authorization": "Bearer " + collector["token"]},
                       json={"network_inputs": [{"state": "MISSING"}]}).status_code == 200
    with srv.db.read() as conn:
        assert any(issue["issue"] == "Collector reported errors" for issue in evidence_health(conn, 120)["issues"])
    assert client.post("/api/v1/collectors/heartbeat", headers={"Authorization": "Bearer " + collector["token"]},
                       json={"network_inputs": [{"state": "READABLE"}]}).status_code == 200
    with srv.db.tx() as conn:
        conn.execute(update(D.jobs).where(D.jobs.c.id == job).values(state="COMPLETE"))
    assert client.get("/api/v1/health/evidence").json()["issues"] == []
    with TestClient(app) as anonymous:
        assert anonymous.get("/api/v1/health/evidence").status_code == 401


def test_specific_rules_match_sealed_evidence_without_duplicate_alerts(service):
    def event(provider):
        return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                f'<Provider Name="{provider}"/><EventID>4719</EventID></System></Event>').encode()

    modification = {"path": "fixture.txt", "action": "modified", "previous_sha256": "a" * 64,
                    "sha256": "b" * 64, "severity": 1}
    batch = [
        wire("1", event("Microsoft-Windows-Security-Auditing"), source_type="windows.event",
             event_type="windows.event", raw_media_type="application/xml"),
        wire("2", event("AnotherProvider"), source_type="windows.event",
             event_type="windows.event", raw_media_type="application/xml"),
        wire("3", json.dumps(modification).encode(), source_type="fim", event_type="file.modified"),
        wire("4", json.dumps({**modification, "sha256": "a" * 64}).encode(),
             source_type="fim", event_type="file.modified"),
    ]
    receipts = service.accept(service.test_collector, batch)
    service.seal_pending()
    expected = {"WIN-AUDIT-POLICY/1.0": receipts[0]["evidence_id"],
                "FIM-CONTENT-CHANGED/1.0": receipts[2]["evidence_id"]}
    with service.db.read() as conn:
        assert dict(conn.execute(select(D.alerts.c.rule_id, D.alerts.c.evidence_id)).all()) == expected
    for receipt in receipts:
        service.analyze(receipt["evidence_id"])
    with service.db.read() as conn:
        assert len(conn.execute(select(D.alerts)).all()) == 2


def test_offline_verification_checks_separately_retained_checkpoint_and_receipt(service, tmp_path, capsys):
    receipt = ingest(service)[0]
    key = service.deployment["public_key"]
    snapshot = {"id": "fixture", "title": "Fixture", "version": 1, "status": "OPEN",
                "description": "", "conclusion": None}
    result = service.make_export("fixture", "system", [receipt["evidence_id"]], 1, snapshot, [])
    package = service.root / "exports" / (result["export_id"] + ".zip")
    with zipfile.ZipFile(package) as archive:
        checkpoint = json.loads(archive.read("checkpoint.json"))
    assert verify_package(package, key, trusted_checkpoint=checkpoint)["assurance"] == "RETAINED_CHECKPOINT_MATCHED"
    with TestClient(create_witness(tmp_path / "separate-witness", key)) as witness:
        response = witness.post("/checkpoints", json=checkpoint)
        assert response.status_code == 200, response.text
        witness_key = witness.get("/public-key").json()["public_key"]
        payload = checkpoint["payload"]
        bundle = witness.get(f"/checkpoints/{payload['deployment_id']}/by-sequence/{payload['checkpoint_seq']}").json()
        assert bundle == {"checkpoint": checkpoint, "receipt": response.json()}
    assert verify_package(package, key, witness_bundle=bundle, witness_public_key=witness_key)["assurance"] == "WITNESS_RECEIPT_VERIFIED"
    from cbb.cli import main
    bundle_path = tmp_path / "witness.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    assert main(["verify-package", str(package), "--public-key", key, "--witness-bundle", str(bundle_path),
                 "--witness-public-key", witness_key]) == 0
    assert json.loads(capsys.readouterr().out)["assurance"] == "WITNESS_RECEIPT_VERIFIED"
    later = service.checkpoint()
    assert verify_package(package, key, trusted_checkpoint=later)["status"] == "INVALID"
    assert verify_package(package, key, witness_bundle={**bundle, "checkpoint": later},
                          witness_public_key=witness_key)["status"] == "INVALID"
    tampered = tmp_path / "changed.zip"
    with zipfile.ZipFile(package) as original, zipfile.ZipFile(tampered, "w") as changed:
        for name in original.namelist():
            changed.writestr(name, b"updated" if name == "report.html" else original.read(name))
    assert verify_package(tampered, key, trusted_checkpoint=checkpoint)["status"] == "INVALID"
