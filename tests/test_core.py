import base64
import json
import time
import zipfile
import pytest
from sqlalchemy import select, update, text
from sqlalchemy.exc import IntegrityError
from cbb import db as D
from cbb.config import Settings
from cbb.crypto import uid, now, sha, canon, strict_json
from cbb.service import Service, row
from cbb.schema import normalize
from cbb.verify import verify_package


@pytest.fixture
def service(tmp_path):
    s=Service(Settings(data=tmp_path,workers=False))
    with s.db.tx() as c:
        c.execute(D.enrollments.insert().values(id=uid(),token_hash=sha(b"test"),name="Fixture",os="test",expires=time.time()+600,used=False))
    cred=s.enroll("test")
    with s.db.read() as c:s.test_collector=row(c,select(D.collectors).where(D.collectors.c.id==cred["collector_id"]))
    yield s
    s.db.engine.dispose()


def wire(seq="1",raw=b'{"summary":"Fixture","severity":3}',**changes):
    stamp="2026-10-29T10:00:00.000Z"
    return {"boot_id":"test-session","source_seq":seq,"source_type":"lab.fixture","event_type":"auth.failure","collected_at":stamp,"original_timestamp":stamp,"raw_base64":base64.b64encode(raw).decode(),"raw_sha256":sha(raw),**changes}


def ingest(service,count=1):
    result=service.accept(service.test_collector,[wire(str(i+1)) for i in range(count)])
    service.seal_pending();return result


def test_durable_receipt_idempotency_and_conflict(service):
    one=service.accept(service.test_collector,[wire()])[0]
    duplicate=service.accept(service.test_collector,[wire()])[0]
    conflict=service.accept(service.test_collector,[wire(raw=b'{}')])[0]
    assert one["preservation_state"]=="STAGED" and duplicate["evidence_id"]==one["evidence_id"]
    assert duplicate["outcome"]=="duplicate" and conflict["outcome"]=="conflict"
    service.seal_pending()
    with service.db.read() as c:
        record=row(c,select(D.evidence));assert service.read_raw(c,record)==b'{"summary":"Fixture","severity":3}'
        assert service.chain(c,"evidence")["head_sequence"]==1


def test_mixed_batch_rejects_invalid_keeps_good(service):
    result=service.accept(service.test_collector,[wire(),wire("2",raw_sha256="0"*64)])
    assert [r["outcome"] for r in result]==["accepted","rejected"]


def test_checkpoint_raw_tamper_and_manifest_tamper(service):
    ingest(service,2);service.checkpoint();assert service.verify()["status"]=="VALID"
    assert service.verify()["assurance"]=="LOCAL_CHECK_ONLY"
    with service.db.read() as c:seg=row(c,select(D.segments))
    manifest=(service.root/seg["path"]).with_suffix(".manifest.json")
    original=manifest.read_bytes();manifest.write_bytes(original+b" ")
    assert "MANIFEST_MODIFIED" in {r["code"] for r in service.verify()["failures"]}
    manifest.write_bytes(original)
    archive=service.root/seg["path"];data=archive.read_bytes();archive.write_bytes(data.replace(b"raw_base64",b"raw_bxse64",1))
    result=service.verify();assert result["status"]=="INVALID" and result["unavailable"]==1


def test_immutable_records_and_external_checkpoint_detect_tail_loss(service):
    ingest(service,2);checkpoint=service.checkpoint()
    with pytest.raises(IntegrityError):
        with service.db.tx() as c:c.execute(update(D.evidence).values(summary="rewritten"))
    # Model a privileged DB attacker who can remove triggers and rewrite the index.
    with service.db.tx() as c:
        c.execute(text("DROP TRIGGER immutable_evidence_DELETE"));c.execute(text("DELETE FROM evidence WHERE sequence=2"))
        first=row(c,select(D.evidence));c.execute(update(D.chains).where(D.chains.c.purpose=="evidence").values(head_sequence=1,head_hash=first["record_hash"]))
    assert "CHECKPOINT_MISMATCH" in {f["code"] for f in service.verify(checkpoint)["failures"]}


def test_staged_receipt_survives_restart_and_orphan_bytes(service):
    accepted=service.accept(service.test_collector,[wire()])[0]
    fresh=Service(Settings(data=service.root,workers=False));fresh.seal_pending()
    with fresh.db.read() as c:assert row(c,select(D.receipts).where(D.receipts.c.id==accepted["receipt_id"]))["state"]=="SEALED"
    fresh.checkpoint();assert fresh.verify()["status"]=="VALID";fresh.db.engine.dispose()


def test_export_frozen_case_and_offline_verifier(service):
    result=ingest(service);actor=uid();cid=uid()
    with service.db.tx() as c:
        c.execute(D.users.insert().values(id=actor,username="owner",role="investigator",active=True,created_at=now()))
        c.execute(D.cases.insert().values(id=cid,title="Current title",description="Current",owner_id=actor,status="OPEN",version=2,severity=1,hold=True,created_at=now(),updated_at=now()))
        snapshot=row(c,select(D.cases).where(D.cases.c.id==cid));snapshot["title"]="Frozen title";snapshot["version"]=1
    output=service.make_export(cid,actor,[result[0]["evidence_id"]],1,snapshot,[])
    path=service.root/"exports"/(output["export_id"]+".zip")
    assert verify_package(path,service.deployment["public_key"])["status"]=="VALID"
    with zipfile.ZipFile(path) as z:assert b"Frozen title" in z.read("report.html")
    bad=service.root/"bad.zip"
    with zipfile.ZipFile(path) as src,zipfile.ZipFile(bad,"w") as dst:
        for name in src.namelist():dst.writestr(name,b"changed" if name=="report.html" else src.read(name))
    assert verify_package(bad,service.deployment["public_key"])["status"]=="INVALID"


def test_strict_input_and_windows_provider_scoping(service):
    for invalid in (b'{"a":1,"a":2}',b'{"a":NaN}',b'['*30+b'0'+b']'*30):
        with pytest.raises(ValueError):strict_json(invalid)
    xml=b'<Event><System><Provider Name="Microsoft-Windows-Kernel-General"/><EventID>1</EventID></System></Event>'
    w=wire(raw=xml,source_type="windows.event",event_type="windows.event",raw_media_type="application/xml")
    assert normalize(w,service.test_collector,"id",now(),{})["event_type"]=="windows.event"


def test_lost_signing_key_fails_closed(service):
    (service.root/"keys/signing.pem").unlink()
    with pytest.raises(ValueError,match="Signing key does not match"):Service(Settings(data=service.root,workers=False))


@pytest.mark.parametrize("source_type,raw", [
    ("lab.fixture", b'{"severity":null}'),
    ("lab.fixture", b'{"severity":{}}'),
    ("lab.fixture", b'{"severity":"invalid"}'),
    ("suricata.eve", b'{"event_type":"alert","alert":{"severity":[]}}'),
])
def test_malformed_severity_preserves_raw_and_does_not_stall(service, source_type, raw):
    accepted = service.accept(service.test_collector, [
        wire("1", raw=raw, source_type=source_type), wire("2")])
    service.seal_pending()
    with service.db.read() as c:
        for result, expected in zip(accepted, [raw, b'{"summary":"Fixture","severity":3}']):
            receipt = row(c, select(D.receipts).where(D.receipts.c.id == result["receipt_id"]))
            assert receipt["state"] == "SEALED"
            evidence = row(c, select(D.evidence).where(D.evidence.c.id == result["evidence_id"]))
            assert service.read_raw(c, evidence) == expected
        first = row(c, select(D.evidence).where(D.evidence.c.id == accepted[0]["evidence_id"]))
        assert "PARSE_ERROR" in json.loads(first["envelope"])["quality_flags"]


@pytest.mark.parametrize("payload", [b'{"value":1e999}', b'{"value":"\\ud800"}'])
def test_strict_json_rejects_nonfinite_and_invalid_unicode(payload):
    with pytest.raises(ValueError):
        strict_json(payload)



def test_out_of_range_timezone_is_unparseable():
    from cbb.schema import parse_time
    assert parse_time("0001-01-01T00:00:00+01:00") is None


def test_sealing_quarantines_one_parser_type_error_and_continues(service, monkeypatch):
    import cbb.service as module
    accepted = service.accept(service.test_collector, [wire("1"), wire("2")])
    original = module.normalize
    def parser(wire_value, *args):
        if wire_value["source_seq"] == "1":
            raise TypeError("Malformed parser field")
        return original(wire_value, *args)
    monkeypatch.setattr(module, "normalize", parser)
    service.seal_pending()
    with service.db.read() as c:
        states = [row(c, select(D.receipts).where(D.receipts.c.id == item["receipt_id"]))["state"] for item in accepted]
    assert states == ["QUARANTINED", "SEALED"]


@pytest.mark.parametrize("source,media,raw", [
    ("suricata.eve", "application/json", b'{"timestamp":"2026-10-29T10:00:00Z","event_type":"alert"}'),
    ("windows.event", "application/xml", b'<Event><System><TimeCreated SystemTime="2026-10-29T10:00:00Z"/></System></Event>'),
    ("zeek", "application/json", b'{"ts":1793268000}'),
])
def test_source_timestamp_finalizes_quality_flags(service, source, media, raw):
    event = wire(raw=raw, source_type=source, raw_media_type=media, original_timestamp=None)
    normalized = normalize(event, service.test_collector, "test", "2026-10-29T10:00:00Z", {})
    assert normalized["occurred_at"] is not None
    assert normalized["time_quality"]["parsed"]
    assert "UNKNOWN_EVENT_TIME" not in normalized["quality_flags"]


@pytest.mark.parametrize("revocation", ["inactive", "role", "membership", "evidence"])
def test_queued_export_rechecks_authorization(service, revocation, monkeypatch):
    from cbb.service import DomainError
    actor, owner, cid, eid = uid(), uid(), uid(), uid()
    with service.db.tx() as c:
        for ident in (actor, owner):
            c.execute(D.users.insert().values(id=ident, username=ident, role="investigator", active=True, created_at=now()))
        c.execute(D.cases.insert().values(id=cid, title="Lab", owner_id=owner, status="OPEN", version=1, created_at=now(), updated_at=now()))
        if revocation != "membership":
            c.execute(D.case_members.insert().values(case_id=cid,user_id=actor))
        if revocation == "inactive": c.execute(update(D.users).where(D.users.c.id==actor).values(active=False))
        if revocation == "role": c.execute(update(D.users).where(D.users.c.id==actor).values(role="auditor"))
    def forbidden(*args, **kwargs):
        pytest.fail("Revoked job must not generate an export")
    monkeypatch.setattr(service, "make_export", forbidden)
    with pytest.raises(DomainError):
        service.run_job({"id":uid(), "kind":"export", "actor_id":actor, "case_id":cid, "payload":json.dumps({"evidence_ids":[eid],"case_version":1})})
