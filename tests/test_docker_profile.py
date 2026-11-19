"""Regression tests for the four-container Docker profile."""
import threading

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from cbb.config import Settings
from cbb.crypto import verify_signature
from cbb.lab import SCENARIOS
from cbb.labsender import create_sender
from cbb.signer import create_signer
from test_api import app_client
from test_lab_workflow import finish

TOKEN = "t" * 40


def test_signer_accepts_report_domain(tmp_path):
    client = TestClient(create_signer(tmp_path, TOKEN))
    headers = {"Authorization": "Bearer " + TOKEN}
    public = client.get("/public-key", headers=headers).json()["public_key"]
    r = client.post("/sign", headers=headers, json={"domain": "CBB-REPORT-v1", "payload": {"sha256": "0" * 64, "size": 1}})
    assert r.status_code == 200, r.text
    assert verify_signature(r.json(), "CBB-REPORT-v1", public)["size"] == 1
    assert client.post("/sign", headers=headers, json={"domain": "CBB-NOPE-v1", "payload": {}}).status_code == 422


def test_virtual_mode_treats_localhost_and_loopback_as_one_origin(tmp_path):
    s = Settings(data=tmp_path, public_url="http://localhost:8765")
    assert {"http://localhost:8765", "http://127.0.0.1:8765"} <= s.origins()
    assert "http://evil.example" not in s.origins()
    s = Settings(data=tmp_path, public_url="http://localhost:8765", allowed_origins="http://cbb.lab:8765")
    assert "http://cbb.lab:8765" in s.origins()


def test_origin_guard_accepts_loopback_alias(app_client):
    app, client = app_client
    public = app.state.service.settings.public_url
    alias = public.replace("127.0.0.1", "localhost") if "127.0.0.1" in public else public.replace("localhost", "127.0.0.1")
    r = client.post("/api/v1/cases", json={"title": "Origin alias", "description": "x", "severity": 2}, headers={"origin": alias})
    assert r.status_code != 403 or r.json().get("code") != "ORIGIN_DENIED"
    r = client.post("/api/v1/cases", json={"title": "x", "description": "x", "severity": 2}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403 and r.json()["code"] == "ORIGIN_DENIED"


def test_sender_requires_token_and_private_allowlisted_target():
    client = TestClient(create_sender(TOKEN, ["localhost"]))
    body = {"scenario": "web-probes", "token": "x" * 32, "host": "localhost", "http_port": 40000, "tcp_port": 40001}
    assert client.post("/run", json=body).status_code == 401
    auth = {"Authorization": "Bearer " + TOKEN}
    assert client.post("/run", json={**body, "host": "example.com"}, headers=auth).status_code == 422
    assert client.post("/run", json={**body, "scenario": "rm -rf"}, headers=auth).status_code == 422
    assert client.get("/health/live").json()["status"] == "alive"


def test_sender_rejects_short_token():
    with pytest.raises(ValueError):
        create_sender("short", ["app"])


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_lab_runs_end_to_end_through_sender_service(app_client, monkeypatch, scenario):
    """App decoys + real sender HTTP service, the same path Docker Compose uses."""
    app, client = app_client
    lab = app.state.lab
    config = uvicorn.Config(create_sender(TOKEN, ["127.0.0.1"]), host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        threading.Event().wait(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        monkeypatch.setattr(lab.settings, "lab_sender_url", f"http://127.0.0.1:{port}")
        monkeypatch.setattr(lab.settings, "lab_sender_token", TOKEN)
        monkeypatch.setattr(lab.settings, "lab_callback_host", "127.0.0.1")
        lab.executor = lab.execute_sender
        assert lab.available()
        assert lab.check()["reachable"] is True
        r = client.post("/api/v1/lab/runs", json={"scenario": scenario})
        assert r.status_code == 202, r.text
        run = finish(app, client)
        assert run["state"] == "COMPLETE", run
        assert run["observed_count"] == SCENARIOS[scenario]["count"]
        assert run["preservation_state"] == "SEALED"
    finally:
        server.should_exit = True
        thread.join(5)


def test_live_monitor_polling_does_not_flood_custody(app_client):
    app, client = app_client
    service = app.state.service
    from sqlalchemy import func, select
    from cbb import db as D

    def custody_count():
        with service.db.read() as c:
            return c.execute(select(func.count()).select_from(D.custody)).scalar()

    client.get("/api/v1/live/events?limit=20")
    before = custody_count()
    for _ in range(5):
        assert client.get("/api/v1/live/events?limit=20").status_code == 200
    assert custody_count() == before
