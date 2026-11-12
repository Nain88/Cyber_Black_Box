import json
import pytest
from fastapi.testclient import TestClient
from cbb.api import create_app
from cbb.config import Settings
from cbb.crypto import now


@pytest.fixture
def app_client(tmp_path):
    app=create_app(Settings(data=tmp_path,workers=False))
    with TestClient(app) as client:
        token=app.state.service.bootstrap_file.read_text()
        assert client.post("/api/v1/admin/setup",json={"token":token,"username":"test-admin","password":"valid-test-password-123"}).status_code==200
        login=client.post("/api/v1/auth/session",json={"username":"test-admin","password":"valid-test-password-123"}).json()
        client.headers["x-csrf-token"]=login["csrf"]
        yield app,client
    app.state.service.db.engine.dispose()


def test_sessions_csrf_and_origin(app_client):
    app,c=app_client
    assert c.get("/api/v1/overview").json()["cases"]==1
    assert c.post("/api/v1/enrollments",json={},headers={"x-csrf-token":"wrong"}).status_code==403
    assert c.post("/api/v1/enrollments",json={},headers={"origin":"https://evil.example"}).status_code==403
    assert c.post("/api/v1/enrollments",content='{"name":"a","name":"b"}',headers={"content-type":"application/json"}).status_code==400
    assert c.delete("/api/v1/auth/session").status_code==200
    assert c.get("/api/v1/evidence").status_code==401


def test_case_scope_optimistic_concurrency_and_reviewer(app_client):
    app,c=app_client
    case=c.get("/api/v1/cases").json()[0]
    response=c.post("/api/v1/users",json={"username":"review-user","password":"valid-review-password","role":"reviewer"})
    assert response.status_code==200
    reviewer_id=response.json()["id"]
    assert c.patch("/api/v1/cases/"+case["id"],json={"version":0,"title":"stale"}).status_code==409
    assert c.post("/api/v1/cases/"+case["id"]+"/members",json={"user_id":reviewer_id}).status_code==200
    with TestClient(app) as r:
        auth=r.post("/api/v1/auth/session",json={"username":"review-user","password":"valid-review-password"}).json();r.headers["x-csrf-token"]=auth["csrf"]
        assert len(r.get("/api/v1/cases").json())==1
        assert r.post("/api/v1/cases",json={"title":"not allowed"}).status_code==403
        assert r.post("/api/v1/cases/"+case["id"]+"/notes",json={"body":"Reviewed"}).status_code==200
        assert c.delete("/api/v1/cases/"+case["id"]+"/members/"+reviewer_id).status_code==200
        assert r.get("/api/v1/cases/"+case["id"]).status_code==404


def test_single_use_enrollment_and_revocation(app_client):
    app,c=app_client
    token=c.post("/api/v1/enrollments",json={"name":"fixture","os":"fixture"}).json()["token"]
    enrolled=c.post("/api/v1/collectors/enroll",json={"token":token}).json()
    assert c.post("/api/v1/collectors/enroll",json={"token":token}).status_code==403
    headers={"authorization":"Bearer "+enrolled["token"]}
    assert c.post("/api/v1/collectors/heartbeat",json={"uptime":1},headers=headers).status_code==200
    assert c.post("/api/v1/collectors/"+enrolled["collector_id"]+"/revoke",json={}).status_code==200
    assert c.post("/api/v1/collectors/heartbeat",json={},headers=headers).status_code==401


def test_cloud_refuses_insecure_defaults(tmp_path):
    with pytest.raises(ValueError,match="PostgreSQL"):Settings(data=tmp_path,mode="cloud").prepare()


def test_saved_views_are_private_and_versioned(app_client):
    app,c=app_client
    assert c.get("/api/v1/saved-views").json()=={"version":0,"views":[]}
    assert c.put("/api/v1/saved-views",json={"version":0,"views":[{"name":"Network","source":"suricata.eve"}]}).status_code==200
    assert c.put("/api/v1/saved-views",json={"version":0,"views":[]}).status_code==409


@pytest.mark.parametrize("severity", [None, {}, [], "invalid", True, 2.5])
def test_case_rejects_invalid_severity(app_client, severity):
    app, c = app_client
    response = c.post("/api/v1/cases", json={"title":"Input validation", "severity":severity})
    assert response.status_code == 422
    assert len(c.get("/api/v1/cases").json()) == 1


@pytest.mark.parametrize("field,value", [("title", {}), ("title", " "), ("description", []), ("conclusion", {})])
def test_case_update_rejects_invalid_text(app_client, field, value):
    app, c = app_client
    case = c.get("/api/v1/cases").json()[0]
    response = c.patch("/api/v1/cases/" + case["id"], json={"version":case["version"], field:value})
    assert response.status_code == 422
    assert c.get("/api/v1/cases/" + case["id"]).json()["version"] == case["version"]


def test_invalid_mfa_secret_returns_validation_error(app_client):
    app, c = app_client
    response = c.post("/api/v1/auth/mfa", json={"password":"valid-test-password-123", "secret":"invalid!", "otp":"123456"})
    assert response.status_code == 422


@pytest.mark.parametrize("payload", ['{"value":1e999}', '{"value":9007199254740993}', '{"value":"\\ud800"}'])
def test_invalid_json_returns_client_error(app_client, payload):
    app, c = app_client
    response = c.post("/api/v1/cases", content=payload, headers={"content-type":"application/json"})
    assert response.status_code == 400


@pytest.mark.parametrize("body", [{"channels":None}, {"channels":"System"}, {"channels":[{}]}, {"poll_seconds":None}, {"max_file_bytes":{}}])
def test_invalid_collector_configuration_is_rejected(app_client, body):
    app, c = app_client
    token = c.post("/api/v1/enrollments", json={"name":"config-test", "os":"fixture"}).json()["token"]
    collector = c.post("/api/v1/collectors/enroll", json={"token":token}).json()
    response = c.put("/api/v1/collectors/" + collector["collector_id"] + "/configuration", json=body)
    assert response.status_code == 422


@pytest.mark.parametrize("ids", [1, "record", [{}], [None]])
def test_evidence_selection_requires_string_array(app_client, ids):
    app, c = app_client
    case = c.get("/api/v1/cases").json()[0]
    response = c.post("/api/v1/cases/" + case["id"] + "/evidence", json={"evidence_ids":ids})
    assert response.status_code == 422


@pytest.mark.parametrize("template", [[], {}])
def test_acquisition_template_requires_string(app_client, template):
    app, c = app_client
    assert c.post("/api/v1/acquisitions", json={"template":template}).status_code == 422


def test_valid_mfa_setup_and_case_edit(app_client):
    import pyotp
    app, c = app_client
    case = c.get("/api/v1/cases").json()[0]
    result = c.patch("/api/v1/cases/" + case["id"], json={"version":case["version"], "title":"Updated case", "description":"Reviewed"})
    assert result.status_code == 200
    secret = c.post("/api/v1/auth/mfa", json={"password":"valid-test-password-123"}).json()["secret"]
    result = c.post("/api/v1/auth/mfa", json={"password":"valid-test-password-123", "secret":secret, "otp":pyotp.TOTP(secret).now()})
    assert result.status_code == 200
    assert result.json()["enabled"] is True


def test_frontend_and_readiness_are_served(app_client):
    app, c = app_client
    assert c.get("/health/ready").status_code == 200
    response = c.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'id="root"' in response.text


@pytest.mark.parametrize("content_type", [None, "application/json", "application/merge-patch+json"])
def test_duplicate_json_guard_covers_all_json_media_types(app_client, content_type):
    app, c = app_client
    headers = {"content-type":content_type} if content_type else {}
    response = c.post("/api/v1/cases", content='{"title":"First title","title":"Second title"}', headers=headers)
    assert response.status_code == 400
    assert len(c.get("/api/v1/cases").json()) == 1
