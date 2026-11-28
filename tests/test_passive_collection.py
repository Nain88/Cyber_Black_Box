"""Regression checks for the preservation-only application."""
from test_api import app_client


def test_main_application_has_no_simulator_operations(app_client):
    _, client = app_client
    spec = client.get("/api/openapi.json").json()
    assert not any(path.startswith("/api/v1/lab") for path in spec["paths"])
    for endpoint in ("/lab/runs", "/lab/check", "/lab/runs/old-id/stop", "/lab/runs/old-id/recover"):
        # The frontend static fallback can answer 405 for a retired POST.
        response = client.post("/api/v1" + endpoint, json={})
        assert response.status_code in {404, 405}


def test_external_log_can_be_preserved_without_simulator(app_client):
    _, client = app_client
    case = client.get("/api/v1/cases").json()[0]
    marker = "CBB-EXTERNAL-DEMO benign local web log"
    response = client.post("/api/v1/imports", json={
        "case_id": case["id"], "source_type": "lab.fixture", "format": "text", "content": marker,
    })
    assert response.status_code == 201
    record_id = response.json()["evidence_ids"][0]
    assert client.get("/api/v1/evidence/" + record_id + "/raw").content == marker.encode()


def test_pipeline_health_requires_admin(app_client):
    app,c=app_client
    result=c.get('/api/v1/health/pipeline');assert result.status_code==200
    assert 'oldest_pending_at' in result.json() and 'disk_free' in result.json()
    c.post('/api/v1/users',json={'username':'health-reviewer','password':'health-reviewer-password','role':'reviewer'}).raise_for_status()
    login=c.post('/api/v1/auth/session',json={'username':'health-reviewer','password':'health-reviewer-password'}).json();c.headers['x-csrf-token']=login['csrf']
    assert c.get('/api/v1/health/pipeline').status_code==403
