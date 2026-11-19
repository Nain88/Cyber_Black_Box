"""End-to-end smoke test against a running Docker Compose stack.

Usage:  python scripts/docker_smoke.py http://localhost:8799 <setup-token>

Exercises: first-time setup, login, case creation, all three Lab attack
scenarios (lab container -> decoys in app), sealing, signed export via the
trust container, offline package verification, integrity verification and
witness anchoring. Exits non-zero on the first failure.
"""
import sys
import time

import httpx

BASE, TOKEN = sys.argv[1].rstrip("/"), sys.argv[2]
PASSWORD = "smoke-test-password-" + str(int(time.time()))
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (" - " + str(detail)[:200] if detail else ""), flush=True)
    if not ok:
        sys.exit(1)


c = httpx.Client(base_url=BASE, headers={"Origin": BASE}, timeout=30, trust_env=False)
status = c.get("/api/v1/status").json()
check("status reports setup required", status["setup_required"] is True, status["mode"])
r = c.post("/api/v1/admin/setup", json={"token": TOKEN, "username": "smoke-admin", "password": PASSWORD})
check("first-time administrator setup", r.status_code == 200, r.status_code)
r = c.post("/api/v1/auth/session", json={"username": "smoke-admin", "password": PASSWORD})
check("login", r.status_code == 200, r.status_code)
c.headers["x-csrf-token"] = r.json()["csrf"]
check("CSRF enforced", httpx.post(BASE + "/api/v1/cases", json={"title": "x"}, headers={"Origin": BASE}, cookies=c.cookies).status_code in (401, 403))
check("foreign origin rejected", c.post("/api/v1/cases", json={"title": "x"}, headers={"Origin": "http://evil.example"}).json().get("code") == "ORIGIN_DENIED")

r = c.post("/api/v1/cases", json={"title": "Smoke case", "description": "Docker smoke test", "severity": 3})
check("create case", r.status_code in (200, 201), r.text[:120])

lab = c.get("/api/v1/lab").json()
check("lab configured in Docker", lab["configured"] is True, lab["target"])
r = c.post("/api/v1/lab/check")
check("lab sender container reachable", r.status_code == 200 and r.json()["reachable"], r.text[:150])

for scenario in ("login-failures", "web-probes", "port-probe"):
    for _ in range(20):
        r = c.post("/api/v1/lab/runs", json={"scenario": scenario})
        if r.status_code != 429 and r.status_code != 409:
            break
        time.sleep(2)
    check("start lab scenario " + scenario, r.status_code == 202, r.text[:150])
    rid = r.json()["id"]
    run = None
    for _ in range(90):
        run = next(x for x in c.get("/api/v1/lab").json()["runs"] if x["id"] == rid)
        if run["state"] not in ("RUNNING", "STOPPING", "FINALIZING") and run["report_state"] in ("SUCCEEDED", "COMPLETE", "FAILED", "NOT_QUEUED"):
            break
        time.sleep(1)
    check(scenario + " completed", run["state"] == "COMPLETE", f"{run['state']} {run.get('error')}")
    check(scenario + " observations sealed", run["preservation_state"] == "SEALED", f"{run['sealed_count']}/{run['observed_count']}")
    check(scenario + " signed report exported", run["report_state"] in ("SUCCEEDED", "COMPLETE") and run["export_id"], f"{run['report_state']} {run.get('report_error')}")
    for fmt, magic in (("pdf", b"%PDF"), ("docx", b"PK"), ("json", b"{")):
        body = c.get(f"/api/v1/exports/{run['export_id']}/report/{fmt}")
        check(f"{scenario} {fmt.upper()} report download", body.status_code == 200 and body.content.startswith(magic))
    package = c.get(f"/api/v1/exports/{run['export_id']}/download")
    check(scenario + " evidence package download", package.status_code == 200 and package.content[:2] == b"PK")
    last_package = package.content

# Offline verification of the last package against the deployment key.
import pathlib, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from cbb.verify import verify_package  # noqa: E402
with tempfile.TemporaryDirectory() as tmp:
    path = pathlib.Path(tmp) / "case.zip"
    path.write_bytes(last_package)
    result = verify_package(path, status["public_key"])
check("offline package verification (trust-container key)", result["status"] == "VALID", result.get("status"))

r = c.post("/api/v1/checkpoints", json={})
if r.status_code == 404:
    r = c.post("/api/v1/admin/checkpoints", json={})
anchored = False
for _ in range(30):
    cps = c.get("/api/v1/checkpoints").json()
    items = cps.get("items", cps) if isinstance(cps, dict) else cps
    if items and any(x.get("witness") or x.get("witnessed") or x.get("receipt") for x in items):
        anchored = True
        break
    time.sleep(2)
check("checkpoint anchored by witness", anchored, f"{len(items) if items else 0} checkpoints")

r = c.post("/api/v1/verification-runs", json={})
check("integrity verification queued", r.status_code in (200, 201, 202), r.text[:150])
verdict = None
for _ in range(60):
    runs = c.get("/api/v1/verification-runs").json()
    runs = runs.get("items", runs) if isinstance(runs, dict) else runs
    done = [x for x in runs if (x.get("result") or {}) and (x.get("state") in (None, "SUCCEEDED", "COMPLETE", "DONE"))]
    if done:
        res = done[0]["result"]
        verdict = res.get("status") if isinstance(res, dict) else None
        if verdict:
            break
    time.sleep(2)
check("integrity verification result", verdict in ("VALID", "LOCAL_CHECK_ONLY"), verdict)

print(f"\nALL {len(results)} CHECKS PASSED")
