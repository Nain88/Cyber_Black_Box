"""Run a mixed, defensive HTTP workload on a disposable loopback demo instance."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from math import ceil
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cbb.cli import seed_demo
from cbb.service import Service
from cbb.verify import verify_package
from scripts._isolated_runtime import clean_environment, isolated_settings


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(seconds, readers, reader_pause=.5, batch_size=10, import_interval=10):
    with tempfile.TemporaryDirectory(prefix="cbb-evidence-soak-") as tmp:
        root = Path(tmp)
        data = root / "data"
        service = Service(isolated_settings(data, workers=False))
        demo = seed_demo(service)
        public_key = service.deployment["public_key"]
        service.db.engine.dispose()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        metrics = defaultdict(list)
        errors = Counter()
        sealed = set()
        expected_digests = Counter()
        samples = []
        verified_exports = 0

        def request(client, method, route, status=200, **kwargs):
            start = time.monotonic()
            response = client.request(method, route, **kwargs)
            elapsed = (time.monotonic() - start) * 1000
            metrics[f"{method} {route.split('?')[0]}"].append(elapsed)
            require(response.status_code == status, f"{method} {route}: expected {status}, received {response.status_code}")
            return response

        def client():
            return httpx.Client(base_url=url, trust_env=False, timeout=20)

        def sign_in(http, credentials=None):
            login = request(http, "POST", "/api/v1/auth/session", json=credentials or
                            {k: demo[k] for k in ("username", "password")}).json()
            http.headers["X-CSRF-Token"] = login["csrf"]

        def start_server(log):
            process = subprocess.Popen(
                [sys.executable, "-m", "cbb.cli", "--data", str(data), "serve", "--port", str(port)],
                cwd=ROOT, env={**clean_environment(), "CBB_PUBLIC_URL": url}, stdout=log, stderr=log,
            )
            try:
                with client() as http:
                    for _ in range(100):
                        if process.poll() is not None:
                            break
                        try:
                            if http.get("/health/ready").status_code == 200:
                                return process
                        except httpx.TransportError:
                            pass
                        time.sleep(.2)
                raise RuntimeError("Isolated server failed readiness")
            except BaseException:
                process.terminate()
                process.wait(timeout=15)
                raise

        def import_batch(http, label, size):
            lines = [
                json.dumps({"summary": f"CBB-SOAK {label} {i}", "event_type": "demo.marker", "severity": 2}) + "\n"
                for i in range(size)
            ]
            body = {"case_id": demo["case_id"], "name": "Soak fixture", "source_type": "lab.fixture",
                    "format": "jsonl", "content": "".join(lines)}
            result = request(http, "POST", "/api/v1/imports", 201, json=body).json()
            require(result["preserved"] == size and not result["rejected"] and not result["not_sealed"],
                    "Import did not preserve the entire batch")
            return body, result["evidence_ids"], lines

        def await_job(http, kind, body):
            job_id = request(http, "POST", f"/api/v1/{kind}", 202, json=body).json()["job_id"]
            stop = time.monotonic() + 60
            while time.monotonic() < stop:
                jobs = request(http, "GET", "/api/v1/jobs").json()
                job = next((job for job in jobs if job["id"] == job_id), None)
                if job and job["state"] == "COMPLETE":
                    return job["result"]
                if job and job["state"] == "FAILED":
                    raise RuntimeError(f"{kind} job failed")
                time.sleep(.5)
            raise RuntimeError(f"{kind} job timed out")

        def verify_export(http):
            result = await_job(http, "exports", {"case_id": demo["case_id"]})
            package = root / "case.zip"
            package.write_bytes(request(http, "GET", f"/api/v1/exports/{result['export_id']}/download").content)
            require(verify_package(package, public_key)["status"] == "VALID", "Signed package failed verification")

        def reader(deadline, index, credentials):
            routes = ("/overview", "/evidence?q=CBB-SOAK", "/cases", "/jobs", "/health/pipeline")
            timings = defaultdict(list)
            with client() as http:
                sign_in(http, credentials)
                renew = time.monotonic() + 3600
                turn = index
                while time.monotonic() < deadline:
                    route = routes[turn % len(routes)]
                    begin = time.monotonic()
                    try:
                        if time.monotonic() >= renew:
                            sign_in(http, credentials)
                            renew = time.monotonic() + 3600
                        request(http, "GET", "/api/v1" + route)
                    except (RuntimeError, httpx.HTTPError) as error:
                        errors[f"{route}: {type(error).__name__}: {error}"] += 1
                    timings[route.split("?")[0]].append((time.monotonic() - begin) * 1000)
                    turn += 1
                    time.sleep(reader_pause)
            return timings

        def percentiles(values):
            ordered = sorted(values)
            return {"requests": len(ordered),
                    **{f"p{pct}_ms": round(ordered[ceil(len(ordered) * pct / 100) - 1], 1)
                       for pct in (50, 95, 99)},
                    "max_ms": round(ordered[-1], 1)}

        with (root / "server.log").open("w") as log:
            process = start_server(log)
            try:
                with client() as http, client() as anonymous:
                    request(anonymous, "GET", "/api/v1/evidence", 401)
                    sign_in(http)
                    request(http, "POST", "/api/v1/checkpoints", 403, headers={"X-CSRF-Token": ""})
                    body, ids, lines = import_batch(http, "preflight", 1)
                    replay = request(http, "POST", "/api/v1/imports", 201, json=body).json()
                    require(replay["evidence_ids"] == ids and replay["duplicates"] == 1, "Re-import failed deduplication")
                    raw_path = f"/api/v1/evidence/{ids[0]}/raw"
                    require(request(http, "GET", raw_path).content == lines[0].encode(), "Raw bytes changed")
                    verify_export(http)
                    verified_exports += 1
                    reader_accounts = []
                    for index in range(readers):
                        credentials = {"username": f"soak-reader-{index}", "password": secrets.token_urlsafe(24)}
                        account = request(http, "POST", "/api/v1/users", json={**credentials, "role": "admin"}).json()
                        request(http, "POST", f"/api/v1/cases/{demo['case_id']}/members", json={"user_id": account["id"]})
                        reader_accounts.append(credentials)
                    print(f"Preflight passed. Starting {seconds}s workload with {readers} readers.", flush=True)
                    start = time.monotonic()
                    deadline = start + seconds
                    next_import = next_export = start
                    renew = start + 3600
                    reader_timings = defaultdict(list)
                    with ThreadPoolExecutor(max_workers=readers) as pool:
                        futures = [pool.submit(reader, deadline, index, credentials)
                                   for index, credentials in enumerate(reader_accounts)]
                        batch = 0
                        while time.monotonic() < deadline:
                            tick = time.monotonic()
                            if tick >= renew:
                                sign_in(http)
                                renew = tick + 3600
                            if tick >= next_import:
                                _, batch_ids, batch_lines = import_batch(http, batch, batch_size)
                                require(len(set(batch_ids)) == len(batch_lines) and not set(batch_ids) & sealed,
                                        "Distinct records reused evidence IDs")
                                sealed.update(batch_ids)
                                expected_digests.update(hashlib.sha256(line.encode()).hexdigest() for line in batch_lines)
                                next_import = tick + import_interval
                                batch += 1
                            if tick >= next_export:
                                verify_export(http)
                                verified_exports += 1
                                health = request(http, "GET", "/api/v1/health/pipeline").json()
                                parent = psutil.Process(process.pid)
                                tree = [parent, *parent.children(recursive=True)]
                                sample = {"elapsed_s": round(tick - start), "sealed": len(sealed),
                                          "staged_receipts": sum(row["count"] for row in health["receipts"] if row["state"] == "STAGED"),
                                          "pending_analysis": sum(job["count"] for job in health["jobs"]
                                                                  if job["kind"] == "analyze" and job["state"] in ("QUEUED", "RUNNING")),
                                          "reader_errors": sum(errors.values()),
                                          "rss_mib": round(sum(p.memory_info().rss for p in tree) / 2**20, 1),
                                          "data_mib": round(sum(p.stat().st_size for p in data.rglob("*") if p.is_file()) / 2**20, 2)}
                                samples.append(sample)
                                print(json.dumps(sample), flush=True)
                                next_export = tick + 60
                            time.sleep(.2)
                        for future in futures:
                            for route, timings in future.result().items():
                                reader_timings[route].extend(timings)
                    print(f"Workload finished with {len(sealed)} sealed records. Checking archive and original bytes.", flush=True)
                    request(http, "POST", "/api/v1/checkpoints")
                    final = await_job(http, "verification-runs", {})
                    require(final["status"] == "VALID", "Archive integrity failed")
                    health = request(http, "GET", "/api/v1/health/pipeline").json()
                    require(not any(row["state"] == "STAGED" and row["count"] for row in health["receipts"]),
                            "Evidence queue did not drain")
                    actual_digests = Counter()
                    for evidence_id in sealed:
                        raw = request(http, "GET", f"/api/v1/evidence/{evidence_id}/raw").content
                        actual_digests[hashlib.sha256(raw).hexdigest()] += 1
                    require(actual_digests == expected_digests, "Sealed bytes mismatched")
                    verified_reader_error_count = sum(errors.values())
            finally:
                process.terminate()
                process.wait(timeout=15)
            process = start_server(log)
            try:
                with client() as http:
                    sign_in(http)
                    require(request(http, "GET", raw_path).content == lines[0].encode(), "Evidence lost after restart")
                    restarted = await_job(http, "verification-runs", {})
                    require(restarted["status"] == "VALID", "Integrity verification failed after restart")
            finally:
                process.terminate()
                process.wait(timeout=15)
        latencies = [value for values in metrics.values() for value in values]
        ordered = sorted(latencies)
        return {
            "status": "FAIL" if errors else "PASS", "configured_load_seconds": seconds, "concurrent_readers": readers,
            "reader_pause_seconds": reader_pause, "import_batch_size": batch_size,
            "import_interval_seconds": import_interval,
            "workload_reads": percentiles([value for values in reader_timings.values() for value in values]),
            "reads_by_route": {route: percentiles(values) for route, values in sorted(reader_timings.items())},
            "http_requests": len(latencies), "mixed_http_p95_ms": round(ordered[ceil(len(ordered) * .95) - 1], 1),
            "mixed_http_max_ms": round(ordered[-1], 1), "new_batch_records": len(sealed),
            "signed_exports_verified": verified_exports, "reader_errors": verified_reader_error_count,
            "reader_error_details": dict(errors),
            "integrity": final, "restart_integrity": restarted["status"], "samples": samples,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--readers", type=int, default=4)
    parser.add_argument("--reader-pause", type=float, default=.5)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--import-interval", type=float, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.seconds < 1 or not 1 <= args.readers <= 16:
        parser.error("--seconds must be positive and --readers must be between 1 and 16")
    if not .05 <= args.reader_pause <= 10 or not 1 <= args.batch_size <= 100 or not 1 <= args.import_interval <= 120:
        parser.error("Reader pause must be .05–10s, batch size 1–100, and import interval 1–120s")
    summary = run(args.seconds, args.readers, args.reader_pause, args.batch_size, args.import_interval)
    result = json.dumps(summary, indent=2)
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(result + "\n")
    print(result)
    sys.exit(summary["status"] != "PASS")
