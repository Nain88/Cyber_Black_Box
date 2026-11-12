"""Windows Docker lab interface. Fixed, bounded tests against ONE RFC1918 Kali VM.

This container intentionally does NOT get Cloud Box credentials. Target-side
observations are forwarded by a separate, host-only Windows relay.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, IPv4Network, ip_address
from pathlib import Path
from threading import Event, Lock, Thread
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
import json
import os
import secrets
import socket
import time
import uuid

PRIVATE_RANGES = tuple(IPv4Network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
SCENARIOS = {
    "port-probe": {"label": "Port reconnaissance", "description": "Six TCP connections to Kali's two decoy listener ports, 8089 and 8090."},
    "login-failures": {"label": "Failed sign-ins", "description": "Six deliberately invalid logins against the Kali decoy endpoint."},
    "web-probes": {"label": "Web path probing", "description": "Five harmless requests to nonexistent, decoy web paths."},
}
STATIC = Path(__file__).resolve().parent / "static"


def validate_kali_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("KALI_TARGET_URL must be an HTTP base URL with no credentials, path, or query")
    try:
        host = ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValueError("KALI_TARGET_URL must use an explicit private IPv4 address") from exc
    if not isinstance(host, IPv4Address) or not any(host in block for block in PRIVATE_RANGES):
        raise ValueError("Only RFC1918 private IPv4 Kali targets are permitted")
    if parsed.port != 8088:
        raise ValueError("Kali's lab service must run on port 8088")
    return f"http://{host}:8088"


class State:
    def __init__(self, target: str, password: str):
        if len(password) < 16 or password.startswith("REPLACE_"):
            raise ValueError("Set LAB_OPERATOR_PASSWORD to a unique password at least 16 characters long")
        self.target = validate_kali_url(target)
        self.password = password
        self.lock = Lock()
        self.sessions: dict[str, tuple[str, float]] = {}
        self.login_attempts: dict[str, deque[float]] = {}
        self.runs: deque[dict] = deque(maxlen=30)
        self.running = False
        self.cancel = Event()
        self.last_start = 0.0

    def login(self, ip: str, password: str) -> tuple[str, str] | None:
        with self.lock:
            t = time.monotonic()
            q = self.login_attempts.setdefault(ip, deque(maxlen=10))
            while q and q[0] < t - 60:
                q.popleft()
            if len(q) >= 5:
                return None
            q.append(t)
            if not secrets.compare_digest(password, self.password):
                return None
            sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            self.sessions[sid] = (csrf, t + 8 * 3600)
            # Bound the in-memory table even on a long-lived local deployment.
            self.sessions = {k: v for k, v in self.sessions.items() if v[1] > t}
            return sid, csrf

    def session(self, sid: str) -> str | None:
        with self.lock:
            record = self.sessions.get(sid)
            return record[0] if record and record[1] > time.monotonic() else None

    def logout(self, sid: str) -> None:
        with self.lock:
            self.sessions.pop(sid, None)

    def start(self, scenario: str) -> dict:
        if scenario not in SCENARIOS:
            raise ValueError("Unknown predefined scenario")
        with self.lock:
            if self.running:
                raise RuntimeError("A scenario is already running")
            if time.monotonic() - self.last_start < 6:
                raise RuntimeError("Wait six seconds between scenarios")
            self.last_start = time.monotonic()
            self.running = True
            self.cancel.clear()
            run = {"id": str(uuid.uuid4()), "scenario": scenario, "label": SCENARIOS[scenario]["label"],
                   "started": datetime.now(timezone.utc).isoformat(), "state": "RUNNING", "results": []}
            self.runs.appendleft(run)
        Thread(target=self._execute, args=(run,), daemon=True).start()
        return {"id": run["id"], "state": run["state"]}

    def stop(self) -> dict:
        with self.lock:
            if self.running:
                self.cancel.set()
                self.runs[0]["state"] = "STOPPING"
            return {"stopping": self.running}

    def _execute(self, run: dict) -> None:
        results, error = [], None
        try:
            results = run_scenario(self.target, run["scenario"], self.cancel)
        except Exception as exc:
            error = type(exc).__name__ + ": " + str(exc)[:220]
        finally:
            with self.lock:
                run["results"] = results
                if error:
                    run["state"], run["error"] = "FAILED", error
                else:
                    run["state"] = "STOPPED" if self.cancel.is_set() else ("COMPLETE" if all(r["ok"] for r in results) else "PARTIAL")
                run["ended"] = datetime.now(timezone.utc).isoformat()
                self.running = False

    def snapshot(self) -> dict:
        with self.lock:
            return {"runs": json.loads(json.dumps(list(self.runs))), "running": self.running,
                    "scenarios": SCENARIOS, "target": self.target}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method: str, url: str, data: bytes | None = None) -> dict:
    req = Request(url, data=data, method=method, headers={"Content-Type": "application/json"} if data is not None else {})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(req, timeout=4) as r:
            return {"ok": True, "status": r.status}
    except Exception as exc:
        # HTTP 401/404 are expected for the two decoy scenarios, not a network failure.
        if hasattr(exc, "code") and exc.code in (401, 404):
            return {"ok": True, "status": exc.code}
        return {"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:120]}


def run_scenario(target: str, scenario: str, cancel: Event | None = None) -> list[dict]:
    cancel = cancel or Event()
    host = urlsplit(target).hostname
    assert host is not None
    results = []
    if scenario == "port-probe":
        # In production State validates target:8088, so only 8089 and 8090 are probed.
        base_port = urlsplit(target).port or 8088
        for port in (base_port + 1, base_port + 2) * 3:
            if cancel.is_set(): break
            try:
                with socket.create_connection((host, port), timeout=3) as sock:
                    sock.settimeout(1)
                    sock.recv(64)
                results.append({"action": f"TCP {port}", "ok": True})
            except OSError as exc:
                results.append({"action": f"TCP {port}", "ok": False, "error": str(exc)[:120]})
            cancel.wait(.35)
    elif scenario == "login-failures":
        for index in range(6):
            if cancel.is_set(): break
            payload = json.dumps({"username": "lab-user", "password": f"wrong-lab-{index + 1}"}).encode()
            result = request("POST", target + "/api/login", payload)
            results.append({"action": f"Invalid sign-in {index + 1}", **result})
            cancel.wait(.35)
    elif scenario == "web-probes":
        for path in ("/.env", "/admin", "/backup.zip", "/wp-admin", "/server-status"):
            if cancel.is_set(): break
            result = request("GET", target + path)
            results.append({"action": f"GET {path}", **result})
            cancel.wait(.35)
    else:
        raise ValueError("Unsupported scenario")
    return results


class Handler(BaseHTTPRequestHandler):
    server_version = "CloudBoxLab/1.0"

    @property
    def state(self) -> State:
        return self.server.lab_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        return  # Avoid logging credentials or session IDs into container output.

    def respond(self, code: int, body: object, *, cookie: str | None = None):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid content length") from exc
        if n < 1 or n > 4096:
            raise ValueError("JSON body must be 1–4096 bytes")
        body = json.loads(self.rfile.read(n))
        if not isinstance(body, dict):
            raise ValueError("Expected a JSON object")
        return body

    def session(self) -> tuple[str, str | None]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            sid = cookie.get("lab_session").value if cookie.get("lab_session") else ""
        except Exception:
            sid = ""
        return sid, self.state.session(sid)

    def require_auth(self, *, mutation: bool = False) -> tuple[str, str] | None:
        sid, csrf = self.session()
        if not csrf:
            self.respond(401, {"error": "Sign in to the local lab dashboard"})
            return None
        if mutation:
            origin = self.headers.get("Origin", "")
            if origin not in ("http://127.0.0.1:8844", "http://localhost:8844"):
                self.respond(403, {"error": "Unexpected origin"})
                return None
            if not secrets.compare_digest(self.headers.get("X-Lab-CSRF", ""), csrf):
                self.respond(403, {"error": "CSRF validation failed"})
                return None
        return sid, csrf

    def do_GET(self):
        if self.path == "/health":
            return self.respond(200, {"status": "ready"})
        if self.path == "/api/session":
            sid, csrf = self.session()
            return self.respond(200, {"authenticated": bool(csrf), "csrf": csrf})
        if self.path == "/api/status":
            if not self.require_auth():
                return
            payload = self.state.snapshot()
            health = request("GET", self.state.target + "/health")
            payload["target_online"] = health.get("status") == 200
            return self.respond(200, payload)
        asset = {"/": "index.html", "/styles.css": "styles.css", "/app.js": "app.js"}.get(self.path)
        if not asset:
            return self.respond(404, {"error": "Not found"})
        p = STATIC / asset
        raw = p.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8"}[p.suffix])
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path == "/api/login":
            origin = self.headers.get("Origin", "")
            if origin not in ("http://127.0.0.1:8844", "http://localhost:8844"):
                return self.respond(403, {"error": "Unexpected origin"})
            try:
                password = self.read_json().get("password", "")
            except (ValueError, json.JSONDecodeError):
                return self.respond(400, {"error": "Invalid body"})
            result = self.state.login(self.client_address[0], str(password))
            if not result:
                return self.respond(401, {"error": "Invalid password or too many attempts"})
            sid, csrf = result
            return self.respond(200, {"authenticated": True, "csrf": csrf},
                                cookie=f"lab_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800")
        session = self.require_auth(mutation=True)
        if not session:
            return
        if self.path == "/api/logout":
            self.state.logout(session[0])
            return self.respond(200, {"ok": True}, cookie="lab_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        if self.path == "/api/stop":
            return self.respond(200, self.state.stop())
        if self.path == "/api/run":
            try:
                scenario = self.read_json().get("scenario", "")
                result = self.state.start(str(scenario))
                return self.respond(202, result)
            except (ValueError, json.JSONDecodeError) as exc:
                return self.respond(422, {"error": str(exc)[:200]})
            except RuntimeError as exc:
                return self.respond(409, {"error": str(exc)[:200]})
        return self.respond(404, {"error": "Unknown API endpoint"})


def main():
    target = os.getenv("KALI_TARGET_URL", "")
    password = os.getenv("LAB_OPERATOR_PASSWORD", "")
    state = State(target, password)
    server = ThreadingHTTPServer((os.getenv("LAB_BIND", "127.0.0.1"), 8844), Handler)
    server.lab_state = state  # type: ignore[attr-defined]
    print("Lab web dashboard listening on port 8844 (publish to host loopback ONLY).", flush=True)
    server.serve_forever(poll_interval=.4)


if __name__ == "__main__":
    main()
