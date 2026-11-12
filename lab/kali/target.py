"""Kali-side decoy that observes REAL incoming lab traffic and retains observations.

No actual accounts, vulnerabilities or exploit execution. Keep this on a private
VM interface; it is not intended to be exposed to the Internet.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Lock, Thread
from urllib.parse import urlsplit, parse_qs
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid

PROBE_PATHS = frozenset(("/.env", "/admin", "/backup.zip", "/wp-admin", "/server-status"))
MAX_BODY = 1024


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class EvidenceStore:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.lock = Lock()
        self.conn = sqlite3.connect(root / "kali-lab.sqlite3", timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.conn.execute("CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY AUTOINCREMENT, raw TEXT NOT NULL)")
        if not self.conn.execute("SELECT value FROM metadata WHERE key='target_id'").fetchone():
            self.conn.execute("INSERT INTO metadata VALUES('target_id',?)", ("kali-" + str(uuid.uuid4()),))
        self.conn.commit()
        self.target_id = self.conn.execute("SELECT value FROM metadata WHERE key='target_id'").fetchone()[0]

    def add(self, *, category: str, summary: str, source_ip: str, port: int, details: dict):
        record = {"target_id": self.target_id, "observed_at": utc(), "event_type": category,
                  "summary": summary[:250], "severity": 3, "src_ip": source_ip,
                  "dst_port": port, "lab_simulation": True, "details": details}
        with self.lock, self.conn:
            cur = self.conn.execute("INSERT INTO observations(raw) VALUES(?)", (json.dumps(record, sort_keys=True, separators=(",", ":")),))
            return cur.lastrowid

    def read(self, after: int, limit: int):
        with self.lock:
            rows = self.conn.execute("SELECT id,raw FROM observations WHERE id>? ORDER BY id LIMIT ?", (after, limit)).fetchall()
        return [{"id": r["id"], "event": json.loads(r["raw"])} for r in rows]

    def count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]


class HmacAuth:
    def __init__(self, secret: str):
        if len(secret) < 24 or secret.startswith("REPLACE_"):
            raise ValueError("Set LAB_SHARED_KEY to a random secret at least 24 characters long")
        self.key = secret.encode()
        self.lock = Lock()
        self.recent: dict[str, float] = {}

    def sign(self, method: str, path_query: str, timestamp: str, nonce: str, body: bytes = b"") -> str:
        message = "\n".join((method, path_query, timestamp, nonce, sha256(body).hexdigest())).encode()
        return hmac.new(self.key, message, sha256).hexdigest()

    def verify(self, method: str, path_query: str, timestamp: str, nonce: str, signature: str, body: bytes = b"") -> bool:
        try:
            if abs(time.time() - int(timestamp)) > 60 or not (16 <= len(nonce) <= 128):
                return False
        except (TypeError, ValueError):
            return False
        expected = self.sign(method, path_query, timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            return False
        with self.lock:
            now = time.time()
            if nonce in self.recent:
                return False
            self.recent = {k: v for k, v in self.recent.items() if v > now - 120}
            self.recent[nonce] = now
        return True


class DecoyHTTP(BaseHTTPRequestHandler):
    server_version = "KaliLabDecoy/1.0"
    def log_message(self, *args):
        return

    @property
    def store(self):
        return self.server.store

    @property
    def auth(self):
        return self.server.auth

    def send_json(self, code: int, value: dict, *, signed_nonce: str | None = None):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if signed_nonce:
            proof = "LAB-RESPONSE-v1\n" + signed_nonce + "\n" + sha256(data).hexdigest()
            signature = hmac.new(self.auth.key, proof.encode(), sha256).hexdigest()
            self.send_header("X-Lab-Response-Signature", signature)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            return self.send_json(200, {"status": "ready", "role": "LAB_DECOY_ONLY", "target_id": self.store.target_id})
        if parsed.path == "/api/events":
            if not self.auth.verify("GET", self.path, self.headers.get("X-Lab-Timestamp", ""),
                                    self.headers.get("X-Lab-Nonce", ""), self.headers.get("X-Lab-Signature", "")):
                return self.send_json(401, {"error": "Invalid signed relay request"})
            query = parse_qs(parsed.query)
            try:
                after, limit = int(query.get("after", ["0"])[0]), int(query.get("limit", ["80"])[0])
            except ValueError:
                return self.send_json(400, {"error": "Invalid cursor"})
            if after < 0 or not 1 <= limit <= 100:
                return self.send_json(400, {"error": "Cursor or limit outside bounds"})
            return self.send_json(200, {"target_id": self.store.target_id, "items": self.store.read(after, limit)},
                                  signed_nonce=self.headers.get("X-Lab-Nonce", ""))
        if parsed.path in PROBE_PATHS:
            self.store.add(category="lab.http.probe", summary="LAB observed suspicious path request: " + parsed.path,
                           source_ip=self.client_address[0], port=self.server.server_port,
                           details={"method": "GET", "path": parsed.path, "status": 404})
            return self.send_json(404, {"error": "Decoy path does not exist"})
        return self.send_json(404, {"error": "Unknown path"})

    def do_POST(self):
        if self.path != "/api/login":
            return self.send_json(404, {"error": "Not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json(400, {"error": "Invalid length"})
        if not 1 <= n <= MAX_BODY:
            return self.send_json(413, {"error": "Bounded decoy input only"})
        try:
            body = json.loads(self.rfile.read(n))
            username = str(body.get("username", "unknown"))[:40] if isinstance(body, dict) else "unknown"
        except (ValueError, UnicodeError):
            username = "invalid-json"
        # No real accounts or password verification. Never persist attempted passwords.
        self.store.add(category="lab.auth.failure", summary="LAB observed failed decoy login for " + username,
                       source_ip=self.client_address[0], port=self.server.server_port,
                       details={"username": username, "path": "/api/login", "status": 401})
        return self.send_json(401, {"error": "Decoy login always rejects credentials"})


class PortProbe(BaseRequestHandler):
    def handle(self):
        self.server.store.add(category="lab.port.probe", summary=f"LAB observed TCP connection on decoy port {self.server.server_address[1]}",
                              source_ip=self.client_address[0], port=self.server.server_address[1],
                              details={"protocol": "tcp", "port": self.server.server_address[1]})
        try:
            self.request.sendall(b"LAB-DECOY\n")
        except OSError:
            pass


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class LabTCPServer(ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_servers(host: str, port: int, store: EvidenceStore, auth: HmacAuth):
    httpd = LabHTTPServer((host, port), DecoyHTTP)
    httpd.store, httpd.auth = store, auth
    decoys = []
    try:
        for p in (port + 1, port + 2):
            s = LabTCPServer((host, p), PortProbe)
            s.store = store
            decoys.append(s)
    except Exception:
        httpd.server_close()
        for s in decoys:
            s.server_close()
        raise
    return httpd, decoys


def main():
    ap = argparse.ArgumentParser(description="Kali lab target: private decoy services + durable observations")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--data", default=".lab-kali-data", type=Path)
    args = ap.parse_args()
    if args.port != 8088:
        ap.error("Only the documented decoy port 8088 is supported")
    store = EvidenceStore(args.data.resolve())
    auth = HmacAuth(os.getenv("LAB_SHARED_KEY", ""))
    httpd, decoys = make_servers(args.host, args.port, store, auth)
    for s in decoys:
        Thread(target=s.serve_forever, daemon=True).start()
    print(f"Kali lab decoy listening on {args.host}:{args.port}, {args.port+1}, {args.port+2}; observed records in {store.root}", flush=True)
    try:
        httpd.serve_forever(poll_interval=.3)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        for s in decoys:
            s.shutdown()
            s.server_close()
        store.conn.close()


if __name__ == "__main__":
    main()
