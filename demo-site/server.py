"""Serve fixed security scenarios and record their synthetic events locally."""

import json
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4


DATABASE = Path("/state/scenarios.sqlite3")
ASSETS = Path(__file__).with_name("dist")
HOST = "127.0.0.1:8081"
SCENARIOS = {
    "/scenarios/failed-login": ("auth.failure", "Failed login", 6),
    "/scenarios/web-path": ("web.path", "Web path", 5),
    "/scenarios/tcp-connection": ("tcp.connection", "TCP connection", 6),
}
FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
EVENT_LIMIT = 10000


def initialize():
    with closing(sqlite3.connect(DATABASE)) as db, db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS stream (name TEXT PRIMARY KEY)")
        if not db.execute("SELECT name FROM stream").fetchone():
            db.execute("INSERT INTO stream VALUES (?)", (uuid4().hex,))
        db.execute("CREATE TABLE IF NOT EXISTS activity (seq INTEGER PRIMARY KEY, raw TEXT NOT NULL)")


def record(scenario, label, count):
    marker = "CBB-LAB-" + uuid4().hex[:12].upper()
    timestamp = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    records = [
        {"schema": "cbb.lab-fixture/1", "marker": marker, "scenario": scenario,
         "synthetic": True, "record": number, "total": count, "occurred_at": timestamp,
         "summary": f"{marker} · Simulated {label.lower()} ({number}/{count})"}
        for number in range(1, count + 1)
    ]
    with closing(sqlite3.connect(DATABASE)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute("SELECT COALESCE(MAX(seq), 0) FROM activity").fetchone()[0]
        if current + count > EVENT_LIMIT:
            return None
        db.executemany("INSERT INTO activity(raw) VALUES (?)", (
            (json.dumps(event, separators=(",", ":")),) for event in records
        ))
    return {"marker": marker, "label": label, "count": count}


def read_batch(previous_stream, previous_seq):
    with closing(sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)) as db:
        stream = db.execute("SELECT name FROM stream").fetchone()[0]
        start = previous_seq if previous_stream == stream else 0
        rows = db.execute("SELECT seq, raw FROM activity WHERE seq > ? ORDER BY seq LIMIT 100", (start,))
        return {"stream": stream, "events": list(rows)}


class SiteHandler(BaseHTTPRequestHandler):
    def send_bytes(self, status, content, media_type):
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, value):
        self.send_bytes(status, json.dumps(value).encode(), "application/json")

    def do_GET(self):
        if self.headers.get("Host") != HOST:
            self.send_json(400, {"message": "Use the local demo address."})
            return
        if self.path not in FILES:
            self.send_json(404, {"message": "Page not found."})
            return
        name, media_type = FILES[self.path]
        self.send_bytes(200, (ASSETS / name).read_bytes(), media_type)

    def do_POST(self):
        if self.headers.get("Host") != HOST or self.headers.get("Origin") != f"http://{HOST}":
            self.send_json(403, {"message": "Open the local demo page directly."})
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length") != "0":
            self.send_json(400, {"message": "This action accepts no input."})
            return
        scenario = SCENARIOS.get(self.path)
        if not scenario:
            self.send_json(404, {"message": "Unknown lab scenario."})
            return
        try:
            run = record(*scenario)
        except sqlite3.Error:
            self.send_json(503, {"message": "The activity log is unavailable. Try again."})
            return
        if run is None:
            self.send_json(507, {"message": "The demo activity log is full."})
            return
        self.send_json(201, run)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "read":
        print(json.dumps(read_batch(sys.argv[2], int(sys.argv[3]))))
    elif len(sys.argv) == 1:
        initialize()
        with ThreadingHTTPServer(("0.0.0.0", 8080), SiteHandler) as server:
            server.serve_forever()
    else:
        raise SystemExit("Usage: server.py [read STREAM SEQUENCE]")
