"""Read-only Kali decoy -> Windows Cloud Box relay; uses only Python stdlib.

Run on the Windows HOST so Cloud Box can keep listening only on 127.0.0.1.
The relay fetches observed Kali records with HMAC authentication, then submits
honestly labelled lab.fixture evidence to the existing Cloud Box ingest API.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hmac
import json
import os
import secrets
import sys
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

DEFAULT_DIR = Path(__file__).resolve().parents[1] / ".lab-state"
PRIVATE_RANGES = tuple(IPv4Network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate_target(value: str) -> str:
    p = urlsplit(value)
    try:
        ip = ip_address(p.hostname or "")
    except ValueError as ex:
        raise ValueError("Use an explicit Kali RFC1918 IPv4 address") from ex
    if p.scheme != "http" or not isinstance(ip, IPv4Address) or not any(ip in block for block in PRIVATE_RANGES) or p.port != 8088 or p.username or p.password or p.path not in ("", "/") or p.query or p.fragment:
        raise ValueError("Kali target must be http://PRIVATE_IPV4:8088")
    return f"http://{ip}:8088"


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def api(url: str, method: str = "GET", payload: object | None = None, headers: dict | None = None) -> dict:
    body = canonical(payload) if payload is not None else None
    req = Request(url, data=body, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urlopen(req, timeout=12) as response:
            if response.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise RuntimeError("API returned non-JSON content")
            return json.loads(response.read(2 * 1024 * 1024))
    except HTTPError as ex:
        raise RuntimeError(f"HTTP {ex.code} from {urlsplit(url).netloc}; verify Cloud Box and enrollment configuration") from ex
    except URLError as ex:
        raise RuntimeError(f"Cannot connect to {urlsplit(url).netloc}: {ex.reason}") from ex


def signed_header(secret: str, path_query: str, method: str = "GET") -> dict:
    stamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    payload = "\n".join((method, path_query, stamp, nonce, sha256(b"").hexdigest())).encode()
    signature = hmac.new(secret.encode(), payload, sha256).hexdigest()
    return {"X-Lab-Timestamp": stamp, "X-Lab-Nonce": nonce, "X-Lab-Signature": signature}


def save_config(path: Path, cfg: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temp.open("x", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    temp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def get_kali_events(target: str, key: str, after: int, limit: int = 80) -> dict:
    path = f"/api/events?after={after}&limit={limit}"
    headers = signed_header(key, path)
    req = Request(target + path, headers=headers)
    try:
        with urlopen(req, timeout=12) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise RuntimeError("Kali response exceeds 2 MiB bound")
            signature = response.headers.get("X-Lab-Response-Signature", "")
    except (URLError, HTTPError) as ex:
        raise RuntimeError("Kali event endpoint unavailable or HMAC rejected; check lab secret and clocks") from ex
    response_proof = "LAB-RESPONSE-v1\n" + headers["X-Lab-Nonce"] + "\n" + sha256(raw).hexdigest()
    expected = hmac.new(key.encode(), response_proof.encode(), sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise RuntimeError("Kali event response signature failed; refusing untrusted evidence")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise RuntimeError("Kali event response schema invalid")
    return data


def make_wire(target_id: str, record: dict) -> dict:
    eid = int(record["id"])
    if eid < 1 or eid >= 10**18:
        raise ValueError("Kali event sequence outside Cloud Box ingest bounds")
    obj = record["event"]
    if obj.get("target_id") != target_id or not obj.get("lab_simulation"):
        raise ValueError("Kali observation has invalid target identity or missing lab label")
    raw = canonical(obj)
    if len(raw) > 65536:
        raise ValueError("Lab observation exceeds Cloud Box per-record limit")
    source_type = str(obj.get("event_type", ""))
    if source_type not in {"lab.port.probe", "lab.auth.failure", "lab.http.probe"}:
        raise ValueError("Unknown Kali lab event type")
    event_time = str(obj["observed_at"])
    datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    return {"schema_version": "cbb.ingest/1.0", "boot_id": target_id,
            "source_seq": str(eid), "source_type": "lab.fixture",
            "event_type": source_type, "collected_at": event_time,
            "original_timestamp": event_time, "raw_media_type": "application/json",
            "raw_base64": base64.b64encode(raw).decode(), "raw_sha256": sha256(raw).hexdigest(),
            "source_cursor": {"kind": "kali-lab-target", "target_id": target_id, "event_id": eid}}


def initialize(args):
    config_path = args.state / "relay.json"
    if config_path.exists():
        raise ValueError("Relay is already enrolled. Keep this state; deleting it invalidates the saved token and cursor")
    target = validate_target(args.kali)
    token = getpass.getpass("Cloud Box one-use collector enrollment token: ").strip()
    key = getpass.getpass("LAB_SHARED_KEY used on Kali (24+ characters): ")
    if len(key) < 24:
        raise ValueError("LAB_SHARED_KEY must have at least 24 characters")
    # Authenticate against the configured decoy before enrolling a Cloud Box collector.
    probe = get_kali_events(target, key, 0, 1)
    target_id = probe["target_id"]
    if not isinstance(target_id, str) or not target_id.startswith("kali-") or len(target_id) > 64:
        raise ValueError("Target returned an invalid identity")
    base = "http://127.0.0.1:8765"  # Strict host loopback; never expose Cloud Box to LAN.
    enrolled = api(base + "/api/v1/collectors/enroll", "POST", {"token": token, "name": "Kali Lab Relay"})
    cfg = {"schema_version": 1, "cloudbox_base": base, "kali_base": target,
           "kali_key": key, "collector_id": enrolled["collector_id"],
           "collector_token": enrolled["token"], "target_id": target_id,
           "cursor": 0, "created_at": utc()}
    save_config(config_path, cfg)
    print("Enrolled Kali Lab Relay collector. Credentials stored locally at " + str(config_path))
    print("Next: run the Cloud Box intake configuration script so the admin sees these records in their case.")


def sync_once(cfg: dict, config_path: Path) -> dict:
    target, key, base = cfg["kali_base"], cfg["kali_key"], cfg["cloudbox_base"]
    headers = {"Authorization": "Bearer " + cfg["collector_token"]}
    result = get_kali_events(target, key, int(cfg["cursor"]), 80)
    target_id = result["target_id"]
    # New Kali evidence database? Preserve the old cursor and explicitly require re-enrollment
    # instead of quietly misattributing observations across restarts.
    if target_id != cfg["target_id"]:
        raise RuntimeError("Kali target identity changed. Re-enroll a new Cloud Box collector and keep old records untouched")
    observations = result["items"]
    last = int(cfg["cursor"])
    if observations:
        wires = [make_wire(target_id, r) for r in observations]
        response = api(base + "/api/v1/ingest/events", "POST",
                       {"batch_id": secrets.token_hex(16), "events": wires}, headers)
        outcomes = response.get("items", [])
        if len(outcomes) != len(observations):
            raise RuntimeError("Cloud Box returned incomplete receipt list")
        for rec, outcome in zip(observations, outcomes):
            if str(outcome.get("source_seq")) != str(rec["id"]) or outcome.get("outcome") not in ("accepted", "duplicate"):
                raise RuntimeError("Cloud Box rejected an observed record: " + str(outcome)[:300])
            # Cloud Box STAGED receipts are durable. It seals them in its background worker.
            last = int(rec["id"])
        cfg["cursor"] = last
        save_config(config_path, cfg)
    heartbeat = {"version": "lab-relay/1.0", "platform": "windows-host-relay",
                 "time": utc(), "observed_target": target, "target_id": target_id,
                 "last_relayed_sequence": last, "source_type": "lab.fixture",
                 "scope": "Observed traffic at a deliberately configured Kali decoy; simulation-labelled evidence"}
    api(base + "/api/v1/collectors/heartbeat", "POST", heartbeat, headers)
    return {"new_records": len(observations), "cursor": last, "target_id": target_id}


def run(args):
    path = args.state / "relay.json"
    if not path.is_file():
        raise ValueError("Not enrolled. Run relay.py init --kali http://YOUR_KALI_PRIVATE_IP:8088")
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if cfg["cloudbox_base"] != "http://127.0.0.1:8765":
        raise ValueError("Relay only supports host-local Cloud Box on 127.0.0.1:8765")
    validate_target(cfg["kali_base"])
    print(f"Relay connected: Kali {cfg['kali_base']} -> Cloud Box localhost:8765. Ctrl+C to stop.")
    while True:
        try:
            outcome = sync_once(cfg, path)
            if outcome["new_records"]:
                print(f"[{utc()}] Forwarded {outcome['new_records']} observed records; cursor={outcome['cursor']}", flush=True)
        except (RuntimeError, ValueError, KeyError, OSError) as exc:
            print(f"[{utc()}] Relay warning: {exc}", file=sys.stderr, flush=True)
            if args.once:
                raise
        if args.once:
            print(json.dumps(outcome, indent=2))
            return
        time.sleep(max(2, min(args.interval, 60)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_DIR)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init", help="Enroll once, using a Cloud Box one-use token")
    init.add_argument("--kali", required=True, help="Example: http://192.168.56.101:8088")
    loop = sub.add_parser("run", help="Poll Kali's observed events and forward to Cloud Box")
    loop.add_argument("--once", action="store_true")
    loop.add_argument("--interval", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            initialize(args)
        else:
            run(args)
    except (ValueError, RuntimeError, OSError, KeyError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
