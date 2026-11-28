"""Deliver the separate Docker lab's synthetic events through the standard collector."""

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

from .agent import Agent, SpoolFull
from .cli import exclusive
from .schema import parse_time


CONTAINER = "cbb-evidence-demo"
SERVER = "http://127.0.0.1:8765"
CURSOR_KEY = "docker_demo_cursor"
SCENARIO_COUNTS = {"auth.failure": 6, "web.path": 5, "tcp.connection": 6}


def docker(*args):
    command = subprocess.run(
        ["docker", *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=12,
    )
    if command.returncode != 0:
        raise RuntimeError("Docker demo is unavailable. Check Docker Desktop and the demo container.")
    return command.stdout.strip()


def collect(agent):
    cursor = agent.spool.get(CURSOR_KEY, {"stream": "-", "sequence": 0})
    template = '{{.Id}} {{index .Config.Labels "org.cyberblackbox.purpose"}}'
    container_id, _, purpose = docker("inspect", "--format", template, CONTAINER).partition(" ")
    if purpose != "passive-demo-site" or not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise ValueError("Docker container identity does not match the evidence demo.")
    batch = json.loads(docker(
        "exec", container_id, "python", "-B", "/site/server.py", "read",
        cursor["stream"], str(cursor["sequence"]),
    ))
    if not isinstance(batch, dict):
        raise ValueError("Unexpected Docker lab log format.")
    stream, events = batch.get("stream"), batch.get("events")
    if (not isinstance(stream, str) or not re.fullmatch(r"[a-f0-9]{32}", stream)
            or not isinstance(events, list) or len(events) > 100):
        raise ValueError("Unexpected Docker demo log format.")
    previous = cursor["sequence"] if cursor["stream"] == stream else 0
    for row in events:
        if not isinstance(row, list) or len(row) != 2 or not isinstance(row[1], str):
            raise ValueError("Docker lab returned an invalid log row.")
        sequence, raw = row
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("Docker lab returned an invalid simulation record.")
        scenario = event.get("scenario")
        marker = event.get("marker")
        count = SCENARIO_COUNTS.get(scenario) if isinstance(scenario, str) else None
        if (type(sequence) is not int or sequence != previous + 1
                or event.get("schema") != "cbb.lab-fixture/1"
                or event.get("synthetic") is not True
                or count is None or event.get("total") != count
                or type(event.get("record")) is not int or not 1 <= event["record"] <= count
                or not isinstance(marker, str) or not re.fullmatch(r"CBB-LAB-[A-F0-9]{12}", marker)
                or not parse_time(event.get("occurred_at"))):
            raise ValueError("Docker lab returned an invalid simulation record.")
        agent.spool.enqueue(
            raw.encode("utf-8"), "lab.fixture", "lab.simulated." + scenario,
            original_timestamp=event["occurred_at"],
            cursor={"stream": stream, "sequence": sequence}, cursor_key=CURSOR_KEY,
        )
        previous = sequence
    return len(events)


def enroll(config_path):
    try:
        with httpx.Client(base_url=SERVER, trust_env=False, timeout=5) as client:
            response = client.get("/api/v1/status")
            response.raise_for_status()
            status = response.json()
    except httpx.HTTPError:
        raise RuntimeError("Start Cyber Black Box on port 8765 before enrolling the demo collector.") from None
    if status["setup_required"]:
        raise RuntimeError("Complete local Cyber Black Box setup before enrolling the demo collector.")
    print("Open Cyber Black Box → Collectors → Enroll collector.", flush=True)
    print("Use the name Docker Security Lab and create a token for this collector.", flush=True)
    token = getpass.getpass("Paste the one-time collector token and press Enter: ").strip()
    if not token:
        raise ValueError("No enrollment token was entered.")
    command = [
        sys.executable, "-m", "cbb.agent", "--config", str(config_path), "enroll",
        "--server", SERVER, "--server-key", status["public_key"], "--name", "Docker Security Lab",
    ]
    result = subprocess.run(command, env={**os.environ, "CBB_ENROLLMENT_TOKEN": token})
    if result.returncode != 0:
        raise RuntimeError("Enrollment failed. Check that the token is fresh and try again.")


def run(agent, once):
    last_message = None
    while True:
        try:
            agent.heartbeat()
            if agent.configuration.get("intake_case_id"):
                agent.flush()
                count = collect(agent)
                if count:
                    agent.flush()
                    print(f"Submitted {count} simulated security event(s) for preservation.", flush=True)
                message = "Collector active. Use the Docker page at http://127.0.0.1:8081."
            else:
                message = "In Collectors, configure the Docker lab collector and select an automatic intake case."
            error = False
        except (httpx.HTTPError, OSError, RuntimeError, ValueError, SpoolFull, subprocess.TimeoutExpired) as exc:
            message = f"Collector waiting. {exc}"
            error = True
        if message != last_message:
            print(message, flush=True)
            last_message = message
        if once:
            return int(error)
        time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("work/demo-site-agent/agent.json"))
    parser.add_argument("--once", action="store_true", help="Run one delivery cycle using existing credentials")
    args = parser.parse_args()
    config_path = args.config.resolve()
    root = config_path.parent
    try:
        with exclusive(root):
            if not config_path.exists():
                if args.once:
                    parser.error("Collector credentials are required for --once.")
                enroll(config_path)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            agent = Agent(config, root)
            try:
                return run(agent, args.once)
            finally:
                agent.client.close()
                agent.spool.close()
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
