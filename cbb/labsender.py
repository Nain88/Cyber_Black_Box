"""Attack-simulation sender service for the Docker lab container.

Runs in its own container on the private compose network. The Cyber Black Box
app asks it (with a shared bearer token) to execute one of the fixed, bounded
scenarios in ``cbb.lab.SCENARIOS`` against the app's temporary decoy
listeners. The sender never accepts arbitrary code, hosts outside the
configured allowlist, or user-supplied payloads.
"""
import argparse
import ipaddress
import os
import secrets
import socket
import subprocess
import sys
import threading

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .lab import SCENARIOS, runner_source


class Run(BaseModel):
    scenario: str
    token: str = Field(min_length=16, max_length=128)
    host: str = Field(min_length=1, max_length=253)
    http_port: int = Field(ge=1024, le=65535)
    tcp_port: int = Field(ge=1024, le=65535)


def _private_target(host, allowed):
    """Only the configured app host(s) on a private network may be targeted."""
    if host not in allowed:
        return False
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(a).is_private for a in addresses)


def create_sender(token=None, allowed_hosts=None):
    secret = token if token is not None else os.getenv("CBB_LAB_SENDER_TOKEN", "")
    if len(secret) < 32:
        raise ValueError("CBB_LAB_SENDER_TOKEN must contain at least 32 random characters")
    allowed = set(allowed_hosts or [h.strip() for h in os.getenv("CBB_LAB_ALLOWED_TARGETS", "app").split(",") if h.strip()])
    busy = threading.Lock()
    app = FastAPI(title="Cyber Black Box lab sender", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health/live")
    def live():
        return {"status": "alive", "scenarios": sorted(SCENARIOS)}

    @app.post("/run")
    def run(body: Run, authorization: str = Header(default="")):
        if not secrets.compare_digest(authorization, "Bearer " + secret):
            raise HTTPException(401, "Sender authentication required")
        if body.scenario not in SCENARIOS:
            raise HTTPException(422, "Unknown scenario")
        if not _private_target(body.host, allowed):
            raise HTTPException(422, "Target is not an allowed private lab host")
        if not busy.acquire(blocking=False):
            raise HTTPException(409, "Another simulation is running")
        try:
            source = runner_source(body.scenario, body.token, host=body.host, http_port=body.http_port, tcp_port=body.tcp_port)
            try:
                result = subprocess.run([sys.executable, "-I", "-"], input=source.encode(), capture_output=True, timeout=45)
            except subprocess.TimeoutExpired:
                raise HTTPException(504, "Simulation timed out")
            return {"scenario": body.scenario, "exit_code": result.returncode, "ok": result.returncode == 0}
        finally:
            busy.release()

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8780)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_sender(), host=args.host, port=args.port, workers=1)


if __name__ == "__main__":
    main()
