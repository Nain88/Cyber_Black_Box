# Technical architecture and trust boundaries

This file describes the legacy optional Docker add-on. The integrated native application uses Kali as the sender and a Windows loopback decoy as the observation source. See [the current presentation architecture](../../docs/KALI-PRESENTATION-2026-11-14.md).

```text
Windows host (Docker Desktop)                  Kali VM (isolated/private)
┌──────────────────────────┐                  ┌─────────────────────────┐
│ Docker attacker dashboard│ ----HTTP/TCP---> │ Kali decoy target       │
│ 127.0.0.1:8844           │   8088-8090      │ - 8088 HTTP login/probes│
│ preapproved scenarios    │                  │ - 8089/8090 TCP decoys  │
└──────────────────────────┘                  │ - SQLite observation DB │
                                             └────────────┬────────────┘
                                                          │ HMAC GET events
Windows HOST (not Docker)                                 │
┌──────────────────────────┐                              │
│ Relay (Python stdlib)    │ <----------------------------┘
│ local private credentials│
└────────────┬─────────────┘
             │ authenticated REST ingest + heartbeat
             v
┌────────────────────────────────────────────────────────────────┐
│ Existing Cloud Box, Windows native, bound to 127.0.0.1:8765 │
│ Receipt: STAGED -> raw seal + hash chain -> alerts / case      │
└────────────────────────────────────────────────────────────────┘
```

## Why the relay stays on Windows

The existing Cloud Box virtual deployment deliberately binds to host loopback. A Kali VM or Docker container cannot reliably access a Windows 127.0.0.1 listener as if it were on the same machine. The relay bridges those environments from the Windows host without opening Cloud Box's listener to the network.

## Provenance

- The Kali decoy logs the actual incoming peer address, port, timestamp and limited request metadata.
- All records are labelled `lab_simulation: true` and forwarded as Cloud Box `lab.fixture` evidence.
- The lab is deliberately **not** described as genuine Suricata telemetry.
- Existing Cloud Box `record_indicator` creates a basic alert for records with severity >= 3 after sealing and analysis. This is a deterministic lab-rule alert, not an IDS signature detection.
- Cloud Box's collector heartbeat shows whether the relay can forward events. An inactive relay shows stale health in Cloud Box.
- The relay advances its local cursor only after Cloud Box reports accepted/duplicate durable receipts. Cloud Box performs sealing asynchronously.
- Relay restarts are safe: re-sending events with the same target ID and source sequence results in duplicates, not new evidence.

## Isolation and limits

- The dashboard supports exactly one fixed RFC1918 target, port 8088.
- Only three hardcoded, bounded scenarios are exposed. No arbitrary host, port or command is accepted from a browser request.
- One active run at a time, at least six seconds between starts.
- Dashboard binds to Windows loopback (`127.0.0.1:8844`).
- Each Kali listener is a decoy and cannot execute commands or authenticate a real user.
- Target event polling requires a shared HMAC secret, timestamp and one-time nonce, preventing casual unauthorized polling or replay. Kali also signs the event response bytes against the request nonce, so the relay rejects altered responses.
- A plain-HTTP private subnet and environment-managed secret are acceptable for an isolated demonstration, not for an untrusted LAN. For stronger isolation use a host-only VM network or authenticated TLS tunnel.
- Real network IDS testing requires separately installing/configuring Suricata on a suitable interface and using Cloud Box's genuine Suricata collector. This package does not fake those logs.

## Operational considerations

- Cloud Box should be running with its background workers enabled; otherwise accepted records may remain staged.
- An admin sees case-scoped records; attach collector intake to an admin-owned case with `Configure-CloudBox-Intake.ps1`.
- Keep `lab/.env`, `lab/.lab-state/` and Kali `.lab-kali-data/` out of GitHub. They contain credentials or captured data.
- Synchronize Kali and Windows clocks (HMAC timestamp drift limited to 60 seconds).
- Ensure Kali is not bridged onto an untrusted/public network. Do not expose ports 8088-8090 outside the approved VM network.
