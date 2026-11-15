# Release acceptance — 12 November 2026

## Results from this run

| Area | Result | Boundary |
|---|---|---|
| Backend regression | 92 passed | One upstream Starlette/httpx deprecation warning |
| Lab controller, target and relay | 9 passed | Local fixtures and loopback target; not the Kali VM |
| Frontend | 3 tests passed; TypeScript and Vite production build passed | No new browser interaction sweep |
| Real server smoke test | Passed login, compiled asset fetch, overview, cases, evidence, alerts, incidents, collectors, checkpoints, custody, jobs, exports and verification-runs | Isolated synthetic six-event database, real loopback HTTP |
| Background exports | Job completed; downloaded ZIP verified VALID using separately retained public key | Local signatures, not independent witnessing |
| Backup and restore | Offline backup restored into a new empty directory and verified | Isolated SQLite deployment, not PostgreSQL disaster recovery |
| Installed dependencies | pip check clean | Not a fresh advisory scan |
| Native tools | Suricata 8.0.7 and Zeek 7.0.0 executable probes passed; firewall logging enabled on all profiles | Installation/configuration availability is not capture completeness |
| Zeek packet processing | Captured 11 packets from a controlled loopback HTTP exchange; native offline replay emitted a connection record | Local traffic only; not an external network coverage test |
| Ollama | Local service and qwen2.5:0.5b model available | Model inference not rerun in this audit |

## Changes

The complete-project release builder now includes the tracked Kali lab, its Compose file, setup guide and native launcher. It selects tracked source and explicitly generated public artifacts instead of recursively including arbitrary local files. Private evidence, lab state, credentials, environments and cache junctions are excluded. The built frontend is included and required before packaging.

The Windows launcher builds a missing frontend when pnpm is available, so a fresh Git clone can start after installing Python and frontend prerequisites. The complete ZIP already includes the frontend. Python dependencies still need internet access on a new machine.

Run `python scripts/audit_smoke.py` from the project root using the project virtual environment to repeat the HTTP/export/backup/restore acceptance test. It uses temporary synthetic data, terminates its own server, and writes non-secret results under `work/`.

## Remaining acceptance gates

- Docker/WSL: Windows component-store error 14098 remains unresolved. The Windows repair version was started separately; its completion and reboot have not been verified here. Native project operation does not require Docker.
- Kali: the VM was located on E:. Host-reachable decoy networking, guest target installation, relay enrollment and live ingestion remain pending.
- PostgreSQL/cloud deployment, cloud mTLS, S3 Object Lock, independent witness and remote signing require their actual configured environments.
- MEGA cloud transfer was not repeated; no private data was uploaded by this audit.
- Privileged acquisition tools, real Linux journals and broad Windows channel permissions require endpoint-specific acceptance.
- Large exports still buffer proof/evidence metadata; storage crash reconciliation, schema migration design and sustained-load acceptance remain open engineering work.

This release contains working, tested core application paths. It is not a claim that every external tool is configured, every detection is correct, or all potential defects have been eliminated.
