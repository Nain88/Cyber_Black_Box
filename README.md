# Cyber Black Box

**18 November: the active simulation sender now runs in Docker Desktop Linux containers. Kali is not required for the three integrated scenarios. See [Docker setup](docs/DOCKER-LAB.md).**

The [14 November Kali presentation guide](docs/KALI-PRESENTATION-2026-11-14.md) documents the earlier SSH sender. Its sender instructions do not apply to the current Docker Lab page. Optional Kali journal collection remains separate from Docker simulations.

Editable source for a dual-deployment FYP evidence preservation and investigation platform. Windows Virtual Mode and Linux Cloud Mode share the API, data model and web interface. No hardware mode is included.


The November Windows release includes a native Suricata/Npcap sensor, Windows Firewall evidence, a polling Live monitor, and local Ollama case analysis. Use [the Windows live demo guide](docs/WINDOWS-LIVE-DEMO.md) and [the acceptance audit](docs/LIVE-ACCEPTANCE.md) for the tested laptop setup and coverage limits.

The [12 November release acceptance](docs/RELEASE-ACCEPTANCE-2026-11-12.md) records the automated checks from that date, real HTTP smoke test, restore test, and remaining deployment limits.

The [11 November code audit](docs/AUDIT-2026-11-11.md) records the fixes, automated checks, dependency scan, and Docker setup status from that date.

Start on Your Computer

The project is saved in `D:\CloudBox`.

1. Double-click **Start-Cyber-Black-Box.cmd**. Keep its window open.
2. Open **http://127.0.0.1:8765**.
3. On first run, paste the setup token shown in the launcher and choose an administrator name and password (minimum 12 characters).
4. Create investigator/reviewer accounts in Administration. Administrators see evidence explicitly assigned to their cases; investigators can search the evidence pool. Enable MFA in account settings.
5. Create a case, import an authorized log file, review evidence, run integrity verification, and generate a signed case export.

The bundled `.venv` is local to this computer. A downloaded source ZIP excludes it. On another Windows machine install Python 3.12+, then run `Start-Cyber-Black-Box.cmd -Install`. The ZIP includes the built interface. Internet access is needed to install Python dependencies. To rebuild the interface install Node 22 and pnpm 10, then run:

```powershell
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
.\.venv\Scripts\python.exe -m pytest -q
```

## Kali log collection

The integrated **Attack simulation lab** uses Docker for its three bounded scenarios and provides administrator Start/Stop controls. It automatically creates an evidence case and generates JSON, Word and PDF reports. Each report has a detached Ed25519 signature and is included in a signed evidence ZIP. Follow the [current Docker walkthrough](docs/DOCKER-LAB.md) for setup, verification and coverage limits. Kali journal collection is an optional, separate workflow.

With the existing Kali VM running, start Cloud Box and then `Start-Kali-Log-Bridge.cmd`. Keep both terminals open. The bridge reconnects interrupted SSH connections; existing queued events remain with the Kali collector. See [Kali connection setup and verified behavior](docs/KALI-LOG-CONNECTION.md).

## Synthetic demonstration

For a separate empty demonstration database:

```powershell
.\.venv\Scripts\python.exe -m cbb.cli --data my-demo demo
.\.venv\Scripts\python.exe -m cbb.cli --data my-demo serve
```

The first command prints a newly generated password. All demonstration observations are labelled synthetic and do not access a real endpoint. Never confuse these observations with collected evidence. Use a new directory when repeating initialization.

## Implemented modules

| Proposal module | Implementation |
| --- | --- |
| M01 Gateway | Bounded intake, single-use enrollment, collector tokens, cloud certificate binding, receipts and duplicate/conflict handling |
| M02 Windows collector | Explicitly enabled Event Log polling, durable bookmarks/spool, source health |
| M03 Linux collector | Journal cursors, health, durable spool and retries |
| M04 Network | Bounded genuine Suricata live runner (Linux/WSL), EVE import/tailing, offline PCAP adapter, Zeek JSON adapter |
| M05 File integrity | Allowlisted paths, watchdog/reconciliation, hashes and YARA screening |
| M06 Schema | Versioned Pydantic schema, raw preservation, normalization and canonical JSON |
| M07 Integrity | Hash chains, custody ledger, Ed25519 checkpoints, independent witness service, offline package verifier |
| M08 Storage | SQLite/PostgreSQL, raw segments, artifact uploads, S3 Object Lock adapter, MEGA hash-verified archive/staged restore, backup/restore |
| M09 Correlation | Explainable process/file/network candidates, timeline, analyst decisions and manual regrouping |
| M10 Anomaly scoring | Reviewed baseline training, Isolation Forest, chronological holdout, versioned model hashes, ranked alerts, local evidence assistant and optional local Ollama |
| M11 Forensic trigger | Scoped proposals, separate approval, signed plans, leases, bounded acquisitions and resumable uploads |
| M12 Investigation UI | Cases, evidence search, alerts, collectors, integrity, custody, acquisitions, reports, jobs, models and administration |

See [deployment instructions](docs/DEPLOYMENT.md), [collector guide](docs/AGENT_GUIDE.md), [implementation status and limits](docs/IMPLEMENTATION_STATUS.md), and the original architecture documents in `output/`.

## Technology and directory map

Python 3.12, FastAPI, Uvicorn, SQLAlchemy, SQLite/PostgreSQL, React, TypeScript, Vite, Argon2id, TOTP, Ed25519, RFC 8785, scikit-learn, watchdog, psutil, YARA, HTTPX, boto3, Docker Compose and Nginx. Suricata and optional memory/Volatility tools are external integrations requiring platform-specific installation and configuration.

`cbb/` contains the backend, collectors, signer, witness and verifier. `web/` contains editable UI source and compiled `dist/`. `tests/` contains automated tests. `deploy/`, `scripts/` and Compose files contain operational configuration. `rules/` contains a benign YARA test rule. `data/` is created for live evidence; `demo-data/` is separate. Neither live data nor private credentials belong in source control or the release ZIP.

## Operator commands

```powershell
.\.venv\Scripts\python.exe -m cbb.cli --help
.\.venv\Scripts\python.exe -m cbb.agent --help
.\.venv\Scripts\python.exe -m cbb.cli --data data verify
.\.venv\Scripts\python.exe -m cbb.cli verify-package case.zip --public-key TRUSTED_BASE64_PUBLIC_KEY
```

Stop the server before local offline verification, checkpoint, backup or restore commands. Verification proves the checked bytes against the supplied trust anchors, not truthful capture or complete observation. Independently retain signing public keys and checkpoints.

This is an implemented FYP software project, not a certification of production readiness or zero defects. See the status document for actual verification and outstanding environment tests.

## October 30 integration upgrade

Read [INTEGRATIONS-GUIDE.md](docs/INTEGRATIONS-GUIDE.md) for step-by-step MEGA login, WSL Suricata setup, a real harmless HTTP marker scenario, AI review and signed DOCX/PDF reports. [UPGRADE-AUDIT.md](docs/UPGRADE-AUDIT.md) distinguishes tested local behavior from environment acceptance still pending. The original architecture documents remain design references; this guide records the implemented changes.
