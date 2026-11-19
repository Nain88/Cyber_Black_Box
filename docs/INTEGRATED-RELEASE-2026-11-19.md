# Integrated release — 19 November 2026

Merged `origin/fyp/docker-audit-gui` (e7b5735) and `origin/main` (3a6bab7), preserving the local audit fixes.

The release combines the four-container Docker deployment, redesigned GUI, lightweight animations and motion toggle, Windows event parsing fixes, queue indexes, cancellable non-overlapping refreshes and explicit case selection. Four GUI merge conflicts were resolved by preserving both the redesign and the audit safeguards.

Validation of the combined version:

- Backend: 138 tests passed; one existing Starlette/httpx deprecation warning.
- Frontend: 13 tests passed; TypeScript and Vite production build passed.
- HTTP acceptance: 11 routes, built GUI assets, signed ZIP verification and offline backup/restore passed using synthetic data.
- Docker Compose configuration validated with placeholder secrets.
- Windows Docker launcher syntax and 1,000 generated secrets validated. Launcher now fails clearly on readiness timeout, preserves credentials after a failed reset, and generates fixed-length random hexadecimal secrets.
- Docker image build: completed. Verified on 20 November: image sha256:367d9042891ac99f5224b8da659f812adba8dcae0661adfd972a9ed6fbccac65; isolated container imports and packaged GUI check passed.

Start on Windows with Docker Desktop running Linux containers, then double-click `Start-Docker.cmd`. The first run creates local secrets and asks you to create the administrator using its setup token. Do not use `-Reset` unless you intend to erase Docker evidence volumes.

The complete ZIP includes source, tests, documentation, Docker configuration and the built GUI. It excludes runtime data, passwords, local evidence, dependency folders and Docker images. The Docker image is built locally; it is not published to an image registry. A successful image build is not a live end-to-end certification of sensors, cloud services or the running four-container deployment.
