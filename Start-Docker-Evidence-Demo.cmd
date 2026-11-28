@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Start Cyber Black Box once to prepare its local Python environment.
    pause
    exit /b 1
)
docker compose -f compose.demo-site.yml up -d --build
if errorlevel 1 (
    pause
    exit /b 1
)
echo Docker Security Simulation Lab is available at http://127.0.0.1:8081
".venv\Scripts\python.exe" -m cbb.demo_site_bridge
if errorlevel 1 (
    pause
    exit /b 1
)
