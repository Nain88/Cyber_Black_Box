@echo off
docker info >nul 2>&1
if errorlevel 1 (
 echo Start Docker Desktop and wait until its Linux engine is running.
 pause
 exit /b 1
)
docker pull python@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
if errorlevel 1 exit /b 1
echo Docker simulation sender ready. Start Cloud Box and open Attack simulation lab.
pause
