@echo off
rem Builds and starts Cyber Black Box in Docker Desktop (4 containers).
rem   Start-Docker.cmd           start / update
rem   Start-Docker.cmd -Reset    wipe all evidence volumes and start fresh
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-up.ps1" %*
pause
