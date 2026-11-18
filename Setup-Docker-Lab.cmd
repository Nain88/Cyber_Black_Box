@echo off
setlocal
where docker >nul 2>&1
if errorlevel 1 (
 echo Docker CLI was not found. Install Docker Desktop, then reopen this helper.
 pause
 exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
 echo Start Docker Desktop and wait until its Linux engine is running.
 pause
 exit /b 1
)
set "CBB_DOCKER_OS="
for /f "delims=" %%O in ('docker info --format "{{.OSType}}" 2^>nul') do set "CBB_DOCKER_OS=%%O"
if /i not "%CBB_DOCKER_OS%"=="linux" (
 echo Switch Docker Desktop to Linux containers, then run this helper again.
 pause
 exit /b 1
)
docker pull python@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
if errorlevel 1 (
 echo Sender image download failed. Check your connection and the Docker error above.
 pause
 exit /b 1
)
echo Docker simulation sender ready. Start Cloud Box and open Attack simulation lab.
pause
