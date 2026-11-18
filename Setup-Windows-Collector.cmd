@echo off
cd /d "%~dp0"
echo Stop the running Cloud Box server with Ctrl+C before continuing.
echo This configures Windows System and Application log collection locally.
echo Complete the first administrator setup before running this helper.
pause
if not exist ".venv\Scripts\python.exe" (
 echo First run Start-Cyber-Black-Box.cmd -Install and complete administrator setup.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" scripts\provision-local-sensor.py
if errorlevel 1 (
 echo Setup did not finish. Read the error above. Existing evidence was not deleted.
 pause
 exit /b 1
)
call Start-Cyber-Black-Box.cmd
