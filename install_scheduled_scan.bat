@echo off
setlocal EnableExtensions
title Install Network Guard Scheduled Scan
cd /d "%~dp0"

REM Creates an hourly quiet LAN scan task (report-only dry-run by default).
REM Change --dry-run to remove for auto-promptless --yes if you want auto-block.

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo Python not found.
  pause
  exit /b 1
)

for /f "delims=" %%I in ('%PY% -c "import sys; print(sys.executable)"') do set "PYEXE=%%I"

schtasks /Create /F /TN "NetworkGuardHourlyScan" /SC HOURLY /MO 1 /RL HIGHEST ^
  /TR "\"%PYEXE%\" \"%~dp0network_guard.py\" --lan --yes --dry-run --json-out \"%~dp0reports\last_scheduled.json\""

if errorlevel 1 (
  echo Failed to create scheduled task. Run this BAT as Administrator.
) else (
  echo Created scheduled task: NetworkGuardHourlyScan
  echo It runs hourly dry-run LAN scans. Edit the task in Task Scheduler to change behavior.
)
pause
