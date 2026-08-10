@echo off
setlocal EnableExtensions
title Network Guard
cd /d "%~dp0"

echo ============================================
echo  Network Guard - local + LAN triage
echo ============================================
echo.

REM Prefer py launcher, then python, then python3
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY where python3 >nul 2>&1 && set "PY=python3"
if not defined PY (
  echo ERROR: Python 3 was not found on PATH.
  echo Install Python 3 from https://www.python.org/downloads/
  echo and enable "Add python.exe to PATH".
  pause
  exit /b 1
)

REM Relaunch elevated if not already admin
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%COMSPEC%' -Verb RunAs -ArgumentList '/c \"\"%~f0\"\" %* & pause'"
  exit /b 0
)

echo Running elevated.
echo For each threat you can View / Kill / Block / Allow / Skip.
echo.
REM Interactive by default. Pass --yes for unattended auto-block.
REM Pass --dry-run to inspect without changing anything.
%PY% "%~dp0network_guard.py" --lan %*
set "EC=%ERRORLEVEL%"
echo.
echo Exit code: %EC%
echo Log file: "%~dp0network_guard.log"
echo.
pause
exit /b %EC%
