@echo off
setlocal EnableExtensions
title Network Guard Agent
cd /d "%~dp0"

echo ============================================
echo  Network Guard Agent - share THIS screen
echo  Run on devices you want to monitor
echo ============================================
echo.

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY where python3 >nul 2>&1 && set "PY=python3"
if not defined PY (
  echo ERROR: Python 3 was not found on PATH.
  pause
  exit /b 1
)

%PY% -c "from PIL import ImageGrab" 1>nul 2>nul
if errorlevel 1 (
  echo Installing Pillow...
  %PY% -m pip install pillow
)

echo Starting agent. Leave this window open.
echo.
%PY% "%~dp0network_guard_agent.py" %*
echo.
pause
