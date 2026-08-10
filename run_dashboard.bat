@echo off
setlocal EnableExtensions
title Network Guard Dashboard
cd /d "%~dp0"

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo ERROR: Python 3 not found.
  pause
  exit /b 1
)

echo Starting Network Guard Command Center...
echo Browser will open to http://127.0.0.1:8765/
echo.
%PY% "%~dp0ng_dashboard.py" %*
pause
