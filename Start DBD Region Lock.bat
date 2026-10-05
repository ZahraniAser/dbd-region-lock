@echo off
REM Double-click to run from source. Needs Python 3.10+ (python.org, tick "Add to PATH").
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH", or download DBDRegionLock.exe from the Releases page.
  start "" https://www.python.org/downloads/
  pause
  exit /b 1
)
start "" pythonw -m dbd_region_lock
