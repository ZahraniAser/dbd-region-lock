@echo off
REM Builds dist\DBDRegionLock.exe: one file, no Python needed to run it, asks for admin on launch.
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || exit /b 1
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin ^
  --name DBDRegionLock --icon assets\icon.ico --add-data "assets\icon.ico;assets" ^
  dbd_region_lock_app.py || exit /b 1
echo.
echo Built dist\DBDRegionLock.exe
