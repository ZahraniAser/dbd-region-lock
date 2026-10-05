@echo off
REM Builds dist\DBDRegionLock.exe: a single file that asks for admin rights on launch.
python -m pip install --upgrade pyinstaller || exit /b 1
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name DBDRegionLock dbd_region_lock_app.py || exit /b 1
echo.
echo Built dist\DBDRegionLock.exe
