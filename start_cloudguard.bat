@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo CloudGuard is not installed yet.
    echo Run install_windows.bat first.
    pause
    exit /b 1
)

echo.
echo Starting CloudGuard dashboard...
echo Press Ctrl+C in this window to stop it.
echo.

".venv\Scripts\python.exe" app.py
set "APP_EXIT=%ERRORLEVEL%"

if not "%APP_EXIT%"=="0" (
    echo.
    echo CloudGuard stopped with an error. Review the message above.
    pause
)

exit /b %APP_EXIT%
