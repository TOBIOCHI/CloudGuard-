@echo off
setlocal
cd /d "%~dp0"

echo.
echo ==========================================
echo          CLOUDGUARD WINDOWS SETUP
echo ==========================================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python Launcher was not found.
    echo Install Python 3.11 or newer, including the Python Launcher.
    goto :failed
)

py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
    echo ERROR: Python 3.11 or newer is required.
    goto :failed
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating CloudGuard virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 goto :failed
)

echo.
echo Installing Python dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed

if not exist ".env" (
    if not exist ".env.example" (
        echo ERROR: .env.example is missing.
        goto :failed
    )
    copy ".env.example" ".env" >nul
    if errorlevel 1 goto :failed
)

echo.
echo Generating Flask secret key if the example placeholder remains...
".venv\Scripts\python.exe" -c "from pathlib import Path; import secrets; p=Path('.env'); s=p.read_text(encoding='utf-8'); old='FLASK_SECRET_KEY=replace_this_with_a_long_random_secret_key'; new='FLASK_SECRET_KEY='+secrets.token_hex(32); p.write_text(s.replace(old,new), encoding='utf-8')"
if errorlevel 1 goto :failed

echo.
where aws >nul 2>nul
if errorlevel 1 (
    echo NOTE: AWS CLI was not detected.
    echo Install AWS CLI v2 and configure your own audit profile before scanning.
) else (
    echo AWS CLI detected. Configure your own audit profile before scanning.
)

echo.
echo CloudGuard setup completed successfully.
echo Run start_cloudguard.bat to open the dashboard.
pause
exit /b 0

:failed
echo.
echo CloudGuard setup did not complete.
echo Check the error above and try again.
pause
exit /b 1
