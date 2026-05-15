@echo off
REM start.bat – Quick-start script for PhishGuard on Windows
REM Usage: Double-click or run from cmd: start.bat

echo ==================================================
echo  PhishGuard – Phishing Email Detection System
echo ==================================================

REM Check if .env exists
if not exist ".env" (
    echo [!] No .env file found. Copying from .env.example...
    copy .env.example .env
    echo [!] Edit .env and set DB_PASSWORD before continuing.
    pause
)

REM Create required directories
if not exist "exports" mkdir exports
if not exist "logs"    mkdir logs

REM Install dependencies
echo [*] Installing Python dependencies...
pip install -r requirements.txt --break-system-packages

REM Start the Flask server
echo.
echo [*] Starting PhishGuard at http://localhost:5000
echo     Press Ctrl+C to stop.
echo.
python app.py
pause
