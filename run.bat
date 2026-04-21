@echo off
REM SIM Card Reader - One-click launcher (Windows)
setlocal

echo.
echo ========================================
echo   SIM Card Reader -- Web UI
echo ========================================
echo.

set DIR=%~dp0
set VENV=%DIR%.venv
set PORT=8082
set URL=http://127.0.0.1:%PORT%
set PYTHON=%VENV%\Scripts\python.exe
set PIP=%VENV%\Scripts\pip.exe

REM Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

REM Create venv if needed
if not exist "%PYTHON%" (
    echo [SETUP] Creating virtual environment...
    python -m venv "%VENV%"
)

REM Install dependencies: check by importing cmd2 (pySim core dep)
"%PYTHON%" -c "import pySim" >nul 2>&1
if errorlevel 1 (
    echo [SETUP] Installing dependencies...
    "%PIP%" install -q --disable-pip-version-check -r "%DIR%requirements.txt"
    echo [SETUP] Installing pySim...
    "%PIP%" install -q --disable-pip-version-check -e "%DIR%pysim"
    echo [SETUP] Done.
)

REM Kill existing process on the same port
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%PORT% " ^| findstr "LISTENING"') do taskkill /F /PID %%a >nul 2>&1

REM Open browser after delay
start "" "%URL%"

REM Start server (use venv python directly)
echo [START] SIM Card Reader at %URL%
set PYTHONDONTWRITEBYTECODE=1
"%PYTHON%" -u "%DIR%src\app.py"
pause
