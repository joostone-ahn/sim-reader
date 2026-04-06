@echo off
REM SIM Card Reader - One-click launcher (Windows)
setlocal

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

REM Install dependencies if needed
if not exist "%VENV%\.deps_installed" (
    echo [SETUP] Installing dependencies...
    "%PIP%" install -q -r "%DIR%requirements.txt"
    "%PIP%" install -q -e "%DIR%pysim"
    if errorlevel 1 (
        echo [WARN] Some pySim dependencies failed to install, retrying without optional deps...
        "%PIP%" install -q --no-deps -e "%DIR%pysim"
    )
    echo. > "%VENV%\.deps_installed"
)

REM Open browser after delay
start "" "%URL%"

REM Start server (use venv python directly)
echo [START] SIM Card Reader at %URL%
"%PYTHON%" "%DIR%src\app.py"
pause
