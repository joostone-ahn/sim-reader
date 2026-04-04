@echo off
REM SIM Card Reader - One-click launcher (Windows)
setlocal

set DIR=%~dp0
set VENV=%DIR%.venv
set PORT=8082
set URL=http://127.0.0.1:%PORT%

REM Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

REM Create venv if needed
if not exist "%VENV%\Scripts\activate.bat" (
    echo 📦 Creating virtual environment...
    python -m venv "%VENV%"
)

REM Activate
call "%VENV%\Scripts\activate.bat"

REM Install dependencies if needed
if not exist "%VENV%\.deps_installed" (
    echo 📦 Installing dependencies...
    pip install -q -r "%DIR%requirements.txt"
    echo. > "%VENV%\.deps_installed"
)

REM Open browser after delay
start "" "%URL%"

REM Start server
echo 🚀 Starting SIM Card Reader at %URL%
python "%DIR%src\app.py"
pause
