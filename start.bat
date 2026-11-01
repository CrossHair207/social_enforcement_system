@echo off
REM ---------------------------------------------------------------------------
REM Social Enforcement Management System - Windows launcher
REM Creates a virtual environment, installs dependencies, initialises the
REM SQLite database and starts the dashboard on http://127.0.0.1:8000
REM ---------------------------------------------------------------------------
setlocal enabledelayedexpansion
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON=py -3"
) else (
    where python >nul 2>nul
    if %errorlevel% neq 0 (
        echo [ERROR] Python 3.10+ was not found on PATH.
        echo Install it from https://www.python.org/downloads/windows/ and tick
        echo "Add python.exe to PATH", then run this script again.
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

if not exist ".venv" (
    echo [1/4] Creating virtual environment...
    %PYTHON% -m venv .venv || goto :error
)

call ".venv\Scripts\activate.bat" || goto :error

echo [2/4] Installing dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt || goto :error

if not exist ".env" (
    echo [3/4] Creating .env from .env.example ...
    copy /y ".env.example" ".env" >nul
    echo.
    echo     A new .env file was created. Set SECRET_KEY and ADMIN_PASSWORD
    echo     before using this system for real cases, then run start.bat again.
    echo.
)

echo [4/4] Starting the dashboard on http://127.0.0.1:8000
start "" http://127.0.0.1:8000
python -m uvicorn app:app --host 127.0.0.1 --port 8000
goto :eof

:error
echo.
echo [ERROR] Setup failed. Review the message above.
pause
exit /b 1
