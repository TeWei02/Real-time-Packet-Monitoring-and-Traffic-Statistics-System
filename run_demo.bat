@echo off
REM run_demo.bat – One-command demo runner for Windows
REM Usage: double-click or run from Command Prompt / PowerShell
REM ──────────────────────────────────────────────────────────────────────────────

setlocal EnableDelayedExpansion

REM ── Banner ────────────────────────────────────────────────────────────────────
echo.
echo  +--------------------------------------------------------------+
echo  ^|   Real-time Packet Monitoring ^& Traffic Statistics System   ^|
echo  ^|        Admissions / Portfolio Demo Runner  (Windows)        ^|
echo  +--------------------------------------------------------------+
echo.
echo   This script will:
echo     1. Verify your Python installation  (3.11+ required)
echo     2. Create an isolated virtual environment  (.\venv)
echo     3. Install the required Python packages
echo     4. Generate a synthetic demo.pcap  (200 packets, no admin needed)
echo     5. Run a full offline analysis and export all results
echo.
echo   Output files will be saved to:  .\output\
echo     - traffic_summary.csv         packet-level dataset
echo     - protocol_distribution.png   protocol pie chart
echo     - top_endpoints.png           top source/destination bar chart
echo     - report.md                   Markdown analysis report
echo.
echo  --------------------------------------------------------------
echo.

REM ── Locate Python (python first, then py launcher) ─────────────────────────
set "PYTHON="

for %%C in (python py) do (
    if "!PYTHON!"=="" (
        where %%C >nul 2>&1
        if !errorlevel! == 0 (
            for /f "tokens=2 delims= " %%V in ('%%C --version 2^>^&1') do (
                set "VER=%%V"
            )
            REM Extract major.minor
            for /f "tokens=1,2 delims=." %%A in ("!VER!") do (
                set "MAJOR=%%A"
                REM Strip any non-numeric suffix (e.g. rc1, a1) from minor token
                set "MINOR_RAW=%%B"
            )
            for /f "tokens=1 delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" %%N in ("!MINOR_RAW!") do (
                set "MINOR=%%N"
            )
            if !MAJOR! GEQ 3 (
                if !MINOR! GEQ 11 (
                    set "PYTHON=%%C"
                    echo [OK]    Found Python !VER! at %%C
                ) else (
                    echo [WARN]  %%C version !VER! found but 3.11+ is required.
                )
            ) else (
                echo [WARN]  %%C version !VER! found but 3.11+ is required.
            )
        )
    )
)

if "!PYTHON!"=="" (
    echo [ERROR] Python 3.11+ not found.
    echo         Please install it from https://www.python.org/ and re-run this script.
    goto :fail
)

REM ── Virtual environment ────────────────────────────────────────────────────
set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%venv"

if exist "!VENV_DIR!\Scripts\activate.bat" (
    echo [INFO]  Virtual environment already exists at !VENV_DIR! -- reusing it.
) else (
    echo [INFO]  Creating virtual environment at !VENV_DIR! ...
    !PYTHON! -m venv "!VENV_DIR!"
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create virtual environment.
        goto :fail
    )
    echo [OK]    Virtual environment created.
)

call "!VENV_DIR!\Scripts\activate.bat"
if !errorlevel! neq 0 (
    echo [ERROR] Could not activate virtual environment.
    goto :fail
)
echo [OK]    Virtual environment activated.

REM ── Install dependencies ───────────────────────────────────────────────────
set "REQ=%SCRIPT_DIR%requirements.txt"
if not exist "!REQ!" (
    echo [ERROR] requirements.txt not found at !REQ!
    goto :fail
)

echo [INFO]  Installing dependencies from requirements.txt
echo         (this may take a minute on first run) ...
pip install --quiet --upgrade pip
pip install --quiet -r "!REQ!"
if !errorlevel! neq 0 (
    echo [ERROR] Dependency installation failed. Check your internet connection.
    goto :fail
)
echo [OK]    All dependencies installed.

echo.
echo  --------------------------------------------------------------
echo [INFO]  Starting demo analysis ...
echo  --------------------------------------------------------------
echo.

REM ── Run the demo ───────────────────────────────────────────────────────────
cd /d "!SCRIPT_DIR!"
python main.py --demo --export
if !errorlevel! neq 0 (
    echo [ERROR] Demo run failed. See error output above.
    goto :fail
)

echo.
echo  --------------------------------------------------------------
echo  [OK]  Demo completed successfully.
echo.
echo   Review the generated outputs in .\output\:
echo     - traffic_summary.csv
echo     - protocol_distribution.png
echo     - top_endpoints.png
echo     - report.md
echo.
echo   To explore further, try:
echo     python main.py --mode offline --pcap sample_data\demo.pcap --export
echo     python main.py --help
echo  --------------------------------------------------------------
echo.
goto :end

:fail
echo.
echo  [ERROR] The demo did not complete. Please review the messages above.
echo.

:end
endlocal
pause
