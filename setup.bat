@echo off
REM Run this once to set up the project on Windows.
REM Requires Python 3.10+ already installed and on PATH.

python -m venv venv
call venv\Scripts\activate.bat
pip install -r requirements.txt

echo.
echo Setup complete.
echo Remember: install Npcap from https://npcap.com/ (check "WinPcap API-compatible Mode")
echo before running main.py, and run your terminal as Administrator.
