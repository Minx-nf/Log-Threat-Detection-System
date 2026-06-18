@echo off
:: 1. Navigate to the project folder (Update this path to your actual folder location!)
cd /d "D:\Log-Threat-Detection-System Improved\backend"

:: 2. Activate the virtual environment
call venv\Scripts\activate

:: 3. Start the Flask Backend (The Brain) in a new window
start "SOC Backend" python app.py

:: 4. Start the Log Collector (The Eyes) in a new window
start "SOC Collector" python windows_logs_collector.py

echo Security Analytics Center is starting...
echo Brain and Eyes are now active. Close the terminal windows to shut down.
pause