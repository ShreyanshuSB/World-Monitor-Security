@echo off
REM ==============================================================================
REM Smart India Hackathon 2026 - SIH26163 (NTRO)
REM Security Assessment Platform for World Monitor
REM Windows Startup Script (Batch)
REM ==============================================================================

echo ==========================================================
echo Starting World Monitor Security Assessment Platform (SIH26163)
echo Environment: Controlled Lab Target (Localhost Only)
echo ==========================================================

set "PYTHONPATH=%~dp0;%PYTHONPATH%"
set "PATH=C:\Program Files\nodejs;%PATH%"

echo [1/4] Initializing and Seeding World Monitor Lab Target Database...
python -m lab.seed

echo [2/4] Launching World Monitor Lab Target (Port 8001)...
start "World Monitor Lab (:8001)" /B python -m uvicorn lab.app:app --host 127.0.0.1 --port 8001

echo [3/4] Launching Security Assessment Engine API (Port 8000)...
start "Assessment API (:8000)" /B python -m uvicorn api.main:app --host 127.0.0.1 --port 8000

echo [4/4] Launching Security Dashboard (Port 5173)...
cd /d "%~dp0dashboard"
start "Security Console (:5173)" cmd /c "npm run dev -- --host 127.0.0.1 --port 5173"

echo ==========================================================
echo All services running:
echo - Lab Target:        http://127.0.0.1:8001
echo - Engine API & Docs: http://127.0.0.1:8000/docs
echo - Security Console:  http://127.0.0.1:5173
echo ==========================================================
pause
