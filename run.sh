#!/usr/bin/env bash
# ==============================================================================
# Smart India Hackathon 2026 - SIH26163 (NTRO)
# Security Assessment Platform for World Monitor
# Unified Startup Script
# ==============================================================================

set -e

echo "=========================================================="
echo " Starting World Monitor Security Assessment Platform (SIH26163)"
echo " Environment: Controlled Lab Target (Localhost Only)"
echo "=========================================================="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$ROOT_DIR:$PYTHONPATH"

# 1. Initialize & Seed Target Lab DB
echo "[1/4] Initializing and Seeding World Monitor Lab Target Database..."
python3 -m lab.seed

# 2. Start Lab Target Server on Port 8001
echo "[2/4] Launching World Monitor Lab Target (Port 8001)..."
python3 -m uvicorn lab.app:app --host 127.0.0.1 --port 8001 &
LAB_PID=$!

# 3. Start Assessment Engine API on Port 8000
echo "[3/4] Launching Security Assessment Engine API (Port 8000)..."
python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000 &
API_PID=$!

# 4. Start React Frontend Dashboard on Port 5173
echo "[4/4] Launching Security Dashboard (Port 5173)..."
cd "$ROOT_DIR/dashboard"
npm run dev -- --host 127.0.0.1 --port 5173 &
FRONTEND_PID=$!

echo "=========================================================="
echo " All services running successfully!"
echo " - Lab Target:        http://127.0.0.1:8001"
echo " - Engine API & Docs: http://127.0.0.1:8000/docs"
echo " - Security Console:  http://127.0.0.1:5173"
echo "=========================================================="

trap "kill $LAB_PID $API_PID $FRONTEND_PID 2>/dev/null" EXIT
wait
