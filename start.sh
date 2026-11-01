#!/usr/bin/env bash
# Social Enforcement Management System - Linux/macOS launcher.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}
if [ ! -d ".venv" ]; then
  echo "[1/4] Creating virtual environment"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/4] Installing dependencies"
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt

if [ ! -f ".env" ]; then
  echo "[3/4] Creating .env from .env.example"
  cp .env.example .env
  echo "      Set SECRET_KEY and ADMIN_PASSWORD in .env before real use."
fi

echo "[4/4] Starting on http://127.0.0.1:8000"
exec python -m uvicorn app:app --host 127.0.0.1 --port 8000
