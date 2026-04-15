#!/bin/bash
# SIM Card Reader - One-click launcher
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/.venv"
PORT=8082
URL="http://127.0.0.1:$PORT"
PYTHON="$VENV/bin/python"
PIP="$VENV/bin/pip"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python3 not found. Please install Python 3.10+"
    exit 1
fi

# Create venv if needed
if [ ! -f "$PYTHON" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv "$VENV"
fi

# Install dependencies: check by importing pySim
if ! "$PYTHON" -c "import pySim" &>/dev/null; then
    echo "📦 Installing dependencies..."
    "$PIP" install -q --disable-pip-version-check -r "$DIR/requirements.txt"
    "$PIP" install -q --disable-pip-version-check -e "$DIR/pysim"
fi

# Open browser after short delay
(sleep 2 && open "$URL" 2>/dev/null || xdg-open "$URL" 2>/dev/null || echo "🌐 Open $URL in your browser") &

# Start server (use venv python directly)
echo "🚀 Starting SIM Card Reader at $URL"
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" "$DIR/src/app.py"
