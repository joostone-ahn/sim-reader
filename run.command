#!/bin/bash
# SIM Card Reader - One-click launcher
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/.venv"
PORT=8082
URL="http://127.0.0.1:$PORT"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python3 not found. Please install Python 3.10+"
    exit 1
fi

# Create venv if needed
if [ ! -d "$VENV" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv "$VENV"
fi

# Activate and install dependencies
source "$VENV/bin/activate"
if [ ! -f "$VENV/.deps_installed" ] || [ "$DIR/requirements.txt" -nt "$VENV/.deps_installed" ]; then
    echo "📦 Installing dependencies..."
    pip install -q -r "$DIR/requirements.txt"
    pip install -q -e "$DIR/pysim"
    touch "$VENV/.deps_installed"
fi

# Open browser after short delay
(sleep 2 && open "$URL" 2>/dev/null || xdg-open "$URL" 2>/dev/null || echo "🌐 Open $URL in your browser") &

# Start server
echo "🚀 Starting SIM Card Reader at $URL"
python "$DIR/src/app.py"
