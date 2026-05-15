#!/bin/bash
# start.sh – Quick-start script for PhishGuard on Linux / macOS
# Usage: chmod +x start.sh && ./start.sh

set -e   # Exit immediately on any error

echo "=================================================="
echo " 🛡  PhishGuard – Phishing Email Detection System"
echo "=================================================="

# ── Check Python version ──
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python: $PYTHON_VERSION"

# ── Check if .env exists ──
if [ ! -f ".env" ]; then
    echo "⚠  No .env file found. Copying from .env.example..."
    cp .env.example .env
    echo "   → Edit .env and set DB_PASSWORD before first run."
fi

# ── Install dependencies if venv not active ──
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠  No virtual environment active."
    echo "   Run: python3 -m venv venv && source venv/bin/activate"
    echo "   Then: pip install -r requirements.txt --break-system-packages"
    echo "   Re-run this script after activating venv."
fi

# ── Create required directories ──
mkdir -p exports logs

# ── Start the Flask development server ──
echo ""
echo "▶ Starting PhishGuard on http://localhost:5000"
echo "  Press Ctrl+C to stop."
echo ""
python3 app.py
