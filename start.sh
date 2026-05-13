#!/bin/bash

# NetWatch IDS — Quick Start Script

echo "╔════════════════════════════════════════════╗"
echo "║    NetWatch IDS — Quick Start              ║"
echo "║    Network Intrusion Detection System      ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi

echo "✅ Python found"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install -q -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"

# Create logs dir
mkdir -p logs

echo ""
echo "🚀 Starting IDS server in DEMO mode (no root required)..."
echo ""
echo "   🌐 Dashboard: http://localhost:5000"
echo "   📊 API: http://localhost:5000/api"
echo ""
echo "   Attacks will be simulated every 30-40 seconds"
echo "   Watch the dashboard for PORT_SCAN, SYN_FLOOD, ICMP_FLOOD alerts"
echo ""
echo "   Press Ctrl+C to stop"
echo ""

python3 backend/server.py --demo --port 5000