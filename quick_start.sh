#!/bin/bash

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   Telegram XSS Scanner - Quick Start                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
mkdir -p {exploits,reports,payloads}

echo ""
echo "[+] Setup complete!"
echo ""
echo "Available tools:"
echo "  1. Master Control Panel:     python master_control.py"
echo "  2. Integrated Framework:     python integrated_exploit_framework.py"
echo "  3. DOM XSS Scanner:          python dom_xss_scanner.py"
echo "  4. Attack Tools Suite:       python attack_tools.py"
echo "  5. Exploit Generator:        python exploit_generator.py"
echo ""
echo "Quick start:"
echo "  python master_control.py"
echo ""

# Make scripts executable
chmod +x *.py

# Launch master control
read -p "Launch Master Control Panel now? (y/n): " launch

if [ "$launch" = "y" ] || [ "$launch" = "Y" ]; then
    python master_control.py
fi
