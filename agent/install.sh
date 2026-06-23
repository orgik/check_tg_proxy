#!/bin/bash
set -e

MASTER=""
TOKEN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --master) MASTER="$2"; shift 2;;
        --token) TOKEN="$2"; shift 2;;
        *) shift;;
    esac
done

if [ -z "$MASTER" ] || [ -z "$TOKEN" ]; then
    echo "Usage: bash install.sh --master http://SERVER --token TOKEN"
    exit 1
fi

INSTALL_DIR="/opt/tg-agent"

echo "=== TG Proxy Checker Agent Installer ==="
echo "Master: $MASTER"
echo "Install dir: $INSTALL_DIR"
echo ""

# Install python and dependencies
echo "[1/5] Installing Python dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv curl

# Create dir
echo "[2/5] Creating $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Download agent
echo "[3/6] Downloading agent..."
curl -sL "$MASTER/static/agent/agent.py" -o "$INSTALL_DIR/agent.py"

# Download client_hello files
echo "[4/6] Downloading TLS fingerprint data..."
mkdir -p "$INSTALL_DIR/client_hello"
for name in chrome_148_0_7778_179 curl linux_firefox_140_11_0esr safari_26_5_11_4; do
    curl -sL "$MASTER/static/agent/client_hello/$name" -o "$INSTALL_DIR/client_hello/$name" 2>/dev/null || true
done

# Install deps
echo "[5/6] Installing dependencies..."
if python3 -m venv "$INSTALL_DIR/venv" 2>/dev/null; then
    "$INSTALL_DIR/venv/bin/pip" install -q websockets requests cryptography scapy
    PYTHON="$INSTALL_DIR/venv/bin/python3"
else
    pip3 install -q websockets requests cryptography scapy 2>/dev/null || \
        python3 -m pip install -q websockets requests cryptography scapy
    PYTHON="$(which python3)"
fi

# Create systemd service
echo "[6/6] Creating systemd service..."
cat > /etc/systemd/system/tg-agent.service << EOF
[Unit]
Description=TG Proxy Checker Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/agent.py --master $MASTER --token $TOKEN
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tg-agent
systemctl restart tg-agent

echo ""
echo "=== Done! ==="
echo "Status:  systemctl status tg-agent"
echo "Logs:    journalctl -u tg-agent -f"
echo "Stop:    systemctl stop tg-agent"
echo "Remove:  systemctl disable tg-agent && rm -rf $INSTALL_DIR /etc/systemd/system/tg-agent.service"
