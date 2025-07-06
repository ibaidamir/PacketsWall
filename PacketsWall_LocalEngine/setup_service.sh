#!/bin/bash

# PacketsWall DDoS Detection and Prevention System Service Setup
# This script sets up the PacketsWall system as a systemd service

echo "Setting up PacketsWall as a system service..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Create service directory
INSTALL_DIR="/opt/packetswall"
echo "Creating installation directory at $INSTALL_DIR..."
mkdir -p $INSTALL_DIR

# Copy files to installation directory
echo "Copying files to installation directory..."
cp -r /home/ubuntu/project/ddos_detection $INSTALL_DIR/
cp -r /home/ubuntu/project/documentation.md $INSTALL_DIR/
cp -r /home/ubuntu/project/key_concepts.md $INSTALL_DIR/

# Create systemd service file
echo "Creating systemd service file..."
cat > /etc/systemd/system/packetswall.service << EOF
[Unit]
Description=PacketsWall DDoS Detection and Prevention System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PYTHONPATH=$INSTALL_DIR"
ExecStart=/usr/bin/python3 -m ddos_detection.main -i eth0
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Enable service to start at boot
echo "Enabling service to start at boot..."
systemctl enable packetswall.service

# Start service
echo "Starting PacketsWall service..."
systemctl start packetswall.service

# Check service status
echo "Service status:"
systemctl status packetswall.service

echo ""
echo "PacketsWall has been installed as a system service!"
echo "The service will start automatically when the system boots."
echo "You can control the service with the following commands:"
echo "  - Start: sudo systemctl start packetswall.service"
echo "  - Stop: sudo systemctl stop packetswall.service"
echo "  - Restart: sudo systemctl restart packetswall.service"
echo "  - Status: sudo systemctl status packetswall.service"
echo ""
echo "To access the dashboard, open a web browser and navigate to: http://localhost:5000"
echo "Installation logs and documentation are available at: $INSTALL_DIR"
