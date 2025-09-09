#!/bin/bash
# filepath: /opt/xjserversetup/install_xjserver.sh

set -e  # Exit on any error

# Update package list and upgrade
sudo apt-get update -y
sudo apt-get upgrade -y

# Install necessary packages
sudo apt-get install -y python3 python3-pip python3-venv

# Set timezone
sudo timedatectl set-timezone Asia/Manila

# Ensure XJServer directory exists
if [ ! -d /opt/xjserver ]; then
    echo "❌ /opt/xjserver directory does not exist!"
    exit 1
fi

cd /opt/xjserver

# Change ownership of /opt/xjserver to the desired user (replace 'orangepi' if needed)
sudo chown -R orangepi:orangepi /opt/xjserver

# Create a virtual environment if not exists
if [ ! -d venv ]; then
    python3 -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install required Python packages
if [ -f requirements.txt ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "❌ requirements.txt not found!"
    exit 1
fi

# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the XJServer service to start on boot
sudo systemctl enable xjserver.service
sudo systemctl enable xjserverstart.service
sudo systemctl enable xjserverudpip.service
sudo systemctl enable xjserverws.service

# Start the XJServer service
sudo systemctl restart xjserver.service
sudo systemctl restart xjserverstart.service
sudo systemctl restart xjserverudpip.service
sudo systemctl restart xjserverws.service

echo "✅ XJServer installation completed successfully."