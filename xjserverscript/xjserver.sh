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

# Ensure /opt/xjserver exists
if [ ! -d /opt/xjserver ]; then
    echo "⚠️  /opt/xjserver does not exist — creating it..."
    sudo mkdir -p /opt/xjserver
fi

cd /opt/xjserver

# Change ownership of /opt/xjserver to the current user
user=$(logname)
sudo chown -R "$user":"$user" /opt/xjserver

# Create a virtual environment if not exists
if [ ! -d venv ]; then
    python3 -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install required Python packages
pip install --upgrade pip
if [ -f requirements.txt ]; then
    echo "📦 Installing from requirements.txt..."
    pip install -r requirements.txt
else
    echo "⚠️ requirements.txt not found! Installing fallback packages..."
    pip install \
        "Flask>=2.2" \
        websockets \
        psutil \
        Werkzeug \
        requests \
        Jinja2 \
        python-dotenv \
        "cryptography>=3.4.8" \
        glob2 \
        scapy \
        gunicorn
fi

# Ensure /opt/xjserverscript exists
if [ ! -d /opt/xjserverscript ]; then
    echo "⚠️  /opt/xjserverscript does not exist — creating it..."
    sudo mkdir -p /opt/xjserverscript
fi

# Ensure xj-autosetup.sh is executable
if [ -f /opt/xjserverscript/xj-autosetup.sh ]; then
    sudo chmod +x /opt/xjserverscript/xj-autosetup.sh
    echo "✅ Made xj-autosetup.sh executable."
else
    echo "⚠️  /opt/xjserverscript/xj-autosetup.sh not found (skipping chmod)."
fi

# Enable and restart autosetup service
sudo systemctl enable "xj-autosetup.service"
sudo systemctl restart "xj-autosetup.service"

echo "✅ XJServer installation completed successfully."
