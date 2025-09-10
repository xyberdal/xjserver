#!/bin/bash
set -e

REPO="https://github.com/xyberdal/xjserver.git"
WORKDIR="/opt/xjserver"
VERSION_FILE="/opt/.xj_last_version"

# Clone or update repo
if [ ! -d "$WORKDIR/.git" ]; then
    git clone $REPO $WORKDIR
fi

cd $WORKDIR
git fetch --all
git reset --hard origin/main

# Get current commit hash
CURRENT_VERSION=$(git rev-parse HEAD)

# Check last version
if [ -f "$VERSION_FILE" ]; then
    LAST_VERSION=$(cat $VERSION_FILE)
else
    LAST_VERSION=""
fi

# If version unchanged, exit quietly
if [ "$CURRENT_VERSION" = "$LAST_VERSION" ]; then
    echo "No update needed (version $CURRENT_VERSION)"
    exit 0
fi

echo "New version detected: $CURRENT_VERSION (was $LAST_VERSION)"

# Save current version
echo "$CURRENT_VERSION" | sudo tee $VERSION_FILE > /dev/null

# Ensure target dirs exist
sudo mkdir -p /opt/xjserver
sudo mkdir -p /etc/systemd/system

# Copy updated systemd files
sudo cp -f $WORKDIR/systemd/* /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Restart & enable all services from systemd folder
for service in $WORKDIR/systemd/*.service; do
    svcname=$(basename "$service")
    sudo systemctl enable "$svcname"
    sudo systemctl restart "$svcname"
done

# Reboot system after update
echo "Rebooting system to apply changes..."
sudo reboot
