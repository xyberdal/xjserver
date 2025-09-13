#!/bin/bash
set -e

REPO="https://github.com/xyberdal/xjserver.git"
WORKDIR="/opt/xjserver_repo"   # temporary repo bag
TARGET_XJSERVER="/opt/xjserver"
TARGET_XJSERVERSCRIPT="/opt/xjserverscript"
VERSION_FILE="/opt/.xj_last_version"

# --- Wait for network to be ready ---
echo "Checking network availability..."
until ping -c1 github.com &>/dev/null; do
    echo "Waiting for network..."
    sleep 5
done
echo "Network is ready."

# Get latest remote commit hash (without cloning everything)
LATEST_VERSION=$(git ls-remote "$REPO" refs/heads/main | awk '{print $1}')

# Read last deployed version
if [ -f "$VERSION_FILE" ]; then
    LAST_VERSION=$(cat "$VERSION_FILE")
else
    LAST_VERSION=""
fi

# If version unchanged, exit quietly
if [ "$LATEST_VERSION" = "$LAST_VERSION" ]; then
    echo "No update needed (version $LATEST_VERSION)"
    exit 0
fi

echo "New version detected: $LATEST_VERSION (was $LAST_VERSION)"

# Fresh clone into temporary workdir (shallow, no history)
rm -rf "$WORKDIR"
git clone --depth=1 "$REPO" "$WORKDIR"
cd "$WORKDIR"

# ---- Systemd units ----
if [ -d "$WORKDIR/systemd" ]; then
    echo "Updating systemd units..."
    sudo cp -f "$WORKDIR/systemd/"* /etc/systemd/system/
    sudo systemctl daemon-reload
    for service in "$WORKDIR/systemd/"*.service; do
        [ -e "$service" ] || continue
        svcname=$(basename "$service")
        sudo systemctl enable "$svcname"
        sudo systemctl restart "$svcname"
    done
fi

# ---- xjserver files (app code only, won't touch db/logs/backups) ----
if [ -d "$WORKDIR/xjserver" ]; then
    echo "Updating /opt/xjserver..."
    sudo mkdir -p "$TARGET_XJSERVER"
    sudo cp -rf "$WORKDIR/xjserver/"* "$TARGET_XJSERVER/"
fi

# ---- xjserverscript files ----
if [ -d "$WORKDIR/xjserverscript" ]; then
    echo "Updating /opt/xjserverscript..."
    sudo mkdir -p "$TARGET_XJSERVERSCRIPT"
    sudo cp -rf "$WORKDIR/xjserverscript/"* "$TARGET_XJSERVERSCRIPT/"
    sudo chmod +x "$TARGET_XJSERVERSCRIPT/"*
fi

# Ensure main autosetup script is executable (if present)
if [ -f "$TARGET_XJSERVERSCRIPT/xj-autosetup.sh" ]; then
    sudo chmod +x "$TARGET_XJSERVERSCRIPT/xj-autosetup.sh"
fi

# Save current version
echo "$LATEST_VERSION" | sudo tee "$VERSION_FILE" > /dev/null

# Clean repo bag
echo "Cleaning up repo bag..."
rm -rf "$WORKDIR"

# Optional reboot
echo "Rebooting system to apply changes..."
sudo reboot
