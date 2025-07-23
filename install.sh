#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting Tunnel Manager Installation..."


# colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color


# Determine the script's own directory
APP_SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Using application source directory: $APP_SOURCE_DIR"


# --- Configuration ---
APP_DIR="/opt/my-tunnel-manager"

# Check if the application is already installed
IS_INSTALLED="false"
if [ -d "$APP_DIR" ] && [ -f "$APP_DIR/instance/users.db" ]; then
    IS_INSTALLED="true"
    echo "Tunnel Manager appears to be already installed."
fi

PYTHON_EXEC="python3"
PIP_EXEC="pip3"
RATHOLE_VERSION="v0.5.0"
ARCH=$(uname -m)
RATHOLE_ARCH=""
if [ "$ARCH" = "x86_64" ]; then
    RATHOLE_ARCH="x86_64-unknown-linux-gnu"
elif [ "$ARCH" = "aarch64" ]; then
    RATHOLE_ARCH="aarch64-unknown-linux-gnu"
else
    echo "Unsupported architecture: $ARCH for rathole auto-download."
    exit 1
fi
RATHOLE_DOWNLOAD_URL="https://github.com/rathole-org/rathole/releases/download/${RATHOLE_VERSION}/rathole-${RATHOLE_ARCH}.zip"


# --- 1. System Dependencies ---
echo "Updating package lists..."
sudo apt-get update -y

echo "Installing system dependencies (python3, pip3, python3-venv, curl, unzip, git, iptables-persistent, certbot)..."
sudo apt-get install -y python3 python3-pip python3-venv curl unzip git iptables-persistent certbot wireguard-tools

# --- 2. Download and Install Rathole ---
echo "Downloading Rathole ${RATHOLE_VERSION} for ${RATHOLE_ARCH}..."
cd /tmp
curl -sSL -o rathole.zip "$RATHOLE_DOWNLOAD_URL"
unzip -o rathole.zip
if [ -f "rathole-${RATHOLE_ARCH}/rathole" ]; then
    sudo mv "rathole-${RATHOLE_ARCH}/rathole" /usr/local/bin/rathole
elif [ -f "rathole" ]; then
    sudo mv rathole /usr/local/bin/rathole
else
    echo "Could not find 'rathole' binary in the downloaded zip."
    exit 1
fi
sudo chmod +x /usr/local/bin/rathole
echo "Rathole installed to /usr/local/bin/rathole"
rathole --version

# --- 3. Application Setup ---
echo "Creating application directory: $APP_DIR"
sudo mkdir -p "$APP_DIR/instance/rathole_configs"

echo "Copying application files to $APP_DIR..."
sudo cp -r "$APP_SOURCE_DIR/app.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/database.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/rathole_manager.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/iptables_manager.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/traffic_manager.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/health_checker.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/ssl_manager.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/reset_password.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/reset_domain.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/cli.py" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/requirements.txt" "$APP_DIR/"
sudo cp -r "$APP_SOURCE_DIR/templates" "$APP_DIR/"

echo "Setting permissions for python scripts..."
sudo chmod +x $APP_DIR/*.py

cd "$APP_DIR"

# --- 4. Python Virtual Environment and Dependencies ---
echo "Creating Python virtual environment..."
sudo $PYTHON_EXEC -m venv .venv
echo "Installing Python dependencies..."
sudo .venv/bin/pip install -r requirements.txt

# --- 5. Initial Database and User Setup ---
if [ "$IS_INSTALLED" = "true" ]; then
    echo ""
    read -p "Tunnel Manager is already installed. Do you want to reset the admin password? (y/N): " RESET_PASSWORD_CHOICE
    if [[ "$RESET_PASSWORD_CHOICE" =~ ^[Yy]$ ]]; then
        echo "Resetting admin password..."
        ADMIN_USERNAME="admin"
        ADMIN_PASSWORD=$(openssl rand -base64 12)
        sudo .venv/bin/python -c "
import database
database.init_db()
database.add_or_update_user('$ADMIN_USERNAME', '$ADMIN_PASSWORD')
"
        echo -e "${GREEN}Admin Username: $ADMIN_USERNAME${NC}"
        echo -e "${GREEN}New Admin Password: $ADMIN_PASSWORD${NC} ${RED}(SAVE THIS! It will not be shown again.)${NC}"
    else
        echo "Skipping password reset."
    fi
else
    echo "Initializing database and creating admin user..."
    ADMIN_PASSWORD=$(openssl rand -base64 12)
    ADMIN_USERNAME="admin"
    sudo .venv/bin/python -c "
import database
database.init_db()
database.add_or_update_user('$ADMIN_USERNAME', '$ADMIN_PASSWORD')
"
fi

# --- 6. iptables and Default Config Setup ---
echo "Setting up iptables for traffic monitoring..."
sudo .venv/bin/python -c "import iptables_manager; iptables_manager.setup_iptables_chain()"

echo "Saving iptables rules..."
sudo netfilter-persistent save

echo "Creating CLI command..."
sudo chmod +x $APP_DIR/cli.py
sudo ln -sf "$APP_DIR/cli.py" /usr/local/bin/tunnel-manager-web

# --- 7. Systemd Service Creation ---
echo "Creating systemd service for the web panel..."
sudo tee /etc/systemd/system/tunnel-manager-web.service > /dev/null <<EOF
[Unit]
Description=Rathole Tunnel Manager Web UI
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python app.py
Restart=always
Environment="FLASK_SECRET_KEY=$(openssl rand -hex 16)"

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd daemon and enabling the service..."
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-manager-web.service
echo "Systemd service 'tunnel-manager-web.service' created and started."


# --- Final Instructions ---
echo ""
echo "--------------------------------------------------------------------"
echo "Installation Complete!"
echo "--------------------------------------------------------------------"
echo ""
SERVER_IP_FOR_URL=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP_FOR_URL" ]; then
    SERVER_IP_FOR_URL="<YOUR_SERVER_IP>"
fi
DEFAULT_RATHOLE_PORT="2333"

echo "${GREEN}Web Panel URL: http://${SERVER_IP_FOR_URL}:5001"
if [ "$IS_INSTALLED" = "false" ]; then
    echo -e "${GREEN}Admin Username: $ADMIN_USERNAME${NC}"
    echo -e "${GREEN}Admin Password: $ADMIN_PASSWORD${NC}  ${RED}(SAVE THIS! It will not be shown again.)${NC}"
fi
echo ""
echo "Important Next Steps:"
echo "1. Configure your firewall to allow traffic on required ports."
echo "   Example for ufw: sudo ufw allow 5001/tcp && sudo ufw allow ${DEFAULT_RATHOLE_PORT}/tcp"
echo ""
echo "2. The application is now running as a systemd service. Manage it with:"
echo "   sudo systemctl status tunnel-manager-web.service"
echo ""
echo "Rathole version used: $RATHOLE_VERSION"
echo "Installation script finished."

# Clean up downloaded files
rm -f /tmp/rathole.zip
rm -rf /tmp/rathole-${RATHOLE_ARCH}

exit 0
