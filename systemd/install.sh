#!/bin/bash

# Ensure the script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo."
  exit 1
fi

# Get the absolute path of the repository root directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Get the invoking user and group
RUN_AS_USER="${SUDO_USER:-$USER}"
RUN_AS_GROUP="$(id -gn "$RUN_AS_USER")"
PYTHON_PATH="$(which python3)"

if [ -z "$PYTHON_PATH" ]; then
  PYTHON_PATH="/usr/bin/python3"
fi

echo "Installing Hashtopolis agent systemd service..."
echo "  User:             $RUN_AS_USER"
echo "  Group:            $RUN_AS_GROUP"
echo "  Working Dir:      $REPO_DIR"
echo "  Python path:      $PYTHON_PATH"

# Generate the service file from template
SERVICE_TEMPLATE="$SCRIPT_DIR/hashtopolis.service"
SERVICE_DEST="/etc/systemd/system/hashtopolis.service"

sed -e "s|%%USER%%|$RUN_AS_USER|g" \
    -e "s|%%GROUP%%|$RUN_AS_GROUP|g" \
    -e "s|%%WORKDIR%%|$REPO_DIR|g" \
    -e "s|%%PYTHON%%|$PYTHON_PATH|g" \
    "$SERVICE_TEMPLATE" > "$SERVICE_DEST"

# Reload systemd and enable/start the service
systemctl daemon-reload
systemctl enable hashtopolis.service
systemctl restart hashtopolis.service

echo "Service installed and started successfully."

if [ ! -f "$REPO_DIR/config.json" ]; then
    echo "Warning: Initial configuration (config.json) not found at $REPO_DIR/config.json."
    echo "Please configure the agent before starting or check status with: systemctl status hashtopolis"
fi
