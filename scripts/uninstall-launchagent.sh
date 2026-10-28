#!/bin/bash
# Stops the server and removes its LaunchAgent. Logs, the passphrase and saved
# sign-ins in ~/.imessage-mcp are left in place.
set -euo pipefail

LABEL="local.imessage-mcp"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
echo "Removed $LABEL"
