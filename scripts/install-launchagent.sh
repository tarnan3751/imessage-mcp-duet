#!/bin/bash
# Installs a LaunchAgent that runs the HTTP server whenever this user is logged in,
# and restarts it if it exits.
#
# Usage: scripts/install-launchagent.sh https://your-mac.your-tailnet.ts.net
#
# Optional environment: IMESSAGE_MCP_PORT (default 3847), IMESSAGE_MCP_RELEASES.
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "This script only works on macOS." >&2
  exit 1
fi

PUBLIC_URL="${1:-}"
if [[ -z "$PUBLIC_URL" ]]; then
  echo "Usage: $0 https://your-mac.your-tailnet.ts.net" >&2
  exit 1
fi
PUBLIC_URL="${PUBLIC_URL%/}"

LABEL="local.imessage-mcp"
PORT="${IMESSAGE_MCP_PORT:-3847}"
RELEASES="${IMESSAGE_MCP_RELEASES:-}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$HOME/Library/Logs/imessage-mcp"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

# Full Disk Access is granted per binary, so resolve symlinks to the real one
NODE_BIN="$(node -p 'require("fs").realpathSync(process.execPath)')"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if (( NODE_MAJOR < 18 || NODE_MAJOR >= 26 )); then
  echo "Node $NODE_MAJOR is not supported. Use Node 24 (see the README)." >&2
  exit 1
fi

if [[ ! -f "${IMESSAGE_MCP_STATE_DIR:-$HOME/.imessage-mcp}/passphrase.json" ]]; then
  echo "No passphrase set yet. Run: node index.js --set-passphrase" >&2
  exit 1
fi

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  printf '%s' "$value"
}

mkdir -p "$LOG_DIR" "$HOME/Library/LaunchAgents"

cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "$NODE_BIN")</string>
    <string>$(xml_escape "$REPO_DIR/index.js")</string>
    <string>--http</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$(xml_escape "$REPO_DIR")</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>IMESSAGE_MCP_PUBLIC_URL</key>
    <string>$(xml_escape "$PUBLIC_URL")</string>
    <key>IMESSAGE_MCP_PORT</key>
    <string>$(xml_escape "$PORT")</string>
    <key>IMESSAGE_MCP_RELEASES</key>
    <string>$(xml_escape "$RELEASES")</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>StandardOutPath</key>
  <string>$(xml_escape "$LOG_DIR/server.log")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "$LOG_DIR/server.log")</string>
</dict>
</plist>
PLIST_EOF

plutil -lint "$PLIST" >/dev/null

DOMAIN="gui/$(id -u)"
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
launchctl enable "$DOMAIN/$LABEL"
launchctl kickstart -k "$DOMAIN/$LABEL"

echo "Installed $PLIST"
echo "Logs: $LOG_DIR/server.log"
echo
echo "Grant Full Disk Access to this exact file:"
echo "  $NODE_BIN"
echo "then restart the server with:"
echo "  launchctl kickstart -k $DOMAIN/$LABEL"
echo
echo "Check it with: curl -s http://127.0.0.1:$PORT/health"
