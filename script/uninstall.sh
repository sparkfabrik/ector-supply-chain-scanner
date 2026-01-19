#!/usr/bin/env bash
set -e

# Ector uninstaller script

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="ector"

echo "Uninstalling ector..."

# Check if binary exists
if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
  rm "$INSTALL_DIR/$BINARY_NAME"
  echo "Removed $INSTALL_DIR/$BINARY_NAME"
else
  echo "Binary not found at $INSTALL_DIR/$BINARY_NAME"
fi

# Check if ector is still in PATH
if command -v ector &>/dev/null; then
  REMAINING_PATH=$(which ector)
  echo ""
  echo "ector still found at: $REMAINING_PATH"
  echo "You may want to remove it manually"
else
  echo ""
  echo "ector successfully uninstalled"
fi
