#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_PATH" ]]; do
    LINK_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
    SCRIPT_PATH="$(readlink "$SCRIPT_PATH")"
    [[ "$SCRIPT_PATH" != /* ]] && SCRIPT_PATH="$LINK_DIR/$SCRIPT_PATH"
done

REPO_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
INSTALL_DIR="${1:-$HOME/.local/bin}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<EOF
Usage:
  install.sh [install-dir]

Description:
  Create symlinks for train and ELF_Tracker in the selected directory.

Arguments:
  [install-dir]          Install location for the symlinks.
                         Default: $HOME/.local/bin

Examples:
  ./install.sh
  ./install.sh /tmp/elf-tracker-bin
EOF
    exit 0
fi

mkdir -p "$INSTALL_DIR"

ln -sfn "$REPO_DIR/train" "$INSTALL_DIR/train"
ln -sfn "$REPO_DIR/ELF_Tracker" "$INSTALL_DIR/ELF_Tracker"

cat <<EOF
[install] linked:
  $INSTALL_DIR/train -> $REPO_DIR/train
  $INSTALL_DIR/ELF_Tracker -> $REPO_DIR/ELF_Tracker

If '$INSTALL_DIR' is not in PATH, add:
  export PATH="$INSTALL_DIR:\$PATH"
EOF
