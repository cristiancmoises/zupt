#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Install Zupt GUI + desktop integration
# Run: sudo ./install.sh   (or ./install.sh --user for per-user install)
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
USER_INSTALL=0
[ "$1" = "--user" ] && USER_INSTALL=1

if [ "$USER_INSTALL" -eq 1 ]; then
    BIN="$HOME/.local/bin"
    APPS="$HOME/.local/share/applications"
    NEMO="$HOME/.local/share/nemo/actions"
    MIME="$HOME/.local/share/mime"
    NAUTILUS="$HOME/.local/share/nautilus/scripts"
else
    BIN="/usr/local/bin"
    APPS="/usr/share/applications"
    NEMO="/usr/share/nemo/actions"
    MIME="/usr/share/mime"
    NAUTILUS=""
fi

mkdir -p "$BIN" "$APPS"

# ── Install launcher ──
cat > "$BIN/zupt-gui" << LAUNCHER
#!/bin/bash
DIR="$DIR"
VENV="\$DIR/.venv"
PY="\$VENV/bin/python3"
[ ! -x "\$PY" ] && python3 -m venv "\$VENV" && "\$VENV/bin/pip" install PySide6 -q
exec "\$PY" "\$DIR/src/zupt_gui.py" "\$@"
LAUNCHER
chmod +x "$BIN/zupt-gui"
echo "Installed: $BIN/zupt-gui"

# ── Desktop entry ──
cp "$DIR/packaging/zupt-gui.desktop" "$APPS/"
echo "Installed: $APPS/zupt-gui.desktop"

# ── Nemo actions (Linux Mint / Cinnamon) ──
if [ -d "$(dirname "$NEMO")" ] || [ "$USER_INSTALL" -eq 1 ]; then
    mkdir -p "$NEMO"
    cp "$DIR/packaging/desktop-integration/nemo/"*.nemo_action "$NEMO/" 2>/dev/null && \
        echo "Installed: Nemo right-click actions" || true
fi

# ── Nautilus scripts (GNOME) ──
if [ -n "$NAUTILUS" ]; then
    mkdir -p "$NAUTILUS"
    cat > "$NAUTILUS/Compress with Zupt" << 'NSCRIPT'
#!/bin/bash
zupt-gui --compress $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS
NSCRIPT
    chmod +x "$NAUTILUS/Compress with Zupt"
    echo "Installed: Nautilus script"
fi

# ── MIME type for .zupt files ──
MIME_XML="$MIME/packages/zupt.xml"
if [ ! -f "$MIME_XML" ]; then
    mkdir -p "$(dirname "$MIME_XML")"
    cat > "$MIME_XML" << 'MIMEXML'
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-zupt">
    <comment>Zupt Archive</comment>
    <glob pattern="*.zupt"/>
    <icon name="package-x-generic"/>
  </mime-type>
</mime-info>
MIMEXML
    if command -v update-mime-database >/dev/null; then
        update-mime-database "$MIME" 2>/dev/null
    fi
    echo "Registered: .zupt MIME type"
fi

# ── Associate .zupt files with zupt-gui ──
if command -v xdg-mime >/dev/null; then
    xdg-mime default zupt-gui.desktop application/x-zupt 2>/dev/null
    echo "Associated: .zupt files open with Zupt GUI"
fi

echo ""
echo "Done. Right-click any file in your file manager to see Zupt options."
echo "Double-click any .zupt file to open it in Zupt GUI."
