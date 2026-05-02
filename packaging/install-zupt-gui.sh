#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Zupt + Zupt GUI all-in-one installer for Linux
# Detects your distro, installs all dependencies, then installs
# zupt and zupt-gui. Run as root or with sudo.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZUPT_CLI_DEB="$SCRIPT_DIR/zupt_2.2.3_amd64.deb"
ZUPT_GUI_DEB="$SCRIPT_DIR/zupt-gui_1.1.1_all.deb"

print_step() { echo ""; echo "═══ $* ═══"; }
print_err()  { echo "ERROR: $*" >&2; exit 1; }

# Must be root
if [ "$EUID" -ne 0 ]; then
    print_err "Run with sudo: sudo bash $0"
fi

# Detect distro
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    DISTRO_LIKE="${ID_LIKE:-}"
else
    print_err "Cannot detect distribution (no /etc/os-release)"
fi

print_step "Detected: $PRETTY_NAME"

# 1. Install Python 3 + Qt6 binding
print_step "Step 1/3: Installing Python 3 and Qt6 binding"
case "$DISTRO" in
    debian|ubuntu|linuxmint|pop)
        apt-get update
        apt-get install -y python3 python3-pyqt6 || \
            apt-get install -y python3 python3-pyside6
        ;;
    fedora|rhel|centos|rocky|almalinux)
        if command -v dnf >/dev/null; then
            dnf install -y python3 python3-pyqt6 || dnf install -y python3 python3-pyside6
        else
            yum install -y python3 python3-pyqt6 || yum install -y python3 python3-pyside6
        fi
        ;;
    opensuse*|suse)
        zypper install -y python3 python3-pyqt6 || zypper install -y python3 python3-PyQt6 \
            || zypper install -y python3 python3-pyside6
        ;;
    arch|manjaro|endeavouros)
        pacman -S --noconfirm python python-pyqt6 || pacman -S --noconfirm python python-pyside6
        ;;
    alpine)
        apk add python3 py3-pyqt6 || apk add python3 py3-pyside6
        ;;
    *)
        # Fallback: try pip
        echo "Unknown distribution '$DISTRO'. Trying pip fallback..."
        if command -v pip3 >/dev/null; then
            pip3 install --break-system-packages PySide6 || pip3 install PySide6
        else
            print_err "No pip3 available. Install python3-pyqt6 manually for your distro."
        fi
        ;;
esac

# Verify Qt6 binding works
if ! python3 -c 'import PyQt6.QtWidgets' 2>/dev/null \
   && ! python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then
    print_err "Failed to install Qt6 Python binding. Install manually with your package manager."
fi
echo "✓ Python 3 + Qt6 binding installed"

# 2. Install zupt CLI
print_step "Step 2/3: Installing zupt CLI 2.2.3"
case "$DISTRO" in
    debian|ubuntu|linuxmint|pop)
        if [ ! -f "$ZUPT_CLI_DEB" ]; then
            print_err "Cannot find $ZUPT_CLI_DEB next to this script"
        fi
        # Force-replace any older zupt
        dpkg -i "$ZUPT_CLI_DEB" || apt-get -f install -y
        ;;
    fedora|rhel|centos|rocky|almalinux|opensuse*|suse)
        ZUPT_CLI_RPM="$SCRIPT_DIR/zupt-2.2.3-1.x86_64.rpm"
        if [ -f "$ZUPT_CLI_RPM" ]; then
            rpm -Uvh --force "$ZUPT_CLI_RPM"
        else
            print_err "RPM build not provided. Build from source tarball or install via SRPM."
        fi
        ;;
    *)
        # Fallback: tarball install
        ZUPT_CLI_TAR="$SCRIPT_DIR/zupt-2.2.3-linux-x86_64.tar.gz"
        if [ -f "$ZUPT_CLI_TAR" ]; then
            tar -xzf "$ZUPT_CLI_TAR" -C /opt/
            ln -sf /opt/zupt-2.2.3-linux-x86_64/zupt /usr/local/bin/zupt
        else
            print_err "No suitable installer for $DISTRO"
        fi
        ;;
esac
echo "✓ zupt CLI installed"

# 3. Install zupt-gui
print_step "Step 3/3: Installing zupt-gui"
case "$DISTRO" in
    debian|ubuntu|linuxmint|pop)
        dpkg -i "$ZUPT_GUI_DEB" || apt-get -f install -y
        ;;
    fedora|rhel|centos|rocky|almalinux|opensuse*|suse)
        ZUPT_GUI_RPM="$SCRIPT_DIR/zupt-gui-1.1.1-1.noarch.rpm"
        if [ -f "$ZUPT_GUI_RPM" ]; then
            rpm -Uvh --force "$ZUPT_GUI_RPM"
        fi
        ;;
    *)
        # Manual fallback
        mkdir -p /opt/zupt-gui /usr/local/bin
        cp "$SCRIPT_DIR/zupt_gui.py" /opt/zupt-gui/ 2>/dev/null || true
        cat > /usr/local/bin/zupt-gui <<'WRAP'
#!/bin/sh
exec python3 /opt/zupt-gui/zupt_gui.py "$@"
WRAP
        chmod +x /usr/local/bin/zupt-gui
        ;;
esac
echo "✓ zupt-gui installed"

print_step "Installation complete"
echo ""
echo "Run:"
echo "  zupt help        # CLI help"
echo "  zupt-gui         # Graphical interface"
echo ""
echo "If you encounter issues, check that your zupt version is correct:"
echo "  zupt version     # should show 2.2.3"
