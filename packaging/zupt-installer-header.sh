#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# ╔════════════════════════════════════════════════════════════════════╗
# ║   ZUPT 2.2.2 + ZUPT-GUI 1.1.1 — UNIVERSAL LINUX INSTALLER          ║
# ║                                                                    ║
# ║   One script, all distributions. Self-extracting. No internet      ║
# ║   needed for the package install (only for Qt6 dependency).        ║
# ║                                                                    ║
# ║   Usage:   sudo bash zupt-installer.sh                             ║
# ║   Or:      sudo bash zupt-installer.sh --gui-only                  ║
# ║   Or:      sudo bash zupt-installer.sh --cli-only                  ║
# ║   Or:      sudo bash zupt-installer.sh --appimage                  ║
# ║   Or:      sudo bash zupt-installer.sh --uninstall                 ║
# ╚════════════════════════════════════════════════════════════════════╝
set -e

VERSION="2.2.2"
GUI_VERSION="1.1.1"
EXTRACT_DIR=""

cleanup() {
    [ -n "$EXTRACT_DIR" ] && [ -d "$EXTRACT_DIR" ] && rm -rf "$EXTRACT_DIR"
}
trap cleanup EXIT

# ── Color output (if terminal supports) ─────────────────────────────
if [ -t 1 ]; then
    BOLD='\033[1m'; CYAN='\033[36m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
else
    BOLD=''; CYAN=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

step()  { echo -e "${CYAN}${BOLD}═══ $* ═══${RESET}"; }
ok()    { echo -e "${GREEN}✓${RESET} $*"; }
warn()  { echo -e "${YELLOW}⚠${RESET} $*"; }
err()   { echo -e "${RED}✗${RESET} $*" >&2; }
die()   { err "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────
MODE="full"
case "${1:-}" in
    --cli-only)   MODE="cli" ;;
    --gui-only)   MODE="gui" ;;
    --appimage)   MODE="appimage" ;;
    --uninstall)  MODE="uninstall" ;;
    --help|-h)
        sed -n '2,15p' "$0" | sed 's/^# //'
        exit 0 ;;
    "") MODE="full" ;;
    *)  die "Unknown option: $1. Use --help for options." ;;
esac

# ── Root check (except for AppImage) ────────────────────────────────
if [ "$MODE" != "appimage" ] && [ "$EUID" -ne 0 ]; then
    die "Run with sudo: sudo bash $0 ${1:-}"
fi

# ── Distro detection ────────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        # Use subshell to prevent /etc/os-release VERSION from clobbering ours
        DISTRO=$(. /etc/os-release; echo "${ID:-unknown}")
        DISTRO_LIKE=$(. /etc/os-release; echo "${ID_LIKE:-}")
        DISTRO_NAME=$(. /etc/os-release; echo "${PRETTY_NAME:-$DISTRO}")
    else
        DISTRO="unknown"; DISTRO_LIKE=""; DISTRO_NAME="Unknown Linux"
    fi
}
detect_distro

# Categorize
DEB_BASED=0; RPM_BASED=0; ARCH_BASED=0; ALPINE=0
case "$DISTRO" in
    debian|ubuntu|linuxmint|pop|elementary|kali|raspbian|deepin|zorin) DEB_BASED=1 ;;
    fedora|rhel|centos|rocky|almalinux|ol)                              RPM_BASED=1 ;;
    opensuse*|suse|sles)                                                 RPM_BASED=1 ;;
    arch|manjaro|endeavouros|garuda|artix)                               ARCH_BASED=1 ;;
    alpine)                                                              ALPINE=1   ;;
    *)
        case "$DISTRO_LIKE" in
            *debian*|*ubuntu*) DEB_BASED=1 ;;
            *fedora*|*rhel*|*suse*) RPM_BASED=1 ;;
            *arch*) ARCH_BASED=1 ;;
        esac ;;
esac

# ── Self-extract embedded payload ───────────────────────────────────
extract_payload() {
    EXTRACT_DIR=$(mktemp -d -t zupt-installer.XXXXXX)
    # Find the line number where the payload starts (marker: __PAYLOAD_BELOW__)
    local marker_line
    marker_line=$(grep -an '^__PAYLOAD_BELOW__$' "$0" | head -1 | cut -d: -f1)
    [ -z "$marker_line" ] && die "Installer is corrupt — no payload marker."
    # Skip past marker line, decode base64 → tar
    tail -n +$((marker_line + 1)) "$0" | base64 -d | tar -xzC "$EXTRACT_DIR"
    [ -f "$EXTRACT_DIR/zupt_${VERSION}_amd64.deb" ] || die "Payload extraction failed."
}

# ── Install Qt6 binding (needs network) ─────────────────────────────
install_qt6() {
    if python3 -c 'import PyQt6.QtWidgets' 2>/dev/null \
       || python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then
        ok "Qt6 binding already installed"
        return 0
    fi
    step "Installing Python 3 + Qt6 binding"
    if [ $DEB_BASED -eq 1 ]; then
        apt-get update -qq || warn "apt-get update failed (network?); continuing anyway"
        apt-get install -y python3 python3-pyqt6 \
            || apt-get install -y python3 python3-pyside6 \
            || warn "Could not install Qt6 binding via apt"
    elif [ $RPM_BASED -eq 1 ]; then
        case "$DISTRO" in
            opensuse*|suse|sles)
                zypper --non-interactive install python3 python3-pyqt6 \
                    || zypper --non-interactive install python3 python3-PyQt6 \
                    || zypper --non-interactive install python3 python3-pyside6 ;;
            *)
                if command -v dnf >/dev/null; then
                    dnf install -y python3 python3-pyqt6 \
                        || dnf install -y python3 python3-pyside6
                else
                    yum install -y python3 python3-pyqt6 \
                        || yum install -y python3 python3-pyside6
                fi ;;
        esac
    elif [ $ARCH_BASED -eq 1 ]; then
        pacman -Sy --noconfirm python python-pyqt6 \
            || pacman -Sy --noconfirm python python-pyside6
    elif [ $ALPINE -eq 1 ]; then
        apk add python3 py3-pyqt6 || apk add python3 py3-pyside6
    else
        warn "Unknown distribution. Trying pip fallback..."
        if command -v pip3 >/dev/null; then
            pip3 install --break-system-packages PySide6 2>/dev/null \
                || pip3 install --user PySide6
        else
            warn "No pip3. Install python3-pyqt6 manually."
        fi
    fi
    if python3 -c 'import PyQt6.QtWidgets' 2>/dev/null \
       || python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then
        ok "Qt6 binding installed"
    else
        warn "Qt6 binding install failed. The CLI will still work; the GUI won't."
    fi
}

# ── Install zupt CLI ────────────────────────────────────────────────
install_cli() {
    step "Installing zupt CLI ${VERSION}"
    if [ $DEB_BASED -eq 1 ]; then
        dpkg -i "$EXTRACT_DIR/zupt_${VERSION}_amd64.deb" 2>&1 \
            | grep -v '^Selecting\|^Preparing\|^Unpacking\|^Setting up\|^Processing' || true
        # Resolve any missing libs from apt
        apt-get -f install -y 2>/dev/null || true
        ok "zupt CLI installed: $(zupt version 2>&1 | head -1)"
    elif [ $RPM_BASED -eq 1 ]; then
        local rpmtar="$EXTRACT_DIR/zupt-${VERSION}.srpm.tar.gz"
        if command -v rpmbuild >/dev/null; then
            local rpmroot=$(mktemp -d)
            tar -xzC "$rpmroot" -f "$rpmtar"
            rpmbuild --define "_topdir $rpmroot" -bb "$rpmroot/SPECS/zupt.spec"
            rpm -Uvh --force "$rpmroot"/RPMS/x86_64/zupt-*.rpm
            rm -rf "$rpmroot"
        else
            # rpmbuild not available — fall back to tarball
            warn "rpmbuild missing — using portable binary install"
            local appdir="$EXTRACT_DIR/zupt-${VERSION}-x86_64.AppDir.tar.gz"
            mkdir -p /opt
            tar -xzC /opt -f "$appdir"
            ln -sf "/opt/zupt-${VERSION}-x86_64.AppDir/AppRun" /usr/local/bin/zupt
            ok "zupt CLI installed (portable mode)"
        fi
    else
        # Universal fallback: portable AppDir tarball
        warn "No native package format for $DISTRO. Using portable binary."
        mkdir -p /opt /usr/local/bin
        tar -xzC /opt -f "$EXTRACT_DIR/zupt-${VERSION}-x86_64.AppDir.tar.gz"
        ln -sf "/opt/zupt-${VERSION}-x86_64.AppDir/AppRun" /usr/local/bin/zupt
        ok "zupt CLI installed (portable mode)"
    fi
}

# ── Install zupt-gui ────────────────────────────────────────────────
install_gui() {
    step "Installing zupt-gui ${GUI_VERSION}"
    if [ $DEB_BASED -eq 1 ]; then
        dpkg -i "$EXTRACT_DIR/zupt-gui_${GUI_VERSION}_all.deb" 2>&1 \
            | grep -v '^Selecting\|^Preparing\|^Unpacking\|^Setting up\|^Processing' || true
        apt-get -f install -y 2>/dev/null || true
        ok "zupt-gui installed"
    elif [ $RPM_BASED -eq 1 ]; then
        local rpmtar="$EXTRACT_DIR/zupt-gui-${GUI_VERSION}.srpm.tar.gz"
        if command -v rpmbuild >/dev/null; then
            local rpmroot=$(mktemp -d)
            tar -xzC "$rpmroot" -f "$rpmtar"
            rpmbuild --define "_topdir $rpmroot" -bb "$rpmroot/SPECS/zupt-gui.spec"
            rpm -Uvh --force "$rpmroot"/RPMS/noarch/zupt-gui-*.rpm
            rm -rf "$rpmroot"
        else
            warn "rpmbuild missing — using portable mode"
            mkdir -p /opt /usr/local/bin
            tar -xzC /opt -f "$EXTRACT_DIR/Zupt-GUI-${GUI_VERSION}-x86_64.AppDir.tar.gz"
            ln -sf "/opt/zupt-gui.AppDir/AppRun" /usr/local/bin/zupt-gui
            ok "zupt-gui installed (portable)"
        fi
    else
        # Portable
        mkdir -p /opt /usr/local/bin
        tar -xzC /opt -f "$EXTRACT_DIR/Zupt-GUI-${GUI_VERSION}-x86_64.AppDir.tar.gz"
        ln -sf "/opt/zupt-gui.AppDir/AppRun" /usr/local/bin/zupt-gui
        # Desktop integration if possible
        if [ -d /usr/share/applications ]; then
            cp /opt/zupt-gui.AppDir/zupt-gui.desktop /usr/share/applications/ 2>/dev/null || true
        fi
        ok "zupt-gui installed (portable)"
    fi
}

# ── AppImage extract (no install) ───────────────────────────────────
install_appimage() {
    step "Extracting AppImage to current directory"
    local target="${PWD}/zupt-portable"
    mkdir -p "$target"
    tar -xzC "$target" -f "$EXTRACT_DIR/zupt-${VERSION}-x86_64.AppDir.tar.gz"
    tar -xzC "$target" -f "$EXTRACT_DIR/Zupt-GUI-${GUI_VERSION}-x86_64.AppDir.tar.gz"
    cat > "$target/zupt" <<EOF
#!/bin/sh
exec "$target/zupt-${VERSION}-x86_64.AppDir/AppRun" "\$@"
EOF
    cat > "$target/zupt-gui" <<EOF
#!/bin/sh
exec "$target/zupt-gui.AppDir/AppRun" "\$@"
EOF
    chmod +x "$target/zupt" "$target/zupt-gui"
    ok "Portable install at: $target"
    echo "Run: $target/zupt help"
    echo "     $target/zupt-gui"
    echo
    warn "Portable mode still needs Python 3 + PyQt6 system-wide."
    warn "To install Qt6: sudo apt install python3-pyqt6  (or equivalent)"
}

# ── Uninstall ───────────────────────────────────────────────────────
do_uninstall() {
    step "Uninstalling zupt + zupt-gui"
    if [ $DEB_BASED -eq 1 ]; then
        dpkg -r zupt-gui 2>/dev/null || true
        dpkg -r zupt 2>/dev/null || true
    elif [ $RPM_BASED -eq 1 ]; then
        rpm -e zupt-gui 2>/dev/null || true
        rpm -e zupt 2>/dev/null || true
    fi
    rm -rf /opt/zupt-2.2.2-x86_64.AppDir /opt/zupt-gui.AppDir 2>/dev/null
    rm -f /usr/local/bin/zupt /usr/local/bin/zupt-gui 2>/dev/null
    rm -f /usr/share/applications/zupt-gui.desktop 2>/dev/null
    ok "Uninstall complete"
}

# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────

cat <<HEADER
${BOLD}${CYAN}
   ╔══════════════════════════════════════════════════════════════╗
   ║       ZUPT ${VERSION}  +  ZUPT-GUI ${GUI_VERSION}                          ║
   ║       Post-quantum backup compression — Linux installer     ║
   ╚══════════════════════════════════════════════════════════════╝
${RESET}
   Distribution detected:  ${BOLD}${DISTRO_NAME}${RESET}
   Mode:                   ${BOLD}${MODE}${RESET}

HEADER

if [ "$MODE" = "uninstall" ]; then
    do_uninstall
    exit 0
fi

extract_payload

case "$MODE" in
    cli)
        install_cli ;;
    gui)
        install_qt6
        install_gui ;;
    full)
        install_qt6
        install_cli
        install_gui ;;
    appimage)
        install_appimage ;;
esac

echo
step "Installation complete"
case "$MODE" in
    cli|full)  echo "  Run:  zupt help" ;;
esac
case "$MODE" in
    gui|full)  echo "  Run:  zupt-gui  (or find 'Zupt GUI' in your applications menu)" ;;
esac
case "$MODE" in
    appimage)  echo "  Run:  ./zupt-portable/zupt help" ;;
esac
echo

exit 0
