#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# ZUPT GUI launcher for Linux and the BSDs (portable package).
# Requirements on the target system:
#   * Python 3.9+
#   * PySide6 or PyQt6
#       Debian/Ubuntu:  sudo apt install python3-pyqt6
#       Fedora/RHEL:    sudo dnf install python3-pyqt6
#       FreeBSD:        pkg install py311-pyside6   (or py311-qt6-pyqt)
#       OpenBSD:        pkg_add py3-pyside6
#       any OS via pip: python3 -m pip install PySide6
#   * The ZUPT CLI: `zupt` next to this file, or on PATH.
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -x "$HERE/zupt" ] && export ZUPT_BIN="$HERE/zupt"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "zupt-gui: Python 3 not found on PATH." >&2
  exit 1
fi
exec "$PY" "$HERE/zupt_gui.py" "$@"
