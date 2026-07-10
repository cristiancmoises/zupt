#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# VaptVupt GUI launcher for macOS (portable package).
# Double-clickable in Finder (.command). Requirements on the target Mac:
#   * Python 3.8+   (python.org, Homebrew `brew install python`, or Xcode CLT)
#   * PySide6 or PyQt6:   python3 -m pip install PySide6
#   * The vaptvupt CLI:   `vaptvupt` next to this file, or on PATH
#     (Homebrew: `brew install cristiancmoises/tap/vaptvupt`).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$HERE/vaptvupt" ] && export VAPTVUPT_BIN="$HERE/vaptvupt"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  osascript -e 'display alert "VaptVupt GUI" message "Python 3 not found. Install it from python.org or `brew install python`, then run: python3 -m pip install PySide6"' 2>/dev/null
  echo "Python 3 not found." >&2; exit 1
fi
exec "$PY" "$HERE/zupt_gui.py" "$@"
