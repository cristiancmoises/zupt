#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# ZUPT GUI launcher for macOS (portable package).
# Double-clickable in Finder (.command). Requirements on the target Mac:
#   * Python 3.9+
#   * PySide6 or PyQt6:   python3 -m pip install PySide6
#   * The ZUPT CLI:       `zupt` next to this file, or on PATH
#     (Homebrew: `brew install cristiancmoises/tap/zupt`).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$HERE/zupt" ] && export ZUPT_BIN="$HERE/zupt"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  osascript -e 'display alert "ZUPT GUI" message "Python 3.9 or newer was not found. Install Python and a trusted PySide6 or PyQt6 package."' 2>/dev/null
  echo "Python 3 not found." >&2; exit 1
fi
exec "$PY" "$HERE/zupt_gui.py" "$@"
