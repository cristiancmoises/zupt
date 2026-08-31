#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# Stable entry point for the source installer. Dependency installation belongs
# to the operating-system package manager; this script performs no downloads.
set -Eeuo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec "$repo_root/gui/install.sh" "$@"
