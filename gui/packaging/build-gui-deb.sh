#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# Compatibility entry point for the canonical source-only GUI builder.
set -Eeuo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
exec "$repo_root/packaging/build-gui-deb.sh" "$@"
