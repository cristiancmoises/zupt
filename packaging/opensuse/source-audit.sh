#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SCANNER=$SCRIPT_DIR/../../scripts/check-source-only.sh

if [[ ! -x $SCANNER ]]; then
    printf 'ERROR: source-only scanner is missing or not executable: %s\n' "$SCANNER" >&2
    exit 2
fi

exec "$SCANNER" "$@"
