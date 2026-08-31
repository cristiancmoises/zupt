#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Fast installer for ZUPT - GNU/Linux

set -Eeuo pipefail
umask 077

VERSION=${VERSION:-5.2.8}
PREFIX=${PREFIX:-/usr/local}

echo "🔧 Installing ZUPT..."

# Create temporary directory
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/zupt-install.XXXXXXXX")
trap 'chmod -R u+rwX "$TMP_DIR" 2>/dev/null || true; rm -rf -- "$TMP_DIR"' EXIT HUP INT TERM

# Clone and build
git clone --depth 1 --branch "v$VERSION" \
    https://github.com/cristiancmoises/zupt.git "$TMP_DIR/zupt"
cd "$TMP_DIR/zupt"

make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 2)" \
    WITH_SDK=0 WITH_PQBOX=0
make WITH_SDK=0 WITH_PQBOX=0 check

# Install
sudo make PREFIX="$PREFIX" WITH_SDK=0 WITH_PQBOX=0 \
    INSTALL_LEGACY_ALIAS=0 install

echo "✅ ZUPT $VERSION successfully installed to $PREFIX/bin/zupt"
echo "🔒 You can now run: zupt"
