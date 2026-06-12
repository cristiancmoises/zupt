#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Fast Installer for VaptVupt - GNU/Linux

set -e

echo "🔧 Installing VaptVupt..."

# Create temporary directory
TMP_DIR=$(mktemp -d)

# Clone and build
git clone https://git.securityops.co/cristiancmoises/vaptvupt.git "$TMP_DIR/vaptvupt"
cd "$TMP_DIR/vaptvupt"

make clean
make

# Install
sudo make install

echo "✅ VaptVupt successfully installed to /usr/local/bin/vaptvupt"
echo "🔒 You can now run: vaptvupt   (legacy 'zupt' symlink also installed)"

# Cleanup
cd ~
rm -rf "$TMP_DIR"
echo "🧹 Cleanup completed"
