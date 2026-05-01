#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
# Fast Installer for Zupt - GNU/Linux

set -e

echo "🔧 Installing Zupt..."

# Create temporary directory
TMP_DIR=$(mktemp -d)

# Clone and build
git clone https://git.securityops.co/cristiancmoises/zupt.git "$TMP_DIR/zupt"
cd "$TMP_DIR/zupt"

make clean
make

# Install
sudo make install

echo "✅ Zupt successfully installed to /usr/local/bin/zupt"
echo "🔒 You can now run: zupt"

# Cleanup
cd ~
rm -rf "$TMP_DIR"
echo "🧹 Cleanup completed"
