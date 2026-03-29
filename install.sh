#!/usr/bin/env bash
# Fast Installer for Zupt - GNU/Linux

set -e

echo "🔧 Installing Zupt..."

# Create temporary directory
TMP_DIR=$(mktemp -d)

# Clone and build
git clone https://github.com/cristiancmoises/zupt.git "$TMP_DIR/zupt"
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
