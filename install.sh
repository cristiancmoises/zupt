#!/usr/bin/env bash
# Fast Installer - For GNU+Linux

set -e

echo "🔧 Installing zupt..."

# Create temporary directory
TMP_DIR=$(mktemp -d)

# Clone repo
git clone https://github.com/cristiancmoises/zupt.git "$TMP_DIR/zupt"

cd "$TMP_DIR/zupt"

# Build
make clean
make

# Install safely with proper permissions
sudo install -m 755 zupt /usr/local/bin/

echo "✅ Installed to /usr/local/bin/zupt"

# Cleanup
cd ~
rm -rf "$TMP_DIR"

echo "🧹 Cleanup done"
echo "🔒 You can now run: zupt"
