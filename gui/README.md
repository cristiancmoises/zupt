# VaptVupt GUI

Desktop application for [vaptvupt](https://git.securityops.co/cristiancmoises/vaptvupt) backup compression with ML-KEM-768 + X25519 post-quantum hybrid encryption.

Works on GNU/Linux, BSD, macOS, and Windows.

## Install

### Linux (recommended)

```bash
tar xzf vaptvupt-gui.tar.gz && cd vaptvupt-gui
./vaptvupt-gui                      # auto-creates venv, installs PySide6
./install.sh --user              # adds right-click menu integration
```

### Windows

**Option A — Installer (recommended):**

Download `VaptVuptGUI-1.3.0-Setup.exe` and run it. Installs to Program Files, adds Start Menu shortcut, desktop shortcut, right-click context menus, and .zupt file association. Includes uninstaller.

**Option B — Build from source:**

```cmd
cd packaging\windows
build-windows.bat
```

Requires Python 3.9+, NSIS 3.x, and a compiled `vaptvupt.exe`.

**Option C — Run directly:**

```cmd
pip install PySide6
python src\zupt_gui.py
```

### macOS / BSD

```bash
pip3 install PySide6
python3 src/zupt_gui.py
```

### AppImage (universal Linux)

```bash
chmod +x VaptVupt-GUI-1.3.0-x86_64.AppImage
./VaptVupt-GUI-1.3.0-x86_64.AppImage
```

### Flatpak

```bash
flatpak-builder --install build packaging/flatpak/dev.zupt.gui.yml
flatpak run dev.zupt.gui
```

## Features

| Tab | Function |
|-----|----------|
| Keys | Generate ML-KEM-768 + X25519 hybrid keypairs |
| Compress | All codecs, levels 1-9, dedup, solid, password, PQ keys |
| Extract | Decrypt and extract .zupt archives |
| Verify | Check block checksums, view archive metadata |
| Disk | Full-disk backup and restore |
| About | Version, cryptographic stack, credits |

All tabs support drag-and-drop. Drop a .zupt file anywhere on the window to extract it. Drop any other file to compress it.

## System Integration

### Linux (Nemo / Cinnamon)

After `./install.sh --user`:
- Right-click any file: **Compress with VaptVupt**
- Right-click .zupt file: **Extract with VaptVupt**
- Double-click .zupt: opens in VaptVupt GUI

### Windows (after installer)

- Right-click any file: **Compress with VaptVupt**
- Right-click any folder: **Compress with VaptVupt**
- Double-click .zupt: opens in VaptVupt GUI
- Right-click .zupt: **Verify Integrity**

## Architecture

```
VaptVupt GUI (PySide6, Python)
    |
    |-- subprocess.Popen() with streaming stderr
    |
    v
vaptvupt CLI (Pure C11 binary)
    ML-KEM-768 + X25519 + AES-256-CTR
    VaptVupt / LZHP / Store codecs
    Block deduplication, full-disk backup
```

The GUI calls the vaptvupt CLI binary — all cryptography runs in native C, not Python.

## Packaging

| Platform | Format | Tool |
|----------|--------|------|
| Any | pip | `pip install .` |
| Debian/Ubuntu/Mint | .deb | `packaging/deb/control` |
| Fedora/RHEL | .rpm | `rpmbuild -ba packaging/rpm/vaptvupt.spec` |
| Universal Linux | .AppImage | `packaging/appimage/build-appimage.sh` |
| Sandboxed Linux | .flatpak | `packaging/flatpak/dev.zupt.gui.yml` |
| Windows | .exe installer | `packaging/windows/build-windows.bat` |
| Windows | NSIS .exe | `packaging/windows/zupt-installer.nsi` |

## Credits

- **vaptvupt** v4.1.0 — Cristian Cezar Moisés ([github](https://git.securityops.co/cristiancmoises/vaptvupt))

## License

AGPL-3.0-or-later
