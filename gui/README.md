# Zupt GUI — Cross-Platform Post-Quantum Backup

Desktop application for [zupt](https://github.com/cristiancmoises/zupt) backup compression with ML-KEM-768 + X25519 post-quantum hybrid encryption.

Works on GNU/Linux, BSD, macOS, and Windows.

## Install

### Linux (recommended)

```bash
tar xzf zupt-gui.tar.gz && cd zupt-gui
./zupt-gui                      # auto-creates venv, installs PySide6
./install.sh --user              # adds right-click menu integration
```

After install, right-click any file in Nemo/Nautilus to see "Compress with Zupt".
Double-click any .zupt file to open it in the GUI.

### Windows

**Option A — Installer (recommended):**

Download `ZuptGUI-2.1.6-Setup.exe` and run it. Installs to Program Files, adds Start Menu shortcut, desktop shortcut, right-click context menus, and .zupt file association. Includes uninstaller.

**Option B — Build from source:**

```cmd
cd packaging\windows
build-windows.bat
```

Requires Python 3.9+, NSIS 3.x, and a compiled `zupt.exe`.

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
chmod +x zupt-gui-1.0.0-x86_64.AppImage
./zupt-gui-1.0.0-x86_64.AppImage
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
- Right-click any file: **Compress with Zupt**
- Right-click .zupt file: **Extract with Zupt**
- Double-click .zupt: opens in Zupt GUI

### Windows (after installer)

- Right-click any file: **Compress with Zupt**
- Right-click any folder: **Compress with Zupt**
- Double-click .zupt: opens in Zupt GUI
- Right-click .zupt: **Verify Integrity**

## Architecture

```
Zupt GUI (PySide6, Python)
    |
    |-- subprocess.Popen() with streaming stderr
    |
    v
zupt CLI (Pure C11 binary)
    ML-KEM-768 + X25519 + AES-256-CTR
    VaptVupt / LZHP / Store codecs
    Block deduplication, full-disk backup
```

The GUI calls the zupt CLI binary — all cryptography runs in native C, not Python.

## Packaging

| Platform | Format | Tool |
|----------|--------|------|
| Any | pip | `pip install .` |
| Debian/Ubuntu/Mint | .deb | `packaging/deb/control` |
| Fedora/openSUSE | .rpm | `rpmbuild -ba packaging/rpm/zupt-gui.spec` |
| Universal Linux | .AppImage | `packaging/appimage/build-appimage.sh` |
| Sandboxed Linux | .flatpak | `packaging/flatpak/dev.zupt.gui.yml` |
| Windows | .exe installer | `packaging/windows/build-windows.bat` |
| Windows | NSIS .exe | `packaging/windows/zupt-installer.nsi` |

## Credits

- **zupt** v2.1.6 — Cristian Cezar Moises ([github](https://github.com/cristiancmoises/zupt))
- **libzupt** v1.0.2 — Alessandro de Oliveira Faria ([github](https://github.com/cabelo/libzupt))

## License

**AGPL-3.0-or-later** — see [LICENSE-GUI](LICENSE-GUI) and the project-root [LICENSE](../LICENSE).

For commercial licensing inquiries, contact: **sac@securityops.co**
