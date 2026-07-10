# VaptVupt + VaptVupt GUI — Install Guide for Linux

If you're seeing the error:

```
vaptvupt-gui depende de python3-pyqt6 | python3-pyside6; porém:
  Pacote python3-pyqt6 não está instalado.
vaptvupt-gui depende de vaptvupt (>= 4.2.1); porém:
  Versão de vaptvupt no sistema é 2.1.7-1.
```

This is correct behavior. The `vaptvupt-gui` deb requires:
- Python 3 with **PyQt6** or **PySide6** (the GUI toolkit)
- The **vaptvupt CLI 4.2.1** or newer

## The fastest fix — one command (Linux Mint, Ubuntu, Debian)

Put all the downloaded files in the same folder, then:

```bash
sudo bash install-zupt-gui.sh
```

This script auto-detects your distribution and installs everything in
the right order.

## Manual fix — three commands (if you prefer)

### Linux Mint / Ubuntu / Debian / Pop!_OS

```bash
# 1. Install the Qt6 Python binding
sudo apt update
sudo apt install -y python3-pyqt6

# 2. Upgrade vaptvupt CLI to 4.2.1
sudo dpkg -i vaptvupt_4.2.1_amd64.deb

# 3. Install the GUI
sudo dpkg -i vaptvupt-gui_1.3.0_all.deb
```

If step 3 still complains about deps, run:

```bash
sudo apt --fix-broken install
```

### Fedora / RHEL / Rocky / AlmaLinux

```bash
sudo dnf install -y python3-pyqt6
sudo dnf install -y vaptvupt-4.2.1-1.x86_64.rpm vaptvupt-gui-1.3.0-1.noarch.rpm
```

(Or build the RPM from the SRPM tarball with `rpmbuild -bb SPECS/vaptvupt.spec`)

### openSUSE Leap / Tumbleweed

```bash
sudo zypper install python3-pyqt6
# Build the RPM from the source tarball — see the SRPM .tar.gz
```

### Arch Linux / Manjaro / EndeavourOS

```bash
sudo pacman -S python-pyqt6
# Build vaptvupt from the source tarball
```

### Anything else (or no apt/dnf/pacman handy)

Use the AppImage — no install needed:

```bash
tar xzf VaptVupt-GUI-1.3.0-x86_64.AppDir.tar.gz
cd vaptvupt-gui.AppDir
./AppRun
```

The AppImage still needs Python 3 + Qt6 binding on the host. For a
fully standalone executable with no Python dependency, use a future
PyInstaller-built version (not in this release).

## Why does the GUI need Qt6?

The VaptVupt GUI is written in Python, using either PyQt6 or PySide6 (it
auto-detects whichever is installed). These are bindings to the Qt 6
graphical toolkit — they're how the GUI draws windows, buttons, and
dialogs.

PyQt6 is in the default repositories of major Linux distributions, so
installing it is one apt/dnf/zypper/pacman command away. We don't bundle
Qt6 inside the deb because:

- It's already on most modern systems
- Bundling would make the deb 80 MB+ instead of 35 KB
- Distribution-managed Qt gets security updates automatically

## Why does the GUI need vaptvupt 4.2.1?

The GUI calls `vaptvupt --pq` and `vaptvupt keygen` for native
post-quantum encryption (ML-KEM-768 + X25519, in-tree implementation).
Older CLI versions lack these flags, so the GUI's compress/extract will
fail against them.

## After installing — verify

```bash
vaptvupt version       # should show: 4.2.1
vaptvupt-gui           # should launch the GUI window
```

## If the GUI window still doesn't appear

```bash
# Run from terminal to see error messages
vaptvupt-gui

# If you see "ImportError: No module named 'PyQt6'":
#   The GUI fell back through both PyQt6 and PySide6 imports.
#   Re-check: python3 -c 'import PyQt6.QtWidgets'

# If you see "DISPLAY not set":
#   You're on SSH without X forwarding. Use ssh -X or run locally.

# If you see "qt.qpa.plugin: Could not load the Qt platform plugin":
#   Missing Qt platform plugin. On Mint/Ubuntu:
#   sudo apt install qt6-qpa-plugins
```

## Reporting issues

If you've tried the above and vaptvupt-gui still won't work, open an issue
at https://git.securityops.co/cristiancmoises/vaptvupt/issues with:

1. Output of `lsb_release -a` (or `cat /etc/os-release`)
2. Output of `python3 --version`
3. Output of `python3 -c 'import PyQt6; print(PyQt6.__version__)' 2>&1`
4. Output of `vaptvupt version`
5. Output of `vaptvupt-gui` (the error message it printed to terminal)

---

## Building from source

If you want to build VaptVupt from the source tarball instead of installing
the pre-built `.deb` / `.rpm` packages, you'll need only a C compiler and
make. The default build has NO external crypto dependency and installs no
shared library.

### Build dependencies (default build)

| Component | Why needed |
|---|---|
| `gcc` ≥ 7 or `clang` ≥ 10 | C11 compiler |
| `make` | build driver |
| libm, pthread | math and threading (part of the standard C library/toolchain) |

The default build uses PBKDF2-SHA256 (600k iterations) for password KDF
and the in-tree native `--pq` mode (ML-KEM-768 + X25519) for post-quantum
encryption. No `libzuptsdk`, no OpenSSL, no libargon2 is required.

### Install build dependencies (Debian/Ubuntu/Mint)

```bash
sudo apt install build-essential
```

### Install build dependencies (Fedora/RHEL/openSUSE)

```bash
sudo dnf install gcc make        # Fedora/RHEL
sudo zypper install gcc make     # openSUSE
```

### Build VaptVupt itself

```bash
tar -xzf vaptvupt-4.2.1-source.tar.gz
cd vaptvupt-4.2.1

make                 # build the `./vaptvupt` binary
sudo make install    # install to /usr/local/bin (override with PREFIX=/usr)

./vaptvupt version       # verify
```

The `make` step takes 10-30 seconds. The build emits the binary as
`./vaptvupt`. The default install prefix is `/usr/local`; override with
`PREFIX=/usr` for system-wide install.

### Run the test suite

```bash
make test
```

Covers roundtrip, multi-file, cross-block, dedup property, path-traversal,
argument-order, and block-swap regression. Each suite reports its own
pass/fail count.

### Cross-compilation

VaptVupt builds on x86_64, aarch64, armhf, ppc64le, s390x, and riscv64. To
cross-compile:

```bash
make CC=aarch64-linux-gnu-gcc      # for AArch64
make CC=arm-linux-gnueabihf-gcc    # for ARMv7 (Raspberry Pi 32-bit)
```

The Makefile auto-detects target architecture via `$(CC) -dumpmachine`
and selects the appropriate SIMD flags (NEON on AArch64, SSE4/AVX2 on
x86_64).

### Optional: WITH_SDK=1 build

The SDK-backed modes — `--pq-sdk`, `--pq-box` (sealed-box), and the
Argon2id KDF — are optional. They are not in the default build and require
building against the separately distributed `libzuptsdk` / `libpqvaptvupt`
libraries:

```bash
make WITH_SDK=1
```

This build additionally needs the SDK development package and its runtime
dependencies (OpenSSL libcrypto, libargon2), which ship with the SDK
distribution. Without `WITH_SDK=1`, the `--pq-sdk` and `--pq-box` flags are
unavailable; use the native `--pq` mode instead.
