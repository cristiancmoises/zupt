# Zupt + Zupt GUI — Install Guide for Linux

If you're seeing the error:

```
zupt-gui depende de python3-pyqt6 | python3-pyside6; porém:
  Pacote python3-pyqt6 não está instalado.
zupt-gui depende de zupt (>= 2.2.3); porém:
  Versão de zupt no sistema é 2.1.7-1.
```

This is correct behavior. The `zupt-gui` deb requires:
- Python 3 with **PyQt6** or **PySide6** (the GUI toolkit)
- The **zupt CLI 2.2.3** or newer

## The fastest fix — one command (Linux Mint, Ubuntu, Debian)

Put all the downloaded files in the same folder, then:

```bash
sudo bash install-zupt-gui.sh
```

This script auto-detects your distribution and installs everything in
the right order. Done.

## Manual fix — three commands (if you prefer)

### Linux Mint / Ubuntu / Debian / Pop!_OS

```bash
# 1. Install the Qt6 Python binding
sudo apt update
sudo apt install -y python3-pyqt6

# 2. Upgrade zupt CLI to 2.2.3
sudo dpkg -i zupt_2.2.3_amd64.deb

# 3. Install the GUI
sudo dpkg -i zupt-gui_1.1.1_all.deb
```

If step 3 still complains about deps, run:

```bash
sudo apt --fix-broken install
```

### Fedora / RHEL / Rocky / AlmaLinux

```bash
sudo dnf install -y python3-pyqt6
sudo dnf install -y zupt-2.2.3-1.x86_64.rpm zupt-gui-1.1.1-1.noarch.rpm
```

(Or build the RPM from the SRPM tarball with `rpmbuild -bb SPECS/zupt.spec`)

### openSUSE Leap / Tumbleweed

```bash
sudo zypper install python3-pyqt6
# Build the RPM from the source tarball — see the SRPM .tar.gz
```

### Arch Linux / Manjaro / EndeavourOS

```bash
sudo pacman -S python-pyqt6
# Build zupt from the source tarball
```

### Anything else (or no apt/dnf/pacman handy)

Use the AppImage — no install needed:

```bash
tar xzf Zupt-GUI-1.1.1-x86_64.AppDir.tar.gz
cd zupt-gui.AppDir
./AppRun
```

The AppImage still needs Python 3 + Qt6 binding on the host (those are
universally available on every Linux distribution since 2022). For a
fully standalone executable with no Python dependency, use a future
PyInstaller-built version (not in this release).

## Why does the GUI need Qt6?

The Zupt GUI is written in Python, using either PyQt6 or PySide6 (it
auto-detects whichever is installed). These are bindings to the Qt 6
graphical toolkit — they're how the GUI draws windows, buttons, and
dialogs.

PyQt6 is in the default repositories of every major Linux distribution
since 2022, so installing it is one apt/dnf/zypper/pacman command away.
We don't bundle Qt6 inside the deb because:

- It's already on most modern systems
- Bundling would make the deb 80 MB+ instead of 35 KB
- Distribution-managed Qt gets security updates automatically

## Why does the GUI need zupt 2.2.3?

The GUI calls `zupt --pq-sdk` and `zupt keygen --sdk` for state-of-the-art
post-quantum encryption (HKDF-SHA3 hybrid combiner, key commitment, HPKE
binding, Argon2id). These flags didn't exist in 2.1.7 — they were added
in 2.2.0.

If you have an older zupt installed, the GUI's compress/extract will fail
with "unknown option --pq-sdk".

## After installing — verify

```bash
zupt version       # should show: 2.2.3
zupt-gui           # should launch the GUI window
```

## If the GUI window still doesn't appear

```bash
# Run from terminal to see error messages
zupt-gui

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

If you've tried the above and zupt-gui still won't work, open an issue
at https://git.securityops.co/cristiancmoises/zupt/issues with:

1. Output of `lsb_release -a` (or `cat /etc/os-release`)
2. Output of `python3 --version`
3. Output of `python3 -c 'import PyQt6; print(PyQt6.__version__)' 2>&1`
4. Output of `zupt version`
5. Output of `zupt-gui` (the error message it printed to terminal)

---

## Building from source

If you want to build Zupt from the source tarball instead of installing
the pre-built `.deb` / `.rpm` packages, you'll need:

### Build dependencies

| Component | Why needed |
|---|---|
| `gcc` ≥ 7 or `clang` ≥ 10 | C11 compiler |
| `make` | build driver |
| `libargon2-dev` | Argon2id KDF |
| `libssl-dev` | OpenSSL libcrypto (AES, SHA-256) |
| **`libzuptsdk-dev` 2.0.0+** | Zupt's cryptographic SDK |

The `libzuptsdk-dev` package is a separate sister project — it contains
the post-quantum hybrid cryptography that Zupt uses on its `--pq-sdk`
path. Both libraries are by the same author (Cristian Cezar Moisés) but
are distributed as separate source/binary packages so each can evolve
on its own release cadence.

### Install build dependencies (Debian/Ubuntu/Mint)

```bash
sudo apt install build-essential libargon2-dev libssl-dev

# Then install libzuptsdk from its package:
sudo apt install ./libzuptsdk2_2.0.0_amd64.deb \
                 ./libzuptsdk-dev_2.0.0_amd64.deb
```

### Install build dependencies (Fedora/RHEL/openSUSE)

```bash
sudo dnf install gcc make libargon2-devel openssl-devel
# libzuptsdk from its SRPM:
tar -xzf libzuptsdk-2.0.0.srpm.tar.gz
rpmbuild -bb SPECS/libzuptsdk.spec
sudo rpm -i ~/rpmbuild/RPMS/x86_64/libzuptsdk-2.0.0-*.rpm
```

### Build Zupt itself

```bash
tar -xzf zupt-2.2.3-source.tar.gz
cd zupt-2.2.3

make                 # build the `./zupt` binary
sudo make install    # install to /usr/local/bin (override with PREFIX=/usr)

./zupt version       # verify
```

The `make` step takes 10-30 seconds. The build emits the binary as
`./zupt`. The default install prefix is `/usr/local`; override with
`PREFIX=/usr` for system-wide install.

### Run the test suite

```bash
make test
```

61 tests pass: roundtrip, audit, multi-file, cross-block, dedup property,
path-traversal, argument-order, block-swap regression. Each suite reports
its own pass/fail count.

### Cross-compilation

Zupt builds on x86_64, aarch64, armhf, ppc64le, s390x, and riscv64. To
cross-compile:

```bash
make CC=aarch64-linux-gnu-gcc      # for AArch64
make CC=arm-linux-gnueabihf-gcc    # for ARMv7 (Raspberry Pi 32-bit)
```

The Makefile auto-detects target architecture via `$(CC) -dumpmachine`
and selects the appropriate SIMD flags (NEON on AArch64, SSE4/AVX2 on
x86_64).

### Static linking against libzuptsdk

If you want a fully self-contained `zupt` binary (no `libzuptsdk.so.2`
runtime dependency), you can link against the static library:

```bash
make LDLIBS='-l:libzuptsdk.a -lcrypto -largon2'
```

This produces a binary that doesn't need `libzuptsdk2` installed at
runtime — useful for containers, embedded systems, or distribution to
machines without package management.
