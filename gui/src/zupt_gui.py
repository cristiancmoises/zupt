#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
"""VaptVupt GUI — Cross-Platform Post-Quantum Backup.

Renamed from "Zupt" in v3.0.0 due to INPI Brasil trademark.
The .zupt file extension is preserved.

Tries PySide6 first (preferred), falls back to PyQt6 if PySide6 is
not installed. PyQt6 is the default available package on Debian/Ubuntu
without requiring pip; PySide6 ships with broader signal/slot semantics
but the API surface used here is portable between the two.
"""
import sys, os, re, subprocess, shutil
from pathlib import Path

# Try PySide6, fall back to PyQt6. The two have nearly-identical APIs;
# the only adjustment needed is Signal/pyqtSignal naming, handled below.
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QLineEdit, QComboBox, QFileDialog,
        QTextEdit, QProgressBar, QTabWidget, QFrame, QCheckBox,
        QSpinBox, QMessageBox, QStatusBar, QScrollArea
    )
    from PySide6.QtCore import Qt, Signal, QObject, QThread, QTimer
    from PySide6.QtGui import QPalette, QColor, QIcon, QPixmap
    QT_BINDING = "PySide6"
except ImportError:
    try:
        from PyQt6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QPushButton, QLineEdit, QComboBox, QFileDialog,
            QTextEdit, QProgressBar, QTabWidget, QFrame, QCheckBox,
            QSpinBox, QMessageBox, QStatusBar, QScrollArea
        )
        from PyQt6.QtCore import Qt, pyqtSignal as Signal, QObject, QThread, QTimer
        from PyQt6.QtGui import QPalette, QColor, QIcon, QPixmap
        QT_BINDING = "PyQt6"
    except ImportError:
        if sys.stderr is not None:   # None under PyInstaller --windowed
            sys.stderr.write(
                "ERROR: vaptvupt-gui requires PySide6 or PyQt6. Install one of:\n"
                "  Debian/Ubuntu:  sudo apt install python3-pyqt6\n"
                "  Fedora/RHEL:    sudo dnf install python3-pyqt6\n"
                "  pip (any OS):   pip install PySide6\n"
            )
        sys.exit(1)

# ── Find vaptvupt binary ──
#
# v3.0.0 rename: the binary is now `vaptvupt`; older installations
# (1.x/2.x) ship `zupt`. We try the new name first, fall back to the
# old name, and on every candidate verify it's actually executable
# (not just present). After picking a candidate, we run a quick
# `version` liveness check — this catches the case where the binary
# exists but can't load its shared library (the original bug report:
# "GUI doesn't find zupt; copying to /usr/local/bin fixes it").
#
# Diagnostic output goes to stderr so users can `vaptvupt-gui 2>log`
# to see exactly which path was tried and why each failed.

_DISCOVERY_LOG = []

def _discovery_log(msg):
    _DISCOVERY_LOG.append(msg)
    # Echo to stderr if VAPTVUPT_DEBUG or ZUPT_DEBUG is set
    if ((os.environ.get("VAPTVUPT_DEBUG") or os.environ.get("ZUPT_DEBUG"))
            and sys.stderr is not None):   # None under PyInstaller --windowed
        sys.stderr.write(f"  [discovery] {msg}\n")

def _is_runnable(path):
    """A path is runnable if it's a file, executable, and exits 0 on `version`."""
    p = str(path)
    if not os.path.isfile(p):
        return False, "not a regular file"
    if not os.access(p, os.X_OK):
        return False, "not executable (chmod +x needed?)"
    # Liveness check — catches missing shared libraries, broken rpath,
    # ABI mismatch, etc. 3-second cap so we never hang the GUI startup.
    try:
        r = subprocess.run([p, "version"], capture_output=True, timeout=3)
        if r.returncode != 0:
            err = r.stderr.decode("utf-8", errors="replace").strip()
            return False, f"exit {r.returncode}: {err.splitlines()[0] if err else 'no stderr'}"
        return True, "OK"
    except FileNotFoundError:
        return False, "FileNotFoundError on exec"
    except subprocess.TimeoutExpired:
        return False, "timeout (3s) on `version` — binary hung"
    except OSError as e:
        return False, f"OSError: {e}"

def _find_vaptvupt():
    # 1. Explicit env override
    for env in ("VAPTVUPT_BIN", "ZUPT_BIN"):
        p = os.environ.get(env)
        if p:
            ok, reason = _is_runnable(p)
            _discovery_log(f"env {env}={p}: {reason}")
            if ok:
                return p

    # 2. Local project tree (running from a source checkout)
    #    Try BOTH names (vaptvupt is v3.0.0+, zupt is legacy).
    here = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    for parent in (here.parent.parent, here.parent, here):
        for name in ("vaptvupt", "zupt", "vaptvupt.exe", "zupt.exe"):
            c = parent / name
            ok, reason = _is_runnable(c)
            _discovery_log(f"local {c}: {reason}")
            if ok:
                return str(c.resolve())

    # 3. System PATH — try new name first, then legacy
    for name in ("vaptvupt", "zupt"):
        found = shutil.which(name)
        if found:
            ok, reason = _is_runnable(found)
            _discovery_log(f"PATH which({name})={found}: {reason}")
            if ok:
                return found
        else:
            _discovery_log(f"PATH which({name}): not found")

    # 4. Hard-coded common install paths — catches the "GUI launched
    #    from a desktop session with a minimal PATH that omits /usr/bin"
    #    scenario reported against v2.4.8.
    common = [
        # New name (v3.0.0+)
        "/usr/local/bin/vaptvupt", "/usr/bin/vaptvupt",
        "/opt/vaptvupt/bin/vaptvupt", "/opt/homebrew/bin/vaptvupt",
        # Legacy name (1.x/2.x)
        "/usr/local/bin/zupt", "/usr/bin/zupt",
        "/opt/zupt/bin/zupt", "/opt/homebrew/bin/zupt",
        # Termux (Android) install path
        "/data/data/com.termux/files/usr/bin/vaptvupt",
        "/data/data/com.termux/files/usr/bin/zupt",
        # Flatpak sandbox runtime path
        "/app/bin/vaptvupt", "/app/bin/zupt",
    ]
    for path in common:
        ok, reason = _is_runnable(path)
        _discovery_log(f"common {path}: {reason}")
        if ok:
            return path

    # 5. Last resort — return "vaptvupt" and let exec fail loudly later.
    #    A caller-visible error is better than silently returning a path
    #    that doesn't work.
    _discovery_log("FAILED: no runnable vaptvupt/zupt binary found")
    return "vaptvupt"

# Backward-compat: code elsewhere in this file still uses `ZUPT`.
VAPTVUPT = _find_vaptvupt()
ZUPT = VAPTVUPT  # legacy alias used throughout the rest of zupt_gui.py

# ── Query version ONCE at import (cached) ──
#
# The CLI's `version` first line is the brand banner. Examples:
#   v2.4.x: "zupt 2.4.8"
#   v3.0.x: "vaptvupt 3.0.0 (formerly zupt; renamed in v3.0.0 — INPI Brasil trademark)"
#
# We extract three things from that line:
#   - VER_SHORT: the full first line (used as a fallback display)
#   - VER_NUMBER: just the version number "3.0.0" or "2.4.8" (for hero text)
#   - VER_FULL: the entire stdout (used in the about panel)
#
# Earlier code did `ZUPT_VER_SHORT.replace("zupt ", "")` to peel the
# product name. That breaks on v3.0.x because the same string "zupt "
# also appears inside the parenthetical "formerly zupt; renamed".
# We now use a strict regex anchored at the start of the line.

_VERSION_RE = re.compile(r'^(?:vaptvupt|zupt)\s+(\d+\.\d+\.\d+(?:[._A-Za-z0-9-]*)?)')

def _get_version():
    short = "vaptvupt (not found)"
    number = "?"
    full = ""
    try:
        r = subprocess.run([VAPTVUPT, "version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            full = r.stdout.strip()
            lines = full.split("\n")
            short = lines[0]
            m = _VERSION_RE.match(short)
            if m:
                number = m.group(1)
    except Exception:
        pass
    return short, number, full

ZUPT_VER_SHORT, ZUPT_VER_NUMBER, ZUPT_VER_FULL = _get_version()

# ── Detect build capabilities from `version` (and `help` as fallback) ──
#
# The default build is SOURCE-ONLY: the libzuptsdk-backed modes (Argon2id
# KDF, --pq-sdk, --pq-box) are absent and fail with exit 1. Offering them in
# the UI is the #1 reason "functions don't work". We detect what THIS binary
# actually supports and build the encryption UI around it:
#   - SDK_AVAILABLE  : --pq-sdk / --pq-box / Argon2id compiled in (WITH_SDK=1)
#   - PQONLY_AVAILABLE: native --pq-only (full post-quantum, v4.2.0+)
#   - DEFAULT_KDF    : the password KDF this build actually uses
# The `version` banner carries a machine-readable "Build:" line (v4.2.1+);
# for older binaries we fall back to `help` text and default SDK off (safe:
# the native --pq / --pq-only / password modes work on every build).
def _get_caps():
    sdk = False
    pqonly = False
    default_kdf = "PBKDF2-SHA256"
    blob = ZUPT_VER_FULL or ""
    for line in blob.splitlines():
        low = line.lower()
        if low.startswith("build:"):
            sdk = ("full" in low) and ("libzuptsdk" in low)
        elif low.startswith("kdf:"):
            default_kdf = "Argon2id" if "argon2id (default)" in low else "PBKDF2-SHA256"
        if "--pq-only" in line:
            pqonly = True
    if not pqonly:
        try:
            h = subprocess.run([VAPTVUPT, "help"], capture_output=True, text=True, timeout=5)
            txt = (h.stdout or "") + (h.stderr or "")
            if "--pq-only" in txt:
                pqonly = True
        except Exception:
            pass
    return sdk, pqonly, default_kdf

SDK_AVAILABLE, PQONLY_AVAILABLE, DEFAULT_KDF = _get_caps()

# Post-quantum recipient modes offered in the UI, keyed to CLI flags.
#   token -> (label, keygen-flag-list, compress/extract-flag)
# keygen-flags are extra flags added to `keygen` (private) and `keygen --pub`.
def pq_mode_options(include_auto=False):
    """Return [(label, token)] for a PQ-mode dropdown given this build."""
    opts = []
    if include_auto:
        opts.append(("Auto-detect from archive", "auto"))
    opts.append(("Hybrid — ML-KEM-768 + X25519 (recommended)", "pq"))
    if PQONLY_AVAILABLE:
        opts.append(("Full PQ — ML-KEM-768 only", "pqonly"))
    if SDK_AVAILABLE:
        opts.append(("SDK v2 — HKDF + commitment + HPKE", "sdk"))
    return opts

# token -> (extra keygen flags, encrypt/decrypt flag)
_PQ_FLAG = {
    "pq":     ([],           "--pq"),
    "pqonly": (["--pq-only"], "--pq-only"),
    "sdk":    (["--sdk"],     "--pq-sdk"),
}

def _detect_archive_pq(archive):
    """Inspect an archive's `info` and return the matching PQ token, or None."""
    try:
        r = subprocess.run([VAPTVUPT, "info", archive], capture_output=True, text=True, timeout=15)
        txt = (r.stdout or "") + (r.stderr or "")
    except Exception:
        return None
    low = txt.lower()
    if "ml-kem-768 only" in low or "no classical" in low:
        return "pqonly"
    if "sdk v2" in low or "hpke" in low:
        return "sdk"
    if "ml-kem-768" in low or "hybrid" in low or "x25519" in low:
        return "pq"
    return None

# ── Find icon file ──
def _find_icon():
    here = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))
    for p in [here/"assets/zupt.ico", here/"assets/zupt-icon.png", here/"assets/zupt.png",
              here.parent/"assets/zupt.ico", here.parent/"assets/zupt-icon.png",
              Path("/usr/share/icons/hicolor/256x256/apps/zupt-gui.png"),
              Path("/usr/share/zupt-gui/assets/zupt-icon.png")]:
        if p.is_file(): return str(p)
    return None

ICON_PATH = _find_icon()

STYLE = """
* { font-family: "Segoe UI", "Cantarell", "Noto Sans", sans-serif; }
QMainWindow { background: #0a0a0a; }
QTabWidget::pane { background: #0a0a0a; border: none; border-top: 1px solid #1a2a30; }
QTabBar { background: #050a0e; }
QTabBar::tab {
    background: #050a0e; color: #5a7a88; padding: 11px 22px;
    border: none; border-bottom: 2px solid transparent;
    font-weight: 600; font-size: 12px;
}
QTabBar::tab:hover { color: #a0c8d8; background: #0a1018; }
QTabBar::tab:selected { color: #00dde0; border-bottom-color: #00dde0; background: #0c1218; }
QLabel { color: #90acb8; }
QLineEdit, QComboBox, QSpinBox {
    background: #0e1820; color: #c0dce8; border: 1px solid #1a2a30;
    border-radius: 6px; padding: 9px 12px;
    font-family: "JetBrains Mono", "Cascadia Code", "SF Mono", monospace; font-size: 13px;
    selection-background-color: #004858;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #006878; }
QComboBox::drop-down { border: none; padding-right: 8px; }
QComboBox QAbstractItemView { background: #0e1820; color: #c0dce8; border: 1px solid #1a2a30; selection-background-color: #004858; }
QPushButton {
    background: #0a2028; color: #00dde0; border: 1px solid #1a3a40;
    border-radius: 6px; padding: 10px 24px; font-weight: 600; font-size: 12px;
}
QPushButton:hover { background: #0e2830; border-color: #00dde0; }
QPushButton:pressed { background: #062020; }
QPushButton:disabled { color: #304048; border-color: #151e22; }
QPushButton#green { color: #00c868; border-color: #0a3020; background: #061a10; }
QPushButton#green:hover { border-color: #00c868; background: #0a2818; }
QPushButton#amber { color: #d0a020; border-color: #2a2010; background: #181200; }
QPushButton#amber:hover { border-color: #d0a020; background: #201800; }
QPushButton#small { padding: 8px 14px; font-size: 11px; }
QTextEdit {
    background: #060c10; color: #608898; border: 1px solid #1a2a30;
    border-radius: 6px; padding: 10px;
    font-family: "JetBrains Mono", "Cascadia Code", "SF Mono", monospace; font-size: 11px;
}
QProgressBar { background: #0e1820; border: none; border-radius: 3px; max-height: 6px; }
QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #00dde0,stop:1 #008090); border-radius: 3px; }
QCheckBox { color: #6a8898; spacing: 6px; font-size: 13px; }
QCheckBox::indicator { width: 16px; height: 16px; border-radius: 3px; border: 1px solid #1a3a40; background: #0e1820; }
QCheckBox::indicator:checked { background: #004858; border-color: #00dde0; }
QScrollArea { border: none; background: transparent; }
QStatusBar { background: #050a0e; color: #3a5868; font-size: 11px; border-top: 1px solid #1a2a30; }
QFrame#sep { background: #1a2a30; max-height: 1px; }
"""

def run_zupt(args, timeout=30):
    try:
        r = subprocess.run([ZUPT]+list(args), capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError: return -1, "", f"vaptvupt not found: {VAPTVUPT}\n\nDiscovery log:\n" + "\n".join(_DISCOVERY_LOG[-10:])
    except subprocess.TimeoutExpired: return -1, "", "Timed out"

class Worker(QObject):
    done = Signal(int, str, str)
    log = Signal(str)
    def __init__(self, args): super().__init__(); self.args = args
    def run(self):
        self.log.emit(f"$ {Path(VAPTVUPT).name} {' '.join(self.args)}")
        try:
            proc = subprocess.Popen([ZUPT]+self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            err_lines = []
            for line in proc.stderr:
                line = line.rstrip('\n')
                if line: err_lines.append(line); self.log.emit(line)
            stdout, _ = proc.communicate(timeout=7200)
            self.done.emit(proc.returncode, stdout or "", "\n".join(err_lines))
        except FileNotFoundError: self.done.emit(-1, "", f"vaptvupt not found: {VAPTVUPT}")
        except subprocess.TimeoutExpired: proc.kill(); self.done.emit(-1, "", "Timed out")

# ── Widgets ──

def H(text):
    lbl = QLabel(text.upper())
    lbl.setStyleSheet("font-size:10px;font-weight:700;color:#3a5868;letter-spacing:1.5px;")
    return lbl

def Sep():
    f = QFrame(); f.setObjectName("sep"); f.setFixedHeight(1); return f

def Log(h=150):
    t = QTextEdit(); t.setReadOnly(True); t.setMaximumHeight(h); return t

def PwField(ph="Optional"):
    pw = QLineEdit(); pw.setEchoMode(QLineEdit.EchoMode.Password); pw.setPlaceholderText(ph); return pw

class PathField(QWidget):
    def __init__(self, ph="", mode="open", filters="All Files (*)"):
        super().__init__()
        self.mode, self.filters = mode, filters
        self.setAcceptDrops(True)
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(6)
        self.edit = QLineEdit(); self.edit.setPlaceholderText(ph)
        lay.addWidget(self.edit, 1)
        btn = QPushButton("Browse"); btn.setObjectName("small"); btn.setFixedWidth(70)
        btn.clicked.connect(self._pick); lay.addWidget(btn)

    def _pick(self):
        if self.mode == "save": p, _ = QFileDialog.getSaveFileName(self, "Save", "", self.filters)
        elif self.mode == "dir": p = QFileDialog.getExistingDirectory(self, "Directory")
        elif self.mode == "multi":
            ps, _ = QFileDialog.getOpenFileNames(self, "Select", "", self.filters)
            p = "|".join(ps) if ps else ""
        else: p, _ = QFileDialog.getOpenFileName(self, "Open", "", self.filters)
        if p: self.edit.setText(p)

    def path(self): return self.edit.text().strip()
    def paths(self):
        t = self.path(); return t.split("|") if "|" in t else [t] if t else []
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()
    def dropEvent(self, e):
        ps = [u.toLocalFile() for u in e.mimeData().urls() if u.toLocalFile()]
        if ps: self.edit.setText("|".join(ps) if self.mode == "multi" else ps[0])

def scrollable(w):
    sa = QScrollArea(); sa.setWidgetResizable(True); sa.setWidget(w); sa.setFrameShape(QFrame.Shape.NoFrame); return sa

def run_async(parent, cmd, btn, log, progress=None, info=None):
    log.clear()
    if info:  # e.g. an auto-detect note; appended AFTER the clear so it survives
        log.append(info)
    btn.setEnabled(False)
    if progress: progress.show()
    t = QThread(); w = Worker(cmd); w.moveToThread(t)
    # log.append targets a main-thread QObject -> Qt queues it to the GUI thread.
    w.log.connect(log.append)
    # Keep a LIST of live (thread, worker) refs on the parent. Tabs with more
    # than one action button (Disk: backup + restore) previously shared a
    # single _thread/_worker slot, so starting a second op dropped the only
    # Python reference to the first still-running QThread — Python GC'd it
    # mid-run and aborted the operation. A list holds every in-flight thread.
    if not hasattr(parent, "_jobs"):
        parent._jobs = []
    parent._jobs.append((t, w))
    def finish(code, out, err):
        btn.setEnabled(True)
        if progress: progress.hide()
        log.append("\nDone." if code == 0 else f"\nFailed (exit {code}).")
        t.quit()
        parent._jobs = [(th, wk) for (th, wk) in parent._jobs if th is not t]
    # `done` is emitted from the worker thread and `finish` touches GUI widgets;
    # a bare functor would connect DirectConnection and run OFF the GUI thread.
    # QueuedConnection marshals it onto the GUI event loop.
    w.done.connect(finish, Qt.ConnectionType.QueuedConnection)
    t.started.connect(w.run); t.start()

# ── Tabs ──

class KeysTab(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)

        v.addWidget(QLabel("Generate or export post-quantum keys (ML-KEM-768)."))
        v.addWidget(Sep())

        # Key type governs both generate and export so the two stay consistent.
        v.addWidget(H("Key type"))
        self.mode = QComboBox()
        self._modes = pq_mode_options()
        for label, _tok in self._modes:
            self.mode.addItem(label)
        self.mode.setToolTip("Hybrid (--pq) is recommended. Full PQ (--pq-only) drops the\n"
                             "classical X25519 layer for PQ-only compliance postures. Both use\n"
                             "in-tree crypto and work on every build.")
        v.addWidget(self.mode)
        v.addWidget(Sep())

        # Section 1: Generate new keypair
        v.addWidget(H("Generate new keypair"))
        v.addWidget(QLabel("Writes a private key and its matching public key."))

        v.addWidget(H("Private key output"))
        self.gen_priv = PathField("e.g. ~/vaptvupt_private.key", "save", "Key (*.key);;All (*)")
        v.addWidget(self.gen_priv)
        v.addWidget(H("Public key output"))
        self.gen_pub = PathField("e.g. ~/vaptvupt_public.key", "save", "Key (*.key);;All (*)")
        v.addWidget(self.gen_pub)

        self.gen_btn = QPushButton("Generate Keypair")
        self.gen_btn.clicked.connect(self._generate)
        v.addWidget(self.gen_btn)
        self.gen_log = Log(120); v.addWidget(self.gen_log)

        v.addWidget(Sep())

        # Section 2: Export public key from existing private key
        v.addWidget(H("Export public key from private key"))
        v.addWidget(QLabel("Extract the public key from an existing private key file "
                           "(uses the key type selected above)."))

        v.addWidget(H("Existing private key"))
        self.exp_priv = PathField("Select private key", "open", "Key (*.key);;All (*)")
        v.addWidget(self.exp_priv)

        v.addWidget(H("Public key output"))
        self.exp_pub = PathField("e.g. ~/vaptvupt_public.key", "save", "Key (*.key);;All (*)")
        v.addWidget(self.exp_pub)

        self.exp_btn = QPushButton("Export Public Key")
        self.exp_btn.setObjectName("green")
        self.exp_btn.clicked.connect(self._export)
        v.addWidget(self.exp_btn)
        self.exp_log = Log(100); v.addWidget(self.exp_log)

        v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))

    def _token(self):
        return self._modes[self.mode.currentIndex()][1]

    def _default_pub(self, priv):
        return (priv.rsplit(".", 1)[0] + "_public.key") if "." in priv else priv + ".pub"

    def _generate(self):
        p = self.gen_priv.path() or str(Path.home() / "vaptvupt_private.key")
        self.gen_priv.edit.setText(p)
        pub = self.gen_pub.path() or self._default_pub(p)
        self.gen_pub.edit.setText(pub)
        tok = self._token()
        kflags, _ = _PQ_FLAG[tok]
        self.gen_log.clear(); self.gen_btn.setEnabled(False)
        if tok == "sdk":
            # SDK keygen writes the private key and <priv>.pub in one step.
            code, _, err = run_zupt(["keygen", "--sdk", "-o", p])
            self.gen_log.append(err.strip())
            self.gen_log.append(f"\nPrivate key:  {p}\nPublic key:   {p}.pub" if code == 0 else "\nFailed.")
        else:
            code, _, err = run_zupt(["keygen"] + kflags + ["-o", p])
            self.gen_log.append(err.strip())
            if code == 0:
                c2, _, e2 = run_zupt(["keygen", "--pub"] + kflags + ["-o", pub, "-k", p])
                self.gen_log.append(e2.strip())
                self.gen_log.append(f"\nPrivate key:  {p}\nPublic key:   {pub}" if c2 == 0 else "\nFailed to export public key.")
            else:
                self.gen_log.append("\nFailed.")
        self.gen_btn.setEnabled(True)

    def _export(self):
        priv = self.exp_priv.path()
        pub = self.exp_pub.path()
        if not priv: QMessageBox.warning(self, "VaptVupt", "Select the private key file."); return
        if not pub:
            pub = self._default_pub(priv); self.exp_pub.edit.setText(pub)
        tok = self._token()
        kflags, _ = _PQ_FLAG[tok]
        self.exp_log.clear(); self.exp_btn.setEnabled(False)
        code, _, err = run_zupt(["keygen", "--pub"] + kflags + ["-o", pub, "-k", priv])
        self.exp_log.append(err.strip())
        self.exp_log.append(f"\nPublic key:  {pub}" if code == 0 else "\nFailed.")
        self.exp_btn.setEnabled(True)


class CompressTab(QWidget):
    def __init__(self, initial=None):
        super().__init__()
        self._thread = self._worker = None
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)
        v.addWidget(QLabel("Compress files into an encrypted .zupt archive."))
        v.addWidget(Sep())
        v.addWidget(H("Source files / directory"))
        self.src = PathField("Drop files here or browse", "multi"); v.addWidget(self.src)
        v.addWidget(H("Output archive"))
        self.dst = PathField("e.g. backup.zupt", "save", "VaptVupt archive (*.zupt);;All (*)"); v.addWidget(self.dst)
        row = QHBoxLayout(); row.setSpacing(16)
        for label, widget in [("Codec", self._mk_codec()), ("Level", self._mk_level())]:
            c = QVBoxLayout(); c.addWidget(H(label)); c.addWidget(widget); row.addLayout(c)
        c = QVBoxLayout(); c.addWidget(H("Options"))
        self.dedup = QCheckBox("Dedup"); self.solid = QCheckBox("Solid")
        oh = QHBoxLayout(); oh.addWidget(self.dedup); oh.addWidget(self.solid); oh.addStretch()
        c.addLayout(oh); row.addLayout(c)
        v.addLayout(row); v.addWidget(Sep())
        enc = QHBoxLayout(); enc.setSpacing(16)
        pw = QVBoxLayout(); pw.addWidget(H("Password")); self.pw = PwField("AES-256"); pw.addWidget(self.pw); enc.addLayout(pw)
        pq = QVBoxLayout(); pq.addWidget(H("PQ public key")); self.pq = PathField("Optional .key", filters="Key (*.key *.pub);;All (*)"); pq.addWidget(self.pq); enc.addLayout(pq)
        mode_box = QVBoxLayout(); mode_box.addWidget(H("PQ mode"))
        self.pqmode = QComboBox()
        self._pqmodes = pq_mode_options()
        for label, _tok in self._pqmodes:
            self.pqmode.addItem(label)
        self.pqmode.setToolTip("Applies when a PQ public key is set. Must match the key type\n"
                               "you generated. Hybrid (--pq) is recommended.")
        mode_box.addWidget(self.pqmode); mode_box.addStretch(); enc.addLayout(mode_box)
        v.addLayout(enc)
        self.btn = QPushButton("Compress"); self.btn.clicked.connect(self._run); v.addWidget(self.btn)
        self.progress = QProgressBar(); self.progress.setRange(0,0); self.progress.hide(); v.addWidget(self.progress)
        self.log = Log(140); v.addWidget(self.log); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))
        if initial: self.src.edit.setText("|".join(initial))

    def _mk_codec(self):
        self.codec = QComboBox(); self.codec.addItems(["AUTO","VaptVupt","LZHP","Store"]); return self.codec
    def _mk_level(self):
        self.level = QSpinBox(); self.level.setRange(1,9); self.level.setValue(7); return self.level

    def _run(self):
        srcs = self.src.paths()
        if not srcs or not srcs[0]: QMessageBox.warning(self, "VaptVupt", "Select files."); return
        dst = self.dst.path() or srcs[0] + ".zupt"; self.dst.edit.setText(dst)
        cmd = ["compress", "-l", str(self.level.value())]
        cm = {"AUTO": None, "VaptVupt": "--vv", "LZHP": "--lzhp", "Store": "-s"}
        if cm.get(self.codec.currentText()): cmd.append(cm[self.codec.currentText()])
        if self.dedup.isChecked(): cmd.append("--dedup")
        if self.solid.isChecked(): cmd.append("--solid")
        if self.pw.text(): cmd += ["-p", self.pw.text()]
        if self.pq.path():
            tok = self._pqmodes[self.pqmode.currentIndex()][1]
            _, flag = _PQ_FLAG[tok]
            cmd += [flag, self.pq.path()]
        cmd.append(dst); cmd.extend(srcs)
        run_async(self, cmd, self.btn, self.log, self.progress)


class ExtractTab(QWidget):
    def __init__(self, initial=None):
        super().__init__()
        self._thread = self._worker = None
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)
        v.addWidget(QLabel("Extract and decrypt a .zupt archive."))
        v.addWidget(Sep())
        v.addWidget(H("Archive")); self.arc = PathField("Drop .zupt here", filters="VaptVupt archive (*.zupt);;All (*)"); v.addWidget(self.arc)
        v.addWidget(H("Output directory")); self.out = PathField("Same as archive", "dir"); v.addWidget(self.out)
        enc = QHBoxLayout(); enc.setSpacing(16)
        pw = QVBoxLayout(); pw.addWidget(H("Password")); self.pw = PwField(); pw.addWidget(self.pw); enc.addLayout(pw)
        pq = QVBoxLayout(); pq.addWidget(H("PQ private key")); self.pq = PathField("Optional .key", filters="Key (*.key);;All (*)"); pq.addWidget(self.pq); enc.addLayout(pq)
        mode_box = QVBoxLayout(); mode_box.addWidget(H("PQ mode"))
        self.pqmode = QComboBox()
        self._pqmodes = pq_mode_options(include_auto=True)
        for label, _tok in self._pqmodes:
            self.pqmode.addItem(label)
        self.pqmode.setToolTip("Auto-detect reads the archive header (vaptvupt info) to pick the\n"
                               "right mode. Or choose it explicitly to match your private key.")
        mode_box.addWidget(self.pqmode); mode_box.addStretch(); enc.addLayout(mode_box)
        v.addLayout(enc)
        self.btn = QPushButton("Extract"); self.btn.setObjectName("green"); self.btn.clicked.connect(self._run); v.addWidget(self.btn)
        self.progress = QProgressBar(); self.progress.setRange(0,0); self.progress.hide(); v.addWidget(self.progress)
        self.log = Log(140); v.addWidget(self.log); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))
        if initial: self.arc.edit.setText(initial)

    def _run(self):
        arc = self.arc.path()
        if not arc: QMessageBox.warning(self, "VaptVupt", "Select an archive."); return
        cmd = ["extract"]
        info = None
        if self.out.path(): cmd += ["-o", self.out.path()]
        if self.pw.text(): cmd += ["-p", self.pw.text()]
        if self.pq.path():
            tok = self._pqmodes[self.pqmode.currentIndex()][1]
            if tok == "auto":
                # The private-key format must match how the archive was encrypted;
                # inspect the header (vaptvupt info) to choose the right flag.
                tok = _detect_archive_pq(arc) or "pq"
                info = f"[auto-detect] using {_PQ_FLAG[tok][1]}"
            _, flag = _PQ_FLAG[tok]
            cmd += [flag, self.pq.path()]
        cmd.append(arc)
        run_async(self, cmd, self.btn, self.log, self.progress, info=info)


class VerifyTab(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)
        v.addWidget(QLabel("Verify checksums or inspect archive metadata."))
        v.addWidget(Sep())
        v.addWidget(H("Verify integrity"))
        self.varc = PathField("Archive to verify", filters="VaptVupt archive (*.zupt);;All (*)"); v.addWidget(self.varc)
        enc = QHBoxLayout(); enc.setSpacing(16)
        pw = QVBoxLayout(); pw.addWidget(H("Password (if encrypted)")); self.vpw = PwField("Leave empty if not encrypted"); pw.addWidget(self.vpw); enc.addLayout(pw)
        pq = QVBoxLayout(); pq.addWidget(H("PQ private key")); self.vpq = PathField("For --pq / --pq-only archives", filters="Key (*.key);;All (*)"); pq.addWidget(self.vpq); enc.addLayout(pq)
        mode_box = QVBoxLayout(); mode_box.addWidget(H("PQ mode"))
        self.vpqmode = QComboBox()
        self._vpqmodes = pq_mode_options(include_auto=True)
        for label, _tok in self._vpqmodes:
            self.vpqmode.addItem(label)
        mode_box.addWidget(self.vpqmode); mode_box.addStretch(); enc.addLayout(mode_box)
        v.addLayout(enc)
        self.vbtn = QPushButton("Verify"); self.vbtn.setObjectName("amber"); self.vbtn.clicked.connect(self._verify); v.addWidget(self.vbtn)
        self.vlog = Log(120); v.addWidget(self.vlog)
        v.addWidget(Sep())
        v.addWidget(H("Archive info (no password needed)"))
        self.iarc = PathField("Archive to inspect", filters="VaptVupt archive (*.zupt);;All (*)"); v.addWidget(self.iarc)
        self.ibtn = QPushButton("Show Info"); self.ibtn.clicked.connect(self._info); v.addWidget(self.ibtn)
        self.ilog = Log(140); v.addWidget(self.ilog); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))

    def _verify(self):
        arc = self.varc.path()
        if not arc: return
        cmd = ["test"]
        if self.vpw.text(): cmd += ["-p", self.vpw.text()]
        self.vlog.clear()
        if self.vpq.path():
            tok = self._vpqmodes[self.vpqmode.currentIndex()][1]
            if tok == "auto":
                tok = _detect_archive_pq(arc) or "pq"
                self.vlog.append(f"[auto-detect] using {_PQ_FLAG[tok][1]}")
            _, flag = _PQ_FLAG[tok]
            cmd += [flag, self.vpq.path()]
        cmd.append(arc)
        code, out, err = run_zupt(cmd, timeout=600)
        self.vlog.append((err + "\n" + out).strip())
        self.vlog.append("\nAll checksums passed." if code == 0 else "\nVerification failed.")

    def _info(self):
        arc = self.iarc.path()
        if not arc: return
        self.ilog.clear()
        code, out, err = run_zupt(["info", arc])
        self.ilog.append(out.strip() if out.strip() else err.strip())


class DiskTab(QWidget):
    def __init__(self):
        super().__init__()
        self._thread = self._worker = None
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)
        v.addWidget(QLabel("Full-disk or partition backup and restore."))
        v.addWidget(Sep())
        v.addWidget(H("Backup — source device or image"))
        self.bsrc = PathField("/dev/sdX or disk.img"); v.addWidget(self.bsrc)
        v.addWidget(H("Backup — output archive"))
        self.bout = PathField("backup.zupt", "save", "VaptVupt archive (*.zupt);;All (*)"); v.addWidget(self.bout)
        bopt = QHBoxLayout(); bopt.setSpacing(16)
        oc = QVBoxLayout(); oc.addWidget(H("Options")); self.bdedup = QCheckBox("Block deduplication"); oc.addWidget(self.bdedup); bopt.addLayout(oc)
        pc = QVBoxLayout(); pc.addWidget(H("Password")); self.bpw = PwField("Optional — AES-256"); pc.addWidget(self.bpw); bopt.addLayout(pc)
        v.addLayout(bopt)
        self.bbtn = QPushButton("Start Backup"); self.bbtn.clicked.connect(self._backup); v.addWidget(self.bbtn)
        self.blog = Log(100); v.addWidget(self.blog)
        v.addWidget(Sep())
        v.addWidget(H("Restore — archive"))
        self.rarc = PathField("backup.zupt", filters="VaptVupt archive (*.zupt);;All (*)"); v.addWidget(self.rarc)
        v.addWidget(H("Restore — target device or file"))
        self.rtgt = PathField("/dev/sdX or output.img", "save"); v.addWidget(self.rtgt)
        v.addWidget(H("Restore — password"))
        self.rpw = PwField("If archive is encrypted"); v.addWidget(self.rpw)
        self.rbtn = QPushButton("Start Restore"); self.rbtn.setObjectName("green"); self.rbtn.clicked.connect(self._restore); v.addWidget(self.rbtn)
        self.rlog = Log(100); v.addWidget(self.rlog); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))

    def _backup(self):
        s, o = self.bsrc.path(), self.bout.path()
        if not s or not o: QMessageBox.warning(self, "VaptVupt", "Set source and output."); return
        cmd = ["disk", "backup"]
        if self.bdedup.isChecked(): cmd.append("--dedup")
        if self.bpw.text(): cmd += ["-p", self.bpw.text()]
        cmd += [o, s]; run_async(self, cmd, self.bbtn, self.blog)

    def _restore(self):
        a, t = self.rarc.path(), self.rtgt.path()
        if not a or not t: QMessageBox.warning(self, "VaptVupt", "Set archive and target."); return
        SB = QMessageBox.StandardButton
        if QMessageBox.warning(self, "Confirm", f"OVERWRITE {t}?", SB.Yes|SB.Cancel) != SB.Yes: return
        cmd = ["disk", "restore"]
        if self.rpw.text(): cmd += ["-p", self.rpw.text()]
        cmd += [a, t]; run_async(self, cmd, self.rbtn, self.rlog)


class AboutTab(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(4)
        for text, style in [
            ("VAPTVUPT", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            (ZUPT_VER_NUMBER, "color:white;font-size:28px;font-weight:800;font-family:monospace;"),
            ("", ""),
            ("Post-quantum backup compression with ML-KEM-768: --pq hybrid", "color:#6a8898;font-size:13px;"),
            (f"(+ X25519) or --pq-only (pure). {DEFAULT_KDF} password KDF,", "color:#6a8898;font-size:13px;"),
            ("block deduplication, and full-disk backup.", "color:#6a8898;font-size:13px;"),
            ("Renamed from Zupt in v3.0.0 (INPI Brasil trademark); .zupt", "color:#6a8898;font-size:13px;"),
            ("archive extension and v1.6 wire format are unchanged.", "color:#6a8898;font-size:13px;"),
            ("", ""),
            ("CRYPTOGRAPHIC STACK", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("ML-KEM-768     FIPS 203     Post-Quantum KEM", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("X25519         RFC 7748     Elliptic Curve DH (hybrid w/ ML-KEM)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("AES-256-CTR    FIPS 197     Symmetric Cipher (fresh per-block nonce)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("HMAC-SHA256    RFC 2104     Authentication (Encrypt-then-MAC)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("PBKDF2-SHA256  RFC 8018     Password KDF (default, 600k iterations)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("Argon2id       RFC 9106     Password KDF (WITH_SDK=1 builds only)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("SHA3-512       FIPS 202     PQ key derivation (--pq / --pq-only)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("HKDF           RFC 5869     Key Derivation Function", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("SHA3/SHAKE     FIPS 202     Hash / XOF", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("XXH64          (non-crypto) Per-block checksum (inside AEAD)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("", ""),
            ("COMPRESSION CODEC", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("VaptVupt LZ + ANS  2.60.4  LZ77 + tabled ANS entropy", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("AVX2 / NEON SIMD acceleration; CBMC-verified BCJ filters", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("", ""),
            ("CREDITS", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("VaptVupt application                    Cristian Cezar Moisés", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("    License: AGPL-3.0-or-later (commercial license available)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("    git.securityops.co/cristiancmoises/vaptvupt", "color:#3a5868;font-size:11px;font-family:monospace;"),
            ("", ""),
            ("VaptVupt LZ + ANS codec                 Cristian Cezar Moisés", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("    License: GPL-3.0-or-later (commercial license available)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("    git.securityops.co/cristiancmoises/vaptvupt", "color:#3a5868;font-size:11px;font-family:monospace;"),
            ("", ""),
            ("WEBSITE & CONTACT", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("https://zupt.securityops.co", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("sac@securityops.co  (commercial licensing)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("zupt@riseup.net     (general / bugs)", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("", ""),
            (ZUPT_VER_SHORT, "color:#3a5868;font-size:11px;font-family:monospace;"),
        ]:
            lbl = QLabel(text)
            if text == "": lbl.setFixedHeight(10)
            elif style: lbl.setStyleSheet(style)
            v.addWidget(lbl)
        v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))


# ── Main ──

class ZuptWindow(QMainWindow):
    def __init__(self, compress_files=None, extract_file=None):
        super().__init__()
        self.setWindowTitle(f"VaptVupt {ZUPT_VER_NUMBER}")
        self.setMinimumSize(720, 500)
        self.resize(880, 640)
        self.setAcceptDrops(True)

        # Window icon
        if ICON_PATH:
            self.setWindowIcon(QIcon(ICON_PATH))

        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)

        # Header
        hdr = QFrame(); hdr.setStyleSheet("background:#050a0e;border-bottom:1px solid #1a2a30;")
        hl = QHBoxLayout(hdr); hl.setContentsMargins(20,10,20,10)
        title = QLabel("VAPTVUPT"); title.setStyleSheet("color:white;font-size:15px;font-weight:800;letter-spacing:3px;")
        hl.addWidget(title)
        sub = QLabel("Post-Quantum Backup"); sub.setStyleSheet("color:#3a5868;font-size:10px;font-weight:600;letter-spacing:1px;margin-left:8px;")
        hl.addWidget(sub); hl.addStretch()
        vl = QLabel(f"v{ZUPT_VER_NUMBER}"); vl.setStyleSheet("color:#3a5868;font-size:10px;font-family:monospace;background:#0a1018;padding:3px 10px;border-radius:4px;border:1px solid #1a2a30;")
        hl.addWidget(vl)
        layout.addWidget(hdr)

        # Tabs
        self.tabs = QTabWidget()
        self.compress_tab = CompressTab(initial=compress_files)
        self.extract_tab = ExtractTab(initial=extract_file)
        self.tabs.addTab(KeysTab(), "Keys")
        self.tabs.addTab(self.compress_tab, "Compress")
        self.tabs.addTab(self.extract_tab, "Extract")
        self.tabs.addTab(VerifyTab(), "Verify")
        self.tabs.addTab(DiskTab(), "Disk")
        self.tabs.addTab(AboutTab(), "About")
        if compress_files: self.tabs.setCurrentIndex(1)
        elif extract_file: self.tabs.setCurrentIndex(2)
        layout.addWidget(self.tabs)

        sb = QStatusBar()
        sb.showMessage(f"VaptVupt {ZUPT_VER_NUMBER}  |  {VAPTVUPT}")
        self.setStatusBar(sb)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()
    def dropEvent(self, e):
        ps = [u.toLocalFile() for u in e.mimeData().urls() if u.toLocalFile()]
        if not ps: return
        if ps[0].endswith(".zupt"):
            self.extract_tab.arc.edit.setText(ps[0]); self.tabs.setCurrentIndex(2)
        else:
            self.compress_tab.src.edit.setText("|".join(ps)); self.tabs.setCurrentIndex(1)


def main():
    args = sys.argv[1:]

    # Lightweight non-GUI flags first, so `vaptvupt-gui --version|--help|--selftest`
    # work with no display and aren't mistaken for files to compress. `--selftest`
    # is a headless-friendly smoke test: it builds the whole UI and spins the event
    # loop once, then exits 0 — the reliable way to confirm the GUI stack launches
    # on a machine where the window itself is hard to see (tiling WM, remote, CI).
    if args and args[0] in ("--version", "-V", "version"):
        print(f"vaptvupt-gui {ZUPT_VER_NUMBER} ({QT_BINDING})  |  CLI: {VAPTVUPT}")
        return 0
    if args and args[0] in ("--help", "-h", "help"):
        print("usage: vaptvupt-gui [ARCHIVE.zupt | --extract ARCHIVE.zupt |\n"
              "                     --compress FILE [FILE ...]]\n"
              "       vaptvupt-gui --selftest   # verify the GUI launches (no window kept)\n"
              "       vaptvupt-gui --version")
        return 0

    compress_files = extract_file = None
    selftest = ("--selftest" in args[:1])
    if args and not selftest:
        if args[0] == "--compress" and len(args) > 1: compress_files = args[1:]
        elif args[0] == "--extract" and len(args) > 1: extract_file = args[1]
        elif args[0].endswith(".zupt"): extract_file = args[0]
        else: compress_files = args

    app = QApplication(sys.argv)
    app.setApplicationName("VaptVupt")
    if ICON_PATH: app.setWindowIcon(QIcon(ICON_PATH))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    pal = QPalette()
    # PyQt6 requires scoped enums (QPalette.ColorRole.Window); PySide6 supports
    # both forms but we use the scoped form for cross-binding compatibility.
    CR = QPalette.ColorRole
    for role, c in [(CR.Window,"#0a0a0a"),(CR.WindowText,"#90acb8"),
        (CR.Base,"#0e1820"),(CR.Text,"#c0dce8"),
        (CR.Button,"#0a2028"),(CR.ButtonText,"#00dde0"),
        (CR.Highlight,"#004858"),(CR.HighlightedText,"#00dde0")]:
        pal.setColor(role, QColor(c))
    app.setPalette(pal)
    win = ZuptWindow(compress_files=compress_files, extract_file=extract_file)

    if selftest:
        win.show()
        QTimer.singleShot(400, app.quit)
        rc = app.exec()
        print(f"selftest OK — {QT_BINDING}: window + {win.tabs.count()} tabs built, "
              f"event loop ran (rc={rc}); CLI={VAPTVUPT}")
        return rc

    # Center + raise + focus ONLY on X11 (xcb), where a stacking WM may place
    # the window off-screen or leave it unfocused. On Wayland the compositor
    # owns placement and focus, and these calls (self-move / xdg restack /
    # xdg-activation) SEGFAULT some Qt-Wayland builds — including PySide6 6.9 as
    # shipped on Guix — so they must not run there. Plain show() is what
    # --selftest exercises and is stable; the compositor maps and focuses the
    # new toplevel itself. On Windows/macOS Qt's automatic placement centers
    # first windows and the OS foregrounds a freshly launched app, so skipping
    # is safe there too. Strict == "xcb" keeps wayland-egl etc. on the safe path.
    is_x11 = app.platformName() == "xcb"
    if is_x11:
        scr = app.primaryScreen()
        if scr is not None:
            fg = win.frameGeometry()
            fg.moveCenter(scr.availableGeometry().center())
            win.move(fg.topLeft())
    win.show()
    if is_x11:
        win.raise_()
        win.activateWindow()

    # A GUI blocks the launching shell, so a working launch otherwise looks like
    # a "stuck" terminal. Emit one line to stderr so it's unambiguous. Guarded:
    # PyInstaller --windowed sets sys.stderr to None (any write would raise and
    # kill the window we just showed), and a dead pipe raises OSError on flush —
    # a courtesy notice must never take the GUI down.
    if sys.stderr is not None:
        try:
            sys.stderr.write(f"VaptVupt {ZUPT_VER_NUMBER} GUI started — "
                             f"window open (close it to exit).\n")
            sys.stderr.flush()
        except OSError:
            pass
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
