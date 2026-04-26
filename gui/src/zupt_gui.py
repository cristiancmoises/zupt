#!/usr/bin/env python3
"""Zupt GUI — Cross-Platform Post-Quantum Backup. Requires PySide6."""
import sys, os, subprocess, shutil
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QComboBox, QFileDialog,
    QTextEdit, QProgressBar, QTabWidget, QFrame, QCheckBox,
    QSpinBox, QMessageBox, QStatusBar, QScrollArea
)
from PySide6.QtCore import Qt, Signal, QObject, QThread
from PySide6.QtGui import QPalette, QColor, QIcon, QPixmap

# ── Find zupt binary ──
def _find_zupt():
    if os.environ.get("ZUPT_BIN") and os.path.isfile(os.environ["ZUPT_BIN"]):
        return os.environ["ZUPT_BIN"]
    # Check local project tree FIRST (handles running from zupt-2.1.6/gui/)
    here = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))
    for c in [here.parent.parent/"zupt",      # zupt-2.1.6/gui/src -> zupt-2.1.6/zupt
              here.parent/"zupt",              # zupt-2.1.6/gui -> zupt-2.1.6/zupt (shouldn't happen but safe)
              here/"zupt",                     # same dir as script
              here.parent.parent/"zupt.exe",
              here.parent/"zupt.exe",
              here/"zupt.exe"]:
        if c.is_file() and os.access(str(c), os.X_OK):
            return str(c.resolve())
    # Then system PATH
    found = shutil.which("zupt")
    if found: return found
    # Fallback common paths
    for c in [Path("/usr/local/bin/zupt"), Path("/usr/bin/zupt")]:
        if c.is_file(): return str(c)
    return "zupt"

ZUPT = _find_zupt()

# ── Query version ONCE at import (cached) ──
def _get_version():
    try:
        r = subprocess.run([ZUPT, "version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            lines = r.stdout.strip().split("\n")
            return lines[0], r.stdout.strip()
    except Exception: pass
    return "zupt (not found)", ""

ZUPT_VER_SHORT, ZUPT_VER_FULL = _get_version()

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
    except FileNotFoundError: return -1, "", f"zupt not found: {ZUPT}"
    except subprocess.TimeoutExpired: return -1, "", "Timed out"

class Worker(QObject):
    done = Signal(int, str, str)
    log = Signal(str)
    def __init__(self, args): super().__init__(); self.args = args
    def run(self):
        self.log.emit(f"$ zupt {' '.join(self.args)}")
        try:
            proc = subprocess.Popen([ZUPT]+self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            err_lines = []
            for line in proc.stderr:
                line = line.rstrip('\n')
                if line: err_lines.append(line); self.log.emit(line)
            stdout, _ = proc.communicate(timeout=7200)
            self.done.emit(proc.returncode, stdout or "", "\n".join(err_lines))
        except FileNotFoundError: self.done.emit(-1, "", f"zupt not found: {ZUPT}")
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
    pw = QLineEdit(); pw.setEchoMode(QLineEdit.Password); pw.setPlaceholderText(ph); return pw

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
    sa = QScrollArea(); sa.setWidgetResizable(True); sa.setWidget(w); sa.setFrameShape(QFrame.NoFrame); return sa

def run_async(parent, cmd, btn, log, progress=None):
    log.clear(); btn.setEnabled(False)
    if progress: progress.show()
    t = QThread(); w = Worker(cmd); w.moveToThread(t)
    w.log.connect(log.append)
    def finish(code, out, err):
        btn.setEnabled(True)
        if progress: progress.hide()
        log.append("\nDone." if code == 0 else f"\nFailed (exit {code}).")
        t.quit()
    w.done.connect(finish)
    t.started.connect(w.run); t.start()
    parent._thread, parent._worker = t, w

# ── Tabs ──

class KeysTab(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)

        v.addWidget(QLabel("Generate or export ML-KEM-768 + X25519 hybrid keys."))
        v.addWidget(Sep())

        # Section 1: Generate new keypair
        v.addWidget(H("Generate new keypair"))
        v.addWidget(QLabel("Creates both private and public key files."))

        v.addWidget(H("Private key output"))
        self.gen_priv = PathField("e.g. ~/zupt_private.key", "save", "Key (*.key);;All (*)")
        v.addWidget(self.gen_priv)

        self.gen_btn = QPushButton("Generate Keypair")
        self.gen_btn.clicked.connect(self._generate)
        v.addWidget(self.gen_btn)
        self.gen_log = Log(120); v.addWidget(self.gen_log)

        v.addWidget(Sep())

        # Section 2: Export public key from existing private key
        v.addWidget(H("Export public key from private key"))
        v.addWidget(QLabel("Extract the public key from an existing private key file."))

        v.addWidget(H("Existing private key"))
        self.exp_priv = PathField("Select private key", "open", "Key (*.key);;All (*)")
        v.addWidget(self.exp_priv)

        v.addWidget(H("Public key output"))
        self.exp_pub = PathField("e.g. ~/zupt_public.key", "save", "Key (*.key);;All (*)")
        v.addWidget(self.exp_pub)

        self.exp_btn = QPushButton("Export Public Key")
        self.exp_btn.setObjectName("green")
        self.exp_btn.clicked.connect(self._export)
        v.addWidget(self.exp_btn)
        self.exp_log = Log(100); v.addWidget(self.exp_log)

        v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))

    def _generate(self):
        p = self.gen_priv.path() or str(Path.home() / "zupt_private.key")
        self.gen_priv.edit.setText(p)
        self.gen_log.clear(); self.gen_btn.setEnabled(False)
        code, _, err = run_zupt(["keygen", "-o", p])
        self.gen_log.append(err.strip())
        if code == 0:
            pub = p.rsplit(".", 1)[0] + "_public.key" if "." in p else p + ".pub"
            c2, _, e2 = run_zupt(["keygen", "--pub", "-o", pub, "-k", p])
            self.gen_log.append(e2.strip())
            if c2 == 0:
                self.gen_log.append(f"\nPrivate key:  {p}\nPublic key:   {pub}")
        else:
            self.gen_log.append("\nFailed.")
        self.gen_btn.setEnabled(True)

    def _export(self):
        priv = self.exp_priv.path()
        pub = self.exp_pub.path()
        if not priv: QMessageBox.warning(self, "Zupt", "Select the private key file."); return
        if not pub:
            pub = priv.rsplit(".", 1)[0] + "_public.key" if "." in priv else priv + ".pub"
            self.exp_pub.edit.setText(pub)
        self.exp_log.clear(); self.exp_btn.setEnabled(False)
        code, _, err = run_zupt(["keygen", "--pub", "-o", pub, "-k", priv])
        self.exp_log.append(err.strip())
        if code == 0:
            self.exp_log.append(f"\nPublic key:  {pub}")
        else:
            self.exp_log.append("\nFailed.")
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
        self.dst = PathField("e.g. backup.zupt", "save", "Zupt (*.zupt);;All (*)"); v.addWidget(self.dst)
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
        pq = QVBoxLayout(); pq.addWidget(H("PQ public key")); self.pq = PathField("Optional .key", filters="Key (*.key);;All (*)"); pq.addWidget(self.pq); enc.addLayout(pq)
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
        if not srcs or not srcs[0]: QMessageBox.warning(self, "Zupt", "Select files."); return
        dst = self.dst.path() or srcs[0] + ".zupt"; self.dst.edit.setText(dst)
        cmd = ["compress", "-l", str(self.level.value())]
        cm = {"AUTO": None, "VaptVupt": "--vv", "LZHP": "--lzhp", "Store": "-s"}
        if cm.get(self.codec.currentText()): cmd.append(cm[self.codec.currentText()])
        if self.dedup.isChecked(): cmd.append("--dedup")
        if self.solid.isChecked(): cmd.append("--solid")
        if self.pw.text(): cmd += ["-p", self.pw.text()]
        if self.pq.path(): cmd += ["--pq", self.pq.path()]
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
        v.addWidget(H("Archive")); self.arc = PathField("Drop .zupt here", filters="Zupt (*.zupt);;All (*)"); v.addWidget(self.arc)
        v.addWidget(H("Output directory")); self.out = PathField("Same as archive", "dir"); v.addWidget(self.out)
        enc = QHBoxLayout(); enc.setSpacing(16)
        pw = QVBoxLayout(); pw.addWidget(H("Password")); self.pw = PwField(); pw.addWidget(self.pw); enc.addLayout(pw)
        pq = QVBoxLayout(); pq.addWidget(H("PQ private key")); self.pq = PathField("Optional .key", filters="Key (*.key);;All (*)"); pq.addWidget(self.pq); enc.addLayout(pq)
        v.addLayout(enc)
        self.btn = QPushButton("Extract"); self.btn.setObjectName("green"); self.btn.clicked.connect(self._run); v.addWidget(self.btn)
        self.progress = QProgressBar(); self.progress.setRange(0,0); self.progress.hide(); v.addWidget(self.progress)
        self.log = Log(140); v.addWidget(self.log); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))
        if initial: self.arc.edit.setText(initial)

    def _run(self):
        arc = self.arc.path()
        if not arc: QMessageBox.warning(self, "Zupt", "Select an archive."); return
        cmd = ["extract"]
        if self.out.path(): cmd += ["-o", self.out.path()]
        if self.pw.text(): cmd += ["-p", self.pw.text()]
        if self.pq.path(): cmd += ["--pq", self.pq.path()]
        cmd.append(arc)
        run_async(self, cmd, self.btn, self.log, self.progress)


class VerifyTab(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(10)
        v.addWidget(QLabel("Verify checksums or inspect archive metadata."))
        v.addWidget(Sep())
        v.addWidget(H("Verify integrity"))
        self.varc = PathField("Archive to verify", filters="Zupt (*.zupt);;All (*)"); v.addWidget(self.varc)
        v.addWidget(H("Password (if encrypted)"))
        self.vpw = PwField("Leave empty if not encrypted"); v.addWidget(self.vpw)
        self.vbtn = QPushButton("Verify"); self.vbtn.setObjectName("amber"); self.vbtn.clicked.connect(self._verify); v.addWidget(self.vbtn)
        self.vlog = Log(120); v.addWidget(self.vlog)
        v.addWidget(Sep())
        v.addWidget(H("Archive info (no password needed)"))
        self.iarc = PathField("Archive to inspect", filters="Zupt (*.zupt);;All (*)"); v.addWidget(self.iarc)
        self.ibtn = QPushButton("Show Info"); self.ibtn.clicked.connect(self._info); v.addWidget(self.ibtn)
        self.ilog = Log(140); v.addWidget(self.ilog); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))

    def _verify(self):
        arc = self.varc.path()
        if not arc: return
        cmd = ["test"]
        if self.vpw.text(): cmd += ["-p", self.vpw.text()]
        cmd.append(arc); self.vlog.clear()
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
        self.bout = PathField("backup.zupt", "save", "Zupt (*.zupt);;All (*)"); v.addWidget(self.bout)
        bopt = QHBoxLayout(); bopt.setSpacing(16)
        oc = QVBoxLayout(); oc.addWidget(H("Options")); self.bdedup = QCheckBox("Block deduplication"); oc.addWidget(self.bdedup); bopt.addLayout(oc)
        pc = QVBoxLayout(); pc.addWidget(H("Password")); self.bpw = PwField("Optional — AES-256"); pc.addWidget(self.bpw); bopt.addLayout(pc)
        v.addLayout(bopt)
        self.bbtn = QPushButton("Start Backup"); self.bbtn.clicked.connect(self._backup); v.addWidget(self.bbtn)
        self.blog = Log(100); v.addWidget(self.blog)
        v.addWidget(Sep())
        v.addWidget(H("Restore — archive"))
        self.rarc = PathField("backup.zupt", filters="Zupt (*.zupt);;All (*)"); v.addWidget(self.rarc)
        v.addWidget(H("Restore — target device or file"))
        self.rtgt = PathField("/dev/sdX or output.img", "save"); v.addWidget(self.rtgt)
        v.addWidget(H("Restore — password"))
        self.rpw = PwField("If archive is encrypted"); v.addWidget(self.rpw)
        self.rbtn = QPushButton("Start Restore"); self.rbtn.setObjectName("green"); self.rbtn.clicked.connect(self._restore); v.addWidget(self.rbtn)
        self.rlog = Log(100); v.addWidget(self.rlog); v.addStretch()
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(scrollable(inner))

    def _backup(self):
        s, o = self.bsrc.path(), self.bout.path()
        if not s or not o: QMessageBox.warning(self, "Zupt", "Set source and output."); return
        cmd = ["disk", "backup"]
        if self.bdedup.isChecked(): cmd.append("--dedup")
        if self.bpw.text(): cmd += ["-p", self.bpw.text()]
        cmd += [o, s]; run_async(self, cmd, self.bbtn, self.blog)

    def _restore(self):
        a, t = self.rarc.path(), self.rtgt.path()
        if not a or not t: QMessageBox.warning(self, "Zupt", "Set archive and target."); return
        if QMessageBox.warning(self, "Confirm", f"OVERWRITE {t}?", QMessageBox.Yes|QMessageBox.Cancel) != QMessageBox.Yes: return
        cmd = ["disk", "restore"]
        if self.rpw.text(): cmd += ["-p", self.rpw.text()]
        cmd += [a, t]; run_async(self, cmd, self.rbtn, self.rlog)


class AboutTab(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        v = QVBoxLayout(inner); v.setContentsMargins(24,24,24,24); v.setSpacing(4)
        # Extract version number from cached string
        ver_num = ZUPT_VER_SHORT.replace("zupt ", "").strip() if "zupt " in ZUPT_VER_SHORT else ZUPT_VER_SHORT
        for text, style in [
            ("ZUPT", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            (ver_num, "color:white;font-size:28px;font-weight:800;font-family:monospace;"),
            ("", ""),
            ("Post-quantum backup compression with ML-KEM-768 + X25519", "color:#6a8898;font-size:13px;"),
            ("hybrid encryption, hardware-adaptive codecs, and block dedup.", "color:#6a8898;font-size:13px;"),
            ("", ""),
            ("CRYPTOGRAPHIC STACK", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("ML-KEM-768     FIPS 203     Post-Quantum KEM", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("X25519         RFC 7748     Elliptic Curve DH", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("AES-256-CTR    FIPS 197     Symmetric Cipher", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("HMAC-SHA256    RFC 2104     Authentication", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("PBKDF2         RFC 8018     Key Derivation", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("SHA3/SHAKE     FIPS 202     Hash / XOF", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("", ""),
            ("CREDITS", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("zupt        Cristian Cezar Moises        AGPL-3.0", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("github.com/cristiancmoises/zupt", "color:#3a5868;font-size:11px;font-family:monospace;"),
            ("", ""),
            ("libzupt     Alessandro de Oliveira Faria  MIT", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("github.com/cabelo/libzupt", "color:#3a5868;font-size:11px;font-family:monospace;"),
            ("", ""),
            ("WEBSITE", "color:#00dde0;font-size:10px;font-weight:700;letter-spacing:2px;font-family:monospace;"),
            ("https://zupt.securityops.co", "color:#5a7a88;font-size:12px;font-family:monospace;"),
            ("zupt@riseup.net", "color:#5a7a88;font-size:12px;font-family:monospace;"),
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
        self.setWindowTitle(f"Zupt — {ZUPT_VER_SHORT}")
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
        title = QLabel("ZUPT"); title.setStyleSheet("color:white;font-size:15px;font-weight:800;letter-spacing:3px;")
        hl.addWidget(title)
        sub = QLabel("Post-Quantum Backup"); sub.setStyleSheet("color:#3a5868;font-size:10px;font-weight:600;letter-spacing:1px;margin-left:8px;")
        hl.addWidget(sub); hl.addStretch()
        ver_num = ZUPT_VER_SHORT.replace("zupt ", "v").strip()
        vl = QLabel(ver_num); vl.setStyleSheet("color:#3a5868;font-size:10px;font-family:monospace;background:#0a1018;padding:3px 10px;border-radius:4px;border:1px solid #1a2a30;")
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
        sb.showMessage(f"{ZUPT_VER_SHORT}  |  {ZUPT}")
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
    compress_files = extract_file = None
    args = sys.argv[1:]
    if args:
        if args[0] == "--compress" and len(args) > 1: compress_files = args[1:]
        elif args[0] == "--extract" and len(args) > 1: extract_file = args[1]
        elif args[0].endswith(".zupt"): extract_file = args[0]
        else: compress_files = args

    app = QApplication(sys.argv)
    app.setApplicationName("Zupt")
    if ICON_PATH: app.setWindowIcon(QIcon(ICON_PATH))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    pal = QPalette()
    for role, c in [(QPalette.Window,"#0a0a0a"),(QPalette.WindowText,"#90acb8"),
        (QPalette.Base,"#0e1820"),(QPalette.Text,"#c0dce8"),
        (QPalette.Button,"#0a2028"),(QPalette.ButtonText,"#00dde0"),
        (QPalette.Highlight,"#004858"),(QPalette.HighlightedText,"#00dde0")]:
        pal.setColor(role, QColor(c))
    app.setPalette(pal)
    win = ZuptWindow(compress_files=compress_files, extract_file=extract_file)
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
