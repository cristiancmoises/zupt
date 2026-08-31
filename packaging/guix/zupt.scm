;;; SPDX-License-Identifier: AGPL-3.0-or-later
;;; Copyright (c) 2026 Cristian Cezar Moisés
;;;
;;; GNU Guix package definitions for ZUPT (CLI + PySide6 GUI).
;;; Source-only build (no vendored libraries): the CLI links only libc/libm/
;;; pthread from the store.
;;;
;;; Install into your profile (additive; keeps everything else):
;;;     guix package -f packaging/guix/zupt.scm                ; installs the GUI
;;;     guix package -e '(@ (guix) …)'  — or, for the CLI on its own:
;;;     guix install -f packaging/guix/zupt.scm                ; (last expr = GUI)
;;; The last expression is the GUI, which carries the CLI as an input; to get
;;; the `zupt` command in your profile too, also run:
;;;     guix package --install-from-expression='(begin (load "packaging/guix/zupt.scm") zupt)'
;;;
;;; GUI-on-Guix note: PySide6's Qt6 links several leaf libraries (libGL from
;;; mesa, libxkbcommon, the X11/xcb family, libzstd, harfbuzz, icu, ...) that are
;;; NOT in its RUNPATH. The launcher therefore sets LD_LIBRARY_PATH to those
;;; libraries (see %gui-runtime-libs). Without this, `import PySide6.QtWidgets`
;;; fails with "libGL.so.1: cannot open shared object file" and the GUI prints
;;; "requires PySide6 or PyQt6". Qt's OWN libraries are intentionally excluded
;;; from LD_LIBRARY_PATH — they resolve via PySide6's RUNPATH; forcing a second
;;; copy causes Qt private-API symbol clashes.

(use-modules (guix packages)
             (guix download)
             (guix gexp)
             (guix utils)
             (guix build-system gnu)
             (guix build-system copy)
             ((guix licenses) #:prefix license:)
             (gnu packages python)     ; python
             (gnu packages qt)         ; python-pyside-6, python-shiboken-6, qtbase, qtwayland
             (gnu packages bash)       ; bash-minimal
             (gnu packages gl)         ; mesa (libGL)
             (gnu packages xdisorg)    ; libxkbcommon, pixman, mtdev
             (gnu packages fontutils)  ; fontconfig, freetype, graphite2
             (gnu packages xorg)       ; libX11 + xcb family, libxft, libevdev
             (gnu packages freedesktop); wayland, libinput-minimal
             (gnu packages glib)       ; glib, dbus
             (gnu packages compression); zlib, zstd, brotli
             (gnu packages image)      ; libpng, libjpeg-turbo
             (gnu packages xml)        ; expat, libxml2
             (gnu packages gtk)        ; harfbuzz
             (gnu packages icu4c)      ; icu4c
             (gnu packages maths)      ; double-conversion
             (gnu packages pcre)       ; pcre2
             (gnu packages markup)     ; md4c
             (gnu packages crypto)     ; libb2
             (gnu packages linux))     ; eudev (libudev)

;; Leaf runtime libraries PySide6's Qt6 (Core/Gui/Widgets) needs but that are
;; NOT in its RUNPATH. NEVER add qtbase/qtwayland here (see header note). These
;; already live in PySide6's closure, so referencing them adds no store size.
(define %gui-runtime-libs
  (list mesa libxkbcommon fontconfig freetype graphite2 harfbuzz
        icu4c double-conversion pcre2 md4c libb2 brotli
        libpng libjpeg-turbo zlib expat libxml2 pixman glib dbus wayland
        libx11 libxext libxrender libxcb libxrandr libxi libxcursor libxft
        libxfixes libxdamage libxcomposite libxtst libxinerama libsm libice
        libxau libxdmcp xcb-util xcb-util-image xcb-util-keysyms
        xcb-util-renderutil xcb-util-wm xcb-util-cursor
        libinput-minimal mtdev libevdev eudev))

(define %zupt-version "5.2.5")

(define %zupt-source
  (origin
    (method url-fetch)
    (uri (string-append
          "https://github.com/cristiancmoises/zupt"
          "/releases/download/v" %zupt-version
          "/zupt-" %zupt-version ".tar.gz"))
    (sha256
     (base32 "194vnvmmggc3h1r11rkkg395hpvh4dybs43674jcwawa855d71kv"))))

(define-public zupt
  (package
    (name "zupt")
    (version %zupt-version)
    (source %zupt-source)
    (build-system gnu-build-system)
    (arguments
     (list
      #:make-flags
      #~(list (string-append "PREFIX=" #$output)
              "WITH_SDK=0"
              "WITH_PQBOX=0"
              (string-append "CC=" #$(cc-for-target)))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)           ; plain Makefile, no ./configure
          (replace 'check
            ;; Self-contained NIST/RFC known-answer vectors (FIPS 180-4/202/203,
            ;; SP 800-38A, RFC 4231/7748) are the crypto gate.
            (lambda* (#:key tests? #:allow-other-keys)
              (when tests?
                (invoke "make" "WITH_SDK=0" "WITH_PQBOX=0"
                        (string-append "CC=" #$(cc-for-target))
                        "test-vectors")
                (invoke "./test_vectors")))))))
    (home-page "https://github.com/cristiancmoises/zupt")
    (synopsis "Post-quantum backup compression utility")
    (description
     "ZUPT is a pure-C11 backup compressor with native
post-quantum encryption.  Two in-tree PQ modes: @code{--pq} hybridizes
ML-KEM-768 with X25519 (recommended), and
@code{--pq-only} uses ML-KEM-768 alone for @dfn{PQ-only} compliance postures.
Payload protection is AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC with a fresh
random per-block nonce; AES-NI/SHA-NI dispatch at runtime; the bundled
VaptVupt 2.65.3 LZ+ANS codec has portable fallbacks.  Password mode uses
PBKDF2-SHA256.  The tool is
AGPL-3.0-or-later; the embedded codec is GPL-3.0-or-later; the two
xxHash-derived XXH64 units additionally carry BSD-2-Clause; and portions of
native ML-KEM adapted from pq-crystals/kyber carry CC0-1.0.  Native X25519
portions adapted from curve25519-donna retain BSD-3-Clause.
The x86 BCJ filter and SHA-NI path also record their public-domain LZMA SDK
and SHA-Intrinsics origins; installed NOTICE and THIRD-PARTY-NOTICES.md carry
the full provenance record.")
    (license (list license:agpl3+ license:gpl3+ license:bsd-2 license:bsd-3 license:cc0))))

(define-public zupt-gui
  (package
    (name "zupt-gui")
    (version %zupt-version)
    (source (package-source zupt))   ; same release tarball
    (build-system copy-build-system)
    (arguments
     (list
      #:install-plan
      #~'(("gui/src/zupt_gui.py" "lib/zupt-gui/")
          ("gui/assets/zupt-icon.png"
           "share/icons/hicolor/256x256/apps/zupt-gui.png")
          ("gui/README.md" "share/doc/zupt-gui/")
          ("LICENSE-AGPL-3.0"
           "share/licenses/zupt-gui/LICENSE-AGPL-3.0")
          ("gui/LICENSE-GUI"
           "share/licenses/zupt-gui/LICENSE-GUI")
          ("gui/assets/README.md"
           "share/licenses/zupt-gui/ASSET-PROVENANCE.md"))
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'install 'make-launcher
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let* ((out     (assoc-ref outputs "out"))
                     (bin     (string-append out "/bin"))
                     (gui     (string-append
                               out "/lib/zupt-gui/zupt_gui.py"))
                     (sh      (search-input-file inputs "/bin/sh"))
                     (python3 (search-input-file inputs "/bin/python3"))
                     (cli     (search-input-file inputs "/bin/zupt"))
                     (pyside  (assoc-ref inputs "python-pyside-6"))
                     (site    (car (find-files pyside "^site-packages$"
                                               #:directories? #t)))
                     ;; Shiboken6 is a SEPARATE package PySide6 imports at
                     ;; runtime; its site-packages must be on GUIX_PYTHONPATH too.
                     (shiboken (assoc-ref inputs "python-shiboken-6"))
                     (shsite  (car (find-files shiboken "^site-packages$"
                                               #:directories? #t)))
                     (qtbase  (assoc-ref inputs "qtbase"))
                     (qtwl    (assoc-ref inputs "qtwayland"))
                     ;; zstd ships libzstd.so.1 in its "lib" output (not "out").
                     (zstdlib (assoc-ref inputs "zstd"))
                     (ldpath (string-join
                              (append
                               (list #$@(map (lambda (p) (file-append p "/lib"))
                                             %gui-runtime-libs))
                               (list (string-append zstdlib "/lib")))
                              ":")))
                (mkdir-p bin)
                (call-with-output-file (string-append bin "/zupt-gui")
                  (lambda (port)
                    (format port "#!~a
export ZUPT_BIN=\"~a\"
export GUIX_PYTHONPATH=\"~a:~a${GUIX_PYTHONPATH:+:}$GUIX_PYTHONPATH\"
export QT_PLUGIN_PATH=\"~a/lib/qt6/plugins:~a/lib/qt6/plugins${QT_PLUGIN_PATH:+:}$QT_PLUGIN_PATH\"
export LD_LIBRARY_PATH=\"~a${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH\"
exec \"~a\" \"~a\" \"$@\"\n"
                            sh cli site shsite qtbase qtwl ldpath python3 gui)))
                (chmod (string-append bin "/zupt-gui") #o755))))
          (add-after 'make-launcher 'install-desktop-file
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out  (assoc-ref outputs "out"))
                     (apps (string-append out "/share/applications")))
                (mkdir-p apps)
                (call-with-output-file
                    (string-append apps "/zupt-gui.desktop")
                  (lambda (port)
                    (format port "[Desktop Entry]
Type=Application
Name=ZUPT
GenericName=Post-Quantum Backup
Comment=Compress, encrypt and restore .zupt archives
Exec=~a/bin/zupt-gui %F
Icon=zupt-gui
Terminal=false
Categories=Utility;Archiving;Security;
MimeType=application/x-zupt;
Keywords=backup;encryption;post-quantum;compression;zupt;\n"
                            out)))))))))
    (inputs
     (append (list bash-minimal python python-pyside-6 python-shiboken-6
                   qtbase qtwayland zupt
                   (list zstd "lib"))   ; libzstd.so.1 is in zstd's "lib" output
             %gui-runtime-libs))
    (home-page "https://github.com/cristiancmoises/zupt")
    (synopsis "Desktop frontend for the ZUPT post-quantum backup tool")
    (description
     "PySide6 (Qt 6) graphical frontend for ZUPT: create, inspect and
extract @code{.zupt} archives with password or post-quantum recipient
encryption, including the @code{--pq} hybrid and @code{--pq-only} full
post-quantum modes.  The launcher pins the matching @code{zupt} CLI from the
store via @env{ZUPT_BIN} and sets @env{LD_LIBRARY_PATH} to the Qt6 leaf
libraries PySide6 needs but does not carry in its RUNPATH.")
    (license license:agpl3+)))

;; `guix package -f' evaluates the file's last expression — the GUI, which
;; carries the CLI as an input.
zupt-gui
