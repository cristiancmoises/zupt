;;; SPDX-License-Identifier: AGPL-3.0-or-later
;;; Copyright (c) 2026 Cristian Cezar Moisés
;;;
;;; GNU Guix package definitions for ZUPT (CLI + PySide6 GUI).
;;; Development recipe: the origin below still pins the withdrawn 5.2.10
;;; delivery, commit 24995eb7652a31eedc46386bab14c63cbb31e050, not the current
;;; working source. Repin only after the official source has passed its gates;
;;; these local phase corrections do not validate that remote archive.
;;; New public release bundles use .zupt; no new tarball is uploaded.
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
             (gnu packages version-control) ; git-minimal for source-only tests
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

(define %zupt-version "5.2.10")

(define %zupt-source
  (origin
    (method url-fetch)
    (uri (string-append
          "https://github.com/cristiancmoises/zupt"
          "/archive/refs/tags/v" %zupt-version ".tar.gz"))
    (sha256
     (base32 "1z78q52n9l7fmlcpbzjijswyj4ml343a7izjv7714iayp8q1rs1m"))))

(define-public zupt
  (package
    (name "zupt")
    (version %zupt-version)
    (source %zupt-source)
    (build-system gnu-build-system)
    (native-inputs (list git-minimal python))
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
          (add-after 'patch-source-shebangs 'patch-test-fixture-interpreters
            (lambda* (#:key inputs native-inputs tests? #:allow-other-keys)
              (when tests?
                (let* ((tools (or native-inputs inputs))
                       (sh (search-input-file tools "/bin/sh"))
                       (bash (search-input-file tools "/bin/bash")))
                  ;; These scripts generate executable shell fixtures at test
                  ;; time, after standard entry-shebang patching has completed.
                  (substitute*
                      '("tests/test_static_analysis_harness.sh"
                        "tests/test_crypto_test_wrappers.sh"
                        "tests/test_ct_timing_harness.sh"
                        "tests/test_kdf_transparency_harness.sh"
                        "tests/test_fuzz_build_wrapper.sh"
                        "tests/test_disk_ioctl_abi_wrapper.sh"
                        "tests/test_atomic_archive_output_probe.sh"
                        "tests/test_legacy_disk_5_2_1_compiler.sh"
                        "tests/test_deb_packaging_failures.sh"
                        "tests/test_rpm_packaging_failures.sh")
                    (("#!/bin/sh") (string-append "#!" sh))
                    (("#!/usr/bin/env bash") (string-append "#!" bash)))))))
          (replace 'check
            ;; Run the source-only suite, including the known-answer vectors.
            (lambda* (#:key tests? #:allow-other-keys)
              (when tests?
                (invoke "make" "WITH_SDK=0" "WITH_PQBOX=0"
                        (string-append "CC=" #$(cc-for-target))
                        "check"))))
          (add-after 'install 'install-documentation
            (lambda _
              (let ((doc (string-append #$output "/share/doc/zupt")))
                (mkdir-p doc)
                (for-each (lambda (file) (install-file file doc))
                          '("README.md" "README.pt-BR.md"
                            "DOCUMENTACAO.pt-BR.md" "SECURITY.md"
                            "CHANGELOG.md" "DISTRIBUTION.md"))
                (let ((guides (string-append doc "/docs")))
                  (mkdir-p guides)
                  (for-each (lambda (file) (install-file file guides))
                            '("docs/USER_GUIDE.md"
                              "docs/GUIA_USUARIO.pt-BR.md"))))))
          (add-after 'validate-runpath 'check-installed
            ;; Exercise the installed, stripped CLI, not the build-tree binary.
            (lambda* (#:key outputs target (tests? (not target)) #:allow-other-keys)
              (when tests?
                (invoke "bash" "scripts/test-installed-zupt.sh"
                        (string-append (assoc-ref outputs "out") "/bin/zupt"))))))))
    (home-page "https://github.com/cristiancmoises/zupt")
    (synopsis "Post-quantum backup compression utility")
    (description
     "ZUPT is a pure-C11 backup compressor with native
post-quantum encryption.  Two in-tree PQ modes: @code{--pq} hybridizes
ML-KEM-768 with X25519 (recommended), and
@code{--pq-only} uses ML-KEM-768 alone for @dfn{PQ-only} compliance postures.
Payload protection is AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC with a fresh
random per-block nonce; AES-NI/SHA-NI dispatch at runtime; the bundled
VaptVupt 2.65.13 LZ+ANS codec has portable fallbacks.  Password mode uses
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
          ;; The GUI searches next to its module; keep the theme copy below.
          ("gui/assets/zupt-icon.png" "lib/zupt-gui/assets/")
          ("gui/assets/zupt-icon.png"
           "share/icons/hicolor/256x256/apps/zupt-gui.png")
          ("gui/README.md" "share/doc/zupt-gui/")
          ("README.pt-BR.md" "share/doc/zupt-gui/")
          ("DOCUMENTACAO.pt-BR.md" "share/doc/zupt-gui/")
          ("docs/USER_GUIDE.md" "share/doc/zupt-gui/docs/")
          ("docs/GUIA_USUARIO.pt-BR.md" "share/doc/zupt-gui/docs/")
          ("SECURITY.md" "share/doc/zupt-gui/")
          ("DISTRIBUTION.md" "share/doc/zupt-gui/")
          ("doc/zupt-gui.1" "share/man/man1/")
          ("LICENSE" "share/licenses/zupt-gui/LICENSE")
          ("LICENSE-AGPL-3.0"
           "share/licenses/zupt-gui/LICENSE-AGPL-3.0")
          ("gui/LICENSE-GUI"
           "share/licenses/zupt-gui/LICENSE-GUI")
          ("gui/assets/README.md"
           "share/licenses/zupt-gui/ASSET-PROVENANCE.md"))
      #:phases
      #~(let ()
          (define (runtime-paths inputs)
            (let* ((pyside (assoc-ref inputs "python-pyside-6"))
                   (site (car (find-files pyside "^site-packages$"
                                         #:directories? #t)))
                   (shiboken (assoc-ref inputs "python-shiboken-6"))
                   (shsite (car (find-files shiboken "^site-packages$"
                                           #:directories? #t)))
                   (qtbase (assoc-ref inputs "qtbase"))
                   (qtwl (assoc-ref inputs "qtwayland"))
                   ;; zstd keeps libzstd.so.1 in its "lib" output.
                   (zstdlib (assoc-ref inputs "zstd")))
              (list
               (cons "GUIX_PYTHONPATH" (string-append site ":" shsite))
               (cons "QT_PLUGIN_PATH"
                     (string-append qtbase "/lib/qt6/plugins:"
                                    qtwl "/lib/qt6/plugins"))
               (cons "LD_LIBRARY_PATH"
                     (string-join
                      (append
                       (list #$@(map (lambda (p) (file-append p "/lib"))
                                     %gui-runtime-libs))
                       (list (string-append zstdlib "/lib")))
                      ":")))))
          (modify-phases %standard-phases
            (add-after 'install 'make-launcher
              (lambda* (#:key inputs outputs #:allow-other-keys)
                (let* ((out     (assoc-ref outputs "out"))
                       (bin     (string-append out "/bin"))
                       (gui     (string-append
                                 out "/lib/zupt-gui/zupt_gui.py"))
                       (sh      (search-input-file inputs "/bin/sh"))
                       (python3 (search-input-file inputs "/bin/python3"))
                       (cli     (search-input-file inputs "/bin/zupt"))
                       (paths (runtime-paths inputs)))
                  (mkdir-p bin)
                  (call-with-output-file (string-append bin "/zupt-gui")
                    (lambda (port)
                      (format port "#!~a
export ZUPT_BIN=\"~a\"
export GUIX_PYTHONPATH=\"~a${GUIX_PYTHONPATH:+:}$GUIX_PYTHONPATH\"
export QT_PLUGIN_PATH=\"~a${QT_PLUGIN_PATH:+:}$QT_PLUGIN_PATH\"
export LD_LIBRARY_PATH=\"~a${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH\"
exec \"~a\" \"~a\" \"$@\"\n"
                              sh cli (assoc-ref paths "GUIX_PYTHONPATH")
                              (assoc-ref paths "QT_PLUGIN_PATH")
                              (assoc-ref paths "LD_LIBRARY_PATH") python3 gui)))
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
                              out))))))
            (add-after 'install-desktop-file 'check
              (lambda* (#:key inputs outputs (tests? #t) #:allow-other-keys)
                (when tests?
                  (let* ((out (assoc-ref outputs "out"))
                         (gui (string-append out "/lib/zupt-gui/zupt_gui.py"))
                         (launcher (string-append out "/bin/zupt-gui"))
                         (python3 (search-input-file inputs "/bin/python3"))
                         (cli (search-input-file inputs "/bin/zupt"))
                         (paths (runtime-paths inputs))
                         (environment (environ)))
                    (dynamic-wind
                      (lambda ()
                        (setenv "ZUPT_BIN" cli)
                        (setenv "ZUPT_GUI_MODULE" gui)
                        (setenv "QT_QPA_PLATFORM" "offscreen")
                        (setenv "PYTHONDONTWRITEBYTECODE" "1")
                        ;; The launcher supplies its own prefixes; do not let
                        ;; inherited paths mask missing package dependencies.
                        (for-each unsetenv (map car paths)))
                      (lambda ()
                        (invoke launcher "--version")
                        (invoke launcher "--selftest")
                        (for-each (lambda (entry) (setenv (car entry) (cdr entry)))
                                  paths)
                        (invoke python3 "-B" "tests/test_gui_workflows.py"))
                      (lambda () (environ environment)))))))))))
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
