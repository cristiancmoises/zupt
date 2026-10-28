;;; SPDX-License-Identifier: AGPL-3.0-or-later
;;; Copyright (c) 2026 Cristian Cezar Moisés

(use-modules (guix packages) (guix gexp) (guix utils)
             (guix build utils)
             ((guix build copy-build-system) #:prefix copy:)
             ((guix build gnu-build-system) #:prefix gnu:)
             (ice-9 match)
             (ice-9 popen)
             (srfi srfi-1)
             (srfi srfi-34)
             (rnrs bytevectors) (rnrs io ports))

(primitive-load "packaging/guix/zupt.scm")
(define gui-package (module-ref (current-module) 'zupt-gui))
(define install-plan
  (match (memq #:install-plan (package-arguments gui-package))
    ((_ value _ ...)
     ;; This plan has no store references; do not lower a derivation or fetch.
     (match (gexp->approximate-sexp value)
       (('quote plan) plan)
       (_ (error "GUI install plan is not a literal file mapping"))))
    (_ (error "GUI package has no install plan"))))

(define (file-bytes path)
  (let ((port (open-file path "rb")))
    (dynamic-wind (lambda () #t)
                  (lambda () (get-bytevector-all port))
                  (lambda () (close-port port)))))

(define* (recipe-phases package-path #:optional (package gui-package) output)
  ;; Replace only package file references, not the launcher implementation.
  ;; This covers the recipe's current default-output leaf list, not general
  ;; Gexp lowering; it does not build dependencies or resolve native outputs.
  (define (resolve-reference value)
    (cond
     ((file-append? value)
      (unless (and (package? (file-append-base value))
                   (list? (file-append-suffix value))
                   (every string? (file-append-suffix value)))
        (error "unsupported GUI phase file reference" value))
      (apply string-append (package-path (file-append-base value))
             (file-append-suffix value)))
     ((equal? value '(*approximate*))
      ;; The CLI phases have one unresolved reference: #$output.  Its caller
      ;; supplies a disposable output directory; no derivation is lowered.
      (or output (error "unresolved recipe phase reference")))
     ((pair? value)
      (cons (resolve-reference (car value))
            (resolve-reference (cdr value))))
     ((record? value) (error "unsupported GUI phase record" value))
     (else value)))
  (let ((environment (make-fresh-user-module)))
    (module-use! environment (resolve-interface '(guix build utils)))
    (module-define! environment '%standard-phases
                    (if (eq? package gui-package)
                        copy:%standard-phases gnu:%standard-phases))
    (match (memq #:phases (package-arguments package))
      ((_ value _ ...)
       (eval (resolve-reference (gexp->approximate-sexp value)) environment))
      (_ (error "GUI package has no build phases")))))

(define (test-cli-fixture-interpreters)
  ;; This must catch an omitted generated-fixture interpreter patch by running
  ;; existing shell-only compiler and package controls, without a product build.
  (call-with-temporary-directory
    (lambda (directory)
      (let* ((source (string-append directory "/source"))
             (shell (dirname (dirname (which "sh"))))
             (phases (recipe-phases
                      (lambda (package) (error "unexpected CLI package reference"))
                      zupt (string-append directory "/out")))
             (patch-source (assoc-ref phases 'patch-source-shebangs))
             (patch (assoc-ref phases 'patch-test-fixture-interpreters)))
        ;; Disabled tests must not look for interpreters or test-source files.
        (with-directory-excursion directory
          (unless (patch #:tests? #f #:inputs '() #:native-inputs '())
            (error "disabled CLI fixture patch failed")))
        (mkdir-p source)
        (for-each
         (lambda (path)
           (copy-recursively path (string-append source "/" path)
                             #:log (open-output-string)))
         '("tests" "src" "include"))
        (mkdir-p (string-append source "/sdk"))
        (copy-file "Makefile" (string-append source "/Makefile"))
        (copy-file "sdk/Makefile.sdk" (string-append source "/sdk/Makefile.sdk"))
        ;; Union of the package controls' selected inputs; include/zupt.h is
        ;; already copied above. Their make and package tools are doubles.
        (for-each
         (lambda (path)
           (let ((destination (string-append source "/" path)))
             (mkdir-p (dirname destination))
             (copy-file path destination)))
         '("packaging/build-deb.sh" "packaging/build-gui-deb.sh"
           "packaging/build-rpm.sh" "packaging/build-gui-rpm.sh"
           "packaging/opensuse/zupt.spec"
           "gui/install.sh" "gui/src/zupt_gui.py" "gui/assets/zupt-icon.png"
           "gui/packaging/zupt-gui.desktop" "doc/zupt-gui.1" "gui/README.md"
           "gui/LICENSE-GUI" "gui/assets/README.md"
           "scripts/check-installed-docs.py" "scripts/publish-package.py"
           "README.md" "README.pt-BR.md" "DOCUMENTACAO.pt-BR.md"
           "CHANGELOG.md" "SECURITY.md" "DISTRIBUTION.md" "THREAT_MODEL.md"
           "NOTICE" "THIRD-PARTY-NOTICES.md" "LICENSE"
           "LICENSE-AGPL-3.0" "LICENSE-GPL-3.0" "LICENSE-BSD-2-Clause"
           "LICENSE-BSD-3-Clause" "LICENSE-CC0-1.0"
           "docs/USER_GUIDE.md" "docs/GUIA_USUARIO.pt-BR.md"))
        (with-directory-excursion source
          ;; These wrappers copy themselves into executable tool fixtures.
          ;; Match the recipe's preceding source phase, including regular
          ;; non-executable scripts, before patching generated script bodies.
          (for-each (lambda (script) (chmod script #o644))
                    '("tests/test_frama_ans_reader_wrapper.sh"
                      "tests/test_frama_ans_log_bounds_wrapper.sh"
                      "tests/test_codec_exact_size_wrapper.sh"
                      "tests/test_threaded_harness.sh"))
          (unless (patch-source #:source source)
            (error "CLI source shebang patch failed"))
          (unless (patch #:tests? #t #:inputs '()
                         #:native-inputs `(("bash" . ,shell)))
            (error "enabled CLI fixture patch failed"))
          (let ((failures '()))
            (for-each
             (lambda (script)
               (let ((status (system* (which "bash") script)))
                 (if (zero? status)
                     (format #t "PASS: Guix CLI patched fixture controls ~a~%" script)
                     (set! failures (cons (list script status) failures)))))
             '("tests/test_disk_ioctl_abi_wrapper.sh"
               "tests/test_atomic_archive_output_probe.sh"
               "tests/test_legacy_disk_5_2_1_compiler.sh"
               "tests/test_fuzz_build_wrapper.sh"
               "tests/test_frama_ans_reader_wrapper.sh"
               "tests/test_frama_ans_log_bounds_wrapper.sh"
               "tests/test_codec_exact_size_wrapper.sh"
               "tests/test_threaded_harness.sh"
               "tests/test_deb_packaging_failures.sh"
               "tests/test_rpm_packaging_failures.sh"))
            (unless (null? failures)
              (error "Guix CLI generated fixtures failed" (reverse failures)))))))))

(test-cli-fixture-interpreters)

(define (test-cli-documentation)
  (call-with-temporary-directory
    (lambda (output)
      (let ((phases (recipe-phases
                     (lambda (package) (error "unexpected CLI package reference"))
                     zupt output)))
        (unless ((assoc-ref phases 'install-documentation))
          (error "Guix CLI documentation phase failed"))
        (for-each
         (lambda (source)
           (let ((installed (string-append output "/share/doc/zupt/" source)))
             (unless (and (file-exists? installed)
                          (eq? (stat:type (lstat installed)) 'regular)
                          (bytevector=? (file-bytes source) (file-bytes installed)))
               (error "Guix CLI installed guide is missing or differs" source))
             (format #t "PASS: Guix CLI installed ~a byte-for-byte~%" source)))
         '("docs/USER_GUIDE.md" "docs/GUIA_USUARIO.pt-BR.md"
           "SECURITY.md" "DISTRIBUTION.md"))))))

(test-cli-documentation)

(define (test-cli-installed-check)
  (call-with-temporary-directory
    (lambda (directory)
      (let* ((output (string-append directory "/installed output"))
             (phases (recipe-phases
                      (lambda (package) (error "unexpected CLI package reference"))
                      zupt output))
             (check (assoc-ref phases 'check-installed))
             (after-validation (memq 'validate-runpath (map car phases)))
             (expected-binary (string-append output "/bin/zupt")))
        ;; Replace only the smoke script process boundary. This tests phase
        ;; wiring and failure propagation, not a Guix build or CLI execution.
        (define (write-probe status)
          (call-with-output-file "scripts/test-installed-zupt.sh"
            (lambda (port)
              (display "printf '%s\\n' \"$#\" \"$1\" > smoke-record\n" port)
              (format port "exit ~a\n" status))))
        (define (assert-record)
          (unless (string=? (call-with-input-file "smoke-record" get-string-all)
                            (string-append "1\n" expected-binary "\n"))
            (error "CLI installed check bypassed its output binary")))
        (unless (and (procedure? check) after-validation
                     (memq 'check-installed (cdr after-validation)))
          (error "CLI installed check must follow runpath validation"))
        (with-directory-excursion directory
          ;; Disabled checks must not require a source script or installed CLI.
          (check #:tests? #f #:outputs '())
          (check #:target "aarch64-linux-gnu" #:outputs '())
          (when (file-exists? "smoke-record")
            (error "disabled CLI installed check launched a child"))
          (mkdir "scripts")
          (write-probe 0)
          (check #:tests? #t #:outputs `(("out" . ,output)))
          (assert-record)
          (delete-file "smoke-record")
          (check #:outputs `(("out" . ,output)))
          (assert-record)
          (delete-file "smoke-record")
          (write-probe 37)
          (let ((failure
                 (guard (condition ((invoke-error? condition) condition))
                   (check #:tests? #t #:outputs `(("out" . ,output)))
                   (error "CLI installed check swallowed smoke failure"))))
            (unless (and (equal? (invoke-error-exit-status failure) 37)
                         (not (invoke-error-term-signal failure))
                         (not (invoke-error-stop-signal failure))
                         (equal? (invoke-error-program failure) "bash")
                         (equal? (invoke-error-arguments failure)
                                 (list "scripts/test-installed-zupt.sh" expected-binary)))
              (error "CLI installed check changed smoke failure")))
          (assert-record)
          (format #t "PASS: Guix CLI installed check honors tests?, output path and child failure~%"))))))

(test-cli-installed-check)

(define (test-check-phase phases directory output probe inputs expected-values)
  (let* ((check (assoc-ref phases 'check))
         (after-desktop (memq 'install-desktop-file (map car phases)))
         (records-file (string-append directory "/check-records.scm"))
         (names '("ZUPT_BIN" "ZUPT_GUI_MODULE" "QT_QPA_PLATFORM"
                  "PYTHONDONTWRITEBYTECODE" "GUIX_PYTHONPATH"
                  "QT_PLUGIN_PATH" "LD_LIBRARY_PATH"))
         (module (string-append output "/lib/zupt-gui/zupt_gui.py"))
         (expected-records
          (map (lambda (arguments) (list arguments expected-values))
               (list (list module "--version")
                     (list module "--selftest")
                     '("-B" "tests/test_gui_workflows.py"))))
         (saved-environment (environ)))
    (define (records)
      (call-with-input-file records-file
        (lambda (port)
          (let loop ((result '()))
            (let ((record (read port)))
              (if (eof-object? record) (reverse result)
                  (loop (cons record result))))))))
    (define (reset-records)
      (call-with-output-file records-file (lambda (port) #t)))
    (define (assert-environment-restored before)
      (unless (equal? (sort before string<?) (sort (environ) string<?))
        (error "GUI check phase did not restore its environment")))
    (unless (and (procedure? check) after-desktop
                 (memq 'check (cdr after-desktop)))
      (error "GUI check phase must follow install-desktop-file"))
    ;; Keep the recipe and generated launcher real. Replace only Python with a
    ;; recorder: these assertions cover phase wiring, not execution of Qt.
    (call-with-output-file probe
      (lambda (port)
        (format port "#!~a\nexec ~a --no-auto-compile -s \"$0\" \"$@\"\n!#\n"
                (which "sh") (which "guile"))
        (format port "(define previous (call-with-input-file ~s\n" records-file)
        (display "  (lambda (port) (let loop ((count 0))\n" port)
        (display "    (if (eof-object? (read port)) count (loop (+ count 1)))))))\n" port)
        (format port "(let ((port (open-file ~s \"a\")))\n" records-file)
        (format port "  (write (list (cdr (command-line)) (map getenv '~s)) port)\n"
                names)
        (display "  (newline port) (close-port port))\n" port)
        (display "(exit (if (= (+ previous 1)\n" port)
        (display "             (string->number (getenv \"TEST_GUI_CHECK_FAIL_AT\")))\n" port)
        (display "          37 0))\n" port)))
    (dynamic-wind
      (lambda () #t)
      (lambda ()
        ;; Deliberately poison inherited values: no suffix may enter the gate.
        (for-each (lambda (name) (setenv name "tainted inherited path:/wrong")) names)
        (setenv "TEST_GUI_CHECK_FAIL_AT" "0")
        (reset-records)
        (let ((before (environ)))
          ;; Missing inputs/outputs must not matter when tests are disabled.
          (unless (check #:tests? #f #:inputs '() #:outputs '())
            (error "GUI disabled check phase failed"))
          (assert-environment-restored before)
          (unless (null? (records))
            (error "GUI disabled check phase launched a child")))
        (for-each
         (lambda (explicit-tests?)
           (reset-records)
           (let ((before (environ)))
             (unless (if explicit-tests?
                         (check #:tests? #t #:inputs inputs
                                #:outputs `(("out" . ,output)))
                         (check #:inputs inputs #:outputs `(("out" . ,output))))
               (error "GUI enabled check phase failed"))
             (assert-environment-restored before)
             (unless (equal? (records) expected-records)
               (error "GUI check phase changed commands, paths or environment" (records)))))
         '(#f #t))
        (for-each
         (lambda (failed-call)
           (reset-records)
           (setenv "TEST_GUI_CHECK_FAIL_AT" (number->string failed-call))
           (let* ((before (environ))
                  (failure
                   (guard (condition ((invoke-error? condition) condition))
                     (check #:tests? #t #:inputs inputs
                            #:outputs `(("out" . ,output)))
                     (error "GUI check phase swallowed a child failure" failed-call))))
             (unless (and (equal? (invoke-error-exit-status failure) 37)
                          (not (invoke-error-term-signal failure))
                          (not (invoke-error-stop-signal failure)))
               (error "GUI check phase did not propagate child exit 37" failed-call))
             (unless (and
                      (equal? (invoke-error-program failure)
                              (if (= failed-call 3) probe
                                  (string-append output "/bin/zupt-gui")))
                      (equal? (invoke-error-arguments failure)
                              (list-ref '(("--version") ("--selftest")
                                          ("-B" "tests/test_gui_workflows.py"))
                                        (- failed-call 1))))
               (error "GUI check phase bypassed its installed launcher or Python input"
                      failed-call))
             (assert-environment-restored before)
             (unless (equal? (records) (take expected-records failed-call))
               (error "GUI check phase ran past a failure or changed its commands" failed-call))))
         '(1 2 3))
        (format #t "PASS: Guix GUI check phase honors tests?, clean installed paths and child failures~%"))
      (lambda () (environ saved-environment)))))

(define (test-launcher directory output)
  (let* ((inputs-directory (string-append directory "/inputs"))
         (sh-directory (string-append inputs-directory "/shell"))
         (python-directory (string-append inputs-directory "/python"))
         (cli-directory (string-append inputs-directory "/cli"))
         (pyside-directory (string-append inputs-directory "/pyside"))
         (shiboken-directory (string-append inputs-directory "/shiboken"))
         (qt-directory (string-append inputs-directory "/qtbase"))
         (wayland-directory (string-append inputs-directory "/qtwayland"))
         (zstd-directory (string-append inputs-directory "/zstd"))
         (probe (string-append python-directory "/bin/python3"))
         (launcher (string-append output "/bin/zupt-gui"))
         (library-prefix
          (string-join
           (map (lambda (name) (string-append directory "/runtime/" name "/lib"))
                '("mesa" "libxkbcommon" "fontconfig-minimal" "freetype" "graphite2"
                  "harfbuzz" "icu4c" "double-conversion" "pcre2" "md4c" "libb2"
                  "brotli" "libpng" "libjpeg-turbo" "zlib" "expat" "libxml2"
                  "pixman" "glib" "dbus" "wayland" "libx11" "libxext" "libxrender"
                  "libxcb" "libxrandr" "libxi" "libxcursor" "libxft" "libxfixes"
                  "libxdamage" "libxcomposite" "libxtst" "libxinerama" "libsm"
                  "libice" "libxau" "libxdmcp" "xcb-util" "xcb-util-image"
                  "xcb-util-keysyms" "xcb-util-renderutil" "xcb-util-wm"
                  "xcb-util-cursor" "libinput-minimal" "mtdev" "libevdev" "eudev"))
           ":"))
         (phases (recipe-phases
                  (lambda (package)
                    (string-append directory "/runtime/" (package-name package))))))
    (for-each mkdir-p
              (list (string-append sh-directory "/bin")
                    (string-append python-directory "/bin")
                    (string-append cli-directory "/bin")
                    (string-append pyside-directory "/lib/site-packages")
                    (string-append shiboken-directory "/lib/site-packages")))
    (symlink (which "sh") (string-append sh-directory "/bin/sh"))
    (call-with-output-file (string-append cli-directory "/bin/zupt")
      (lambda (port) (display "fixture CLI path only\n" port)))
    ;; A recording executable observes the real generated shell wrapper.
    (call-with-output-file probe
      (lambda (port)
        (format port "#!~a\nexec ~a --no-auto-compile -s \"$0\" \"$@\"\n!#\n"
                (which "sh") (which "guile"))
        (display "(write (list (cdr (command-line))\n"
                 port)
        (display "             (map getenv '(\"ZUPT_BIN\" \"GUIX_PYTHONPATH\"\n"
                 port)
        (display "                           \"QT_PLUGIN_PATH\" \"LD_LIBRARY_PATH\"))))\n"
                 port)
        (display "(newline)\n(exit (string->number (or (getenv \"TEST_GUI_EXIT\") \"0\")))\n"
                 port)))
    (chmod probe #o755)
    (call-with-output-file (string-append directory "/matches.zupt")
      (lambda (port) (display "synthetic glob fixture\n" port)))
    (unless ((assoc-ref phases 'make-launcher)
             #:inputs `(("shell" . ,sh-directory) ("python" . ,python-directory)
                        ("zupt" . ,cli-directory)
                        ("python-pyside-6" . ,pyside-directory)
                        ("python-shiboken-6" . ,shiboken-directory)
                        ("qtbase" . ,qt-directory) ("qtwayland" . ,wayland-directory)
                        ("zstd" . ,zstd-directory))
             #:outputs `(("out" . ,output)))
      (error "GUI launcher phase failed"))
    (unless (= (logand (stat:mode (stat launcher)) #o777) #o755)
      (error "GUI launcher mode is not executable"))
    (let ((saved-environment
           (map (lambda (name) (cons name (getenv name)))
                '("GUIX_PYTHONPATH" "QT_PLUGIN_PATH" "LD_LIBRARY_PATH"
                  "ZUPT_BIN" "TEST_GUI_EXIT"))))
      (dynamic-wind
        (lambda () #t)
        (lambda ()
          (for-each
           (lambda (case)
             (match case
               ((arguments suffix exit-code)
                (for-each (lambda (name)
                            (if suffix (setenv name suffix) (unsetenv name)))
                          '("GUIX_PYTHONPATH" "QT_PLUGIN_PATH" "LD_LIBRARY_PATH"))
                (setenv "ZUPT_BIN" "/not/the/pinned/cli")
                (setenv "TEST_GUI_EXIT" (number->string exit-code))
                (with-directory-excursion directory
                  (let ((port (apply open-pipe* OPEN_READ launcher arguments))
                        (result #f) (at-eof? #f) (status #f))
                    (dynamic-wind
                      (lambda () #t)
                      (lambda ()
                        (set! result (read port))
                        (set! at-eof? (eof-object? (read port))))
                      (lambda () (set! status (close-pipe port))))
                    (unless (and at-eof? (equal? (status:exit-val status) exit-code))
                      (error "GUI launcher changed child status or output" status))
                    (match result
                      ((actual-arguments (cli python-path plugin-path library-path))
                       (unless (equal? actual-arguments
                                       (cons (string-append output "/lib/zupt-gui/zupt_gui.py")
                                             arguments))
                         (error "GUI launcher changed arguments" actual-arguments))
                       (unless (string=? cli (string-append cli-directory "/bin/zupt"))
                         (error "GUI launcher did not pin the matching CLI" cli))
                       (let ((tail (if (and suffix (not (string-null? suffix)))
                                       (string-append ":" suffix) "")))
                         (unless (and
                                  (string=? python-path
                                            (string-append pyside-directory "/lib/site-packages:"
                                                           shiboken-directory "/lib/site-packages" tail))
                                  (string=? plugin-path
                                            (string-append qt-directory "/lib/qt6/plugins:"
                                                           wayland-directory "/lib/qt6/plugins" tail))
                                  (string=? library-path
                                            (string-append library-prefix ":"
                                                           zstd-directory "/lib" tail)))
                           (error "GUI launcher changed required paths or inherited suffixes" result))))
                      (_ (error "GUI launcher probe returned malformed data" result))))))))
           '((() #f 0)
             (("" "with spaces" "quote'\"" "*.zupt" "line\nbreak" "--flag=value")
              "inherited path:/tail" 37)
             (("one.zupt") "" 0))))
        (lambda ()
          (for-each (lambda (entry)
                      (if (cdr entry) (setenv (car entry) (cdr entry))
                          (unsetenv (car entry))))
                    saved-environment))))
    (unless ((assoc-ref phases 'install-desktop-file) #:outputs `(("out" . ,output)))
      (error "GUI desktop phase failed"))
    (let ((desktop (call-with-input-file
                      (string-append output "/share/applications/zupt-gui.desktop")
                    get-string-all)))
      (for-each
       (lambda (line)
         (unless (string-contains desktop (string-append "\n" line "\n"))
           (error "GUI desktop entry lost required field" line)))
       (list "Type=Application" "Icon=zupt-gui" "Terminal=false"
             "MimeType=application/x-zupt;"
             (string-append "Exec=" launcher " %F"))))
    (format #t "PASS: Guix GUI generated launcher arguments, environment, status and desktop entry~%")
    (test-check-phase
     phases directory output probe
     `(("shell" . ,sh-directory) ("python" . ,python-directory)
       ("zupt" . ,cli-directory)
       ("python-pyside-6" . ,pyside-directory)
       ("python-shiboken-6" . ,shiboken-directory)
       ("qtbase" . ,qt-directory) ("qtwayland" . ,wayland-directory)
       ("zstd" . ,zstd-directory))
     (list (string-append cli-directory "/bin/zupt")
           (string-append output "/lib/zupt-gui/zupt_gui.py") "offscreen" "1"
           (string-append pyside-directory "/lib/site-packages:"
                          shiboken-directory "/lib/site-packages")
           (string-append qt-directory "/lib/qt6/plugins:"
                          wayland-directory "/lib/qt6/plugins")
           (string-append library-prefix ":" zstd-directory "/lib")))))

(call-with-temporary-directory
  (lambda (test-directory)
    (define output (string-append test-directory "/out"))
    (unless ((assoc-ref copy:%standard-phases 'install)
             #:install-plan install-plan #:outputs `(("out" . ,output)))
      (error "Guix GUI copy phase failed"))
    ;; Assert on installed files, not on matching text in the recipe.
    (for-each
     (lambda (mapping)
       (match mapping
         ((source destination)
          (let ((installed (string-append output "/" destination)))
            (unless (file-exists? installed)
              (error "missing installed Guix GUI file" destination))
            (unless (and (eq? (stat:type (lstat installed)) 'regular)
                         (bytevector=? (file-bytes source)
                                       (file-bytes installed)))
              (error "installed Guix GUI file differs from source" destination))
            (format #t "PASS: Guix GUI installed ~a byte-for-byte~%" destination)))))
     '(("doc/zupt-gui.1" "share/man/man1/zupt-gui.1")
       ("LICENSE" "share/licenses/zupt-gui/LICENSE")
       ("LICENSE-AGPL-3.0" "share/licenses/zupt-gui/LICENSE-AGPL-3.0")
       ("gui/LICENSE-GUI" "share/licenses/zupt-gui/LICENSE-GUI")
       ("gui/assets/README.md" "share/licenses/zupt-gui/ASSET-PROVENANCE.md")
       ("docs/USER_GUIDE.md" "share/doc/zupt-gui/docs/USER_GUIDE.md")
       ("docs/GUIA_USUARIO.pt-BR.md" "share/doc/zupt-gui/docs/GUIA_USUARIO.pt-BR.md")
       ("SECURITY.md" "share/doc/zupt-gui/SECURITY.md")
       ("DISTRIBUTION.md" "share/doc/zupt-gui/DISTRIBUTION.md")
       ("gui/assets/zupt-icon.png" "lib/zupt-gui/assets/zupt-icon.png")))
    (test-launcher test-directory output)))
