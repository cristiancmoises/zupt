# Zupt — backup compression with hybrid post-quantum encryption
# Build system. Pure GNU make, no autotools, no cmake required.
#
# Targets:
#   make                Build the zupt binary (uses CC, CFLAGS, LDFLAGS env)
#   make V=1            Verbose: show every command line
#   make install        Install to /usr/local (override with PREFIX=/usr)
#   make test           Run the full test suite (55 tests across 6 suites)
#   make test-asan      Build and run with AddressSanitizer + UBSan
#   make clean          Remove build artifacts
#
# Build profiles (all controllable via standard env vars):
#   CC=clang make                          Use Clang instead of GCC
#   CFLAGS="-O3 -march=native" make        Optimize for current host
#   make PREFIX=/usr DESTDIR=/tmp/stage    Staged install for packagers
#
# Architectures supported (auto-detected from $(uname -m)):
#   x86_64    — full speed: Jasmin constant-time crypto, AVX2 SIMD decode
#   aarch64   — full speed: C crypto, NEON SIMD decode
#   armhf, ppc64le, s390x, riscv64 — C crypto, scalar decode
#
# Operating systems supported:
#   Linux (glibc 2.28+), macOS 10.15+, Windows (MSYS2/MinGW), Termux Android,
#   FreeBSD, OpenBSD (with system make compatibility shims).

CC        ?= cc
# v3.0.2: -Woverlength-strings catches usage()-style string literals
# that violate the C99 4095-char single-string limit. F-13 was hit
# in v3.0.1 when usage() drifted past the limit; the warning now
# fails the build under -Werror downstream.
CFLAGS    ?= -Wall -Wextra -Woverlength-strings -O2 -std=c11
CFLAGS    += -Iinclude -Isrc
LDFLAGS   ?=
LDLIBS    ?= -lm

# pthreads: link -lpthread on Linux/BSD, skip on Android/Termux (bionic built-in)
ifeq ($(shell uname -o 2>/dev/null),Android)
  # Termux/Android: pthreads built into bionic libc
else
  LDLIBS += -lpthread
endif

PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
MANDIR    ?= $(PREFIX)/share/man
MAN1DIR   ?= $(MANDIR)/man1
GZIP      ?= gzip
GZIPFLAGS ?= -9 -n

# --- Verbose build ---
V ?= 0
ifeq ($(V),1)
  Q =
else
  Q = @
endif

# --- Zupt core sources ---
ZUPT_SOURCES = src/zupt_main.c src/zupt_format.c src/zupt_lz.c src/zupt_lzh.c \
               src/zupt_xxh.c src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_aes256.c src/zupt_crypto.c \
               src/zupt_crypto_sdk.c src/zupt_crypto_pqbox.c \
               src/zupt_predict.c src/zupt_parallel.c src/zupt_keccak.c \
               src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c \
               src/zupt_filetype.c src/zupt_disk.c src/zupt_dedup.c

# --- Optional vendored libraries (libzuptsdk + libpqvaptvupt) ---
#
# These are PREBUILT shared libraries shipped only as binaries (no source), so
# they are NOT part of the source tree and a distro/source build must not need
# them. WITH_SDK is therefore OFF by default: the tool builds entirely from the
# in-tree C sources, using native crypto (PBKDF2-SHA256 password KDF and native
# ML-KEM-768 + X25519 via --pq). The SDK-backed modes (--pq-sdk, --pq-box, and
# the Argon2id password KDF) compile to "unsupported" stubs in that case.
#
# Set WITH_SDK=1 (with the vendored libs present under vendor/) to enable them.
WITH_SDK ?= 0
ifeq ($(WITH_SDK),1)
ZUPTSDK_DIR ?= vendor/zuptsdk
ZUPTSDK_ABS := $(abspath $(ZUPTSDK_DIR))
CFLAGS  += -DZUPT_WITH_SDK -I$(ZUPTSDK_DIR)/include
PQVV_DIR ?= vendor/pqvaptvupt
CFLAGS  += -I$(PQVV_DIR)/include
LDFLAGS += -L$(ZUPTSDK_DIR) -Wl,-rpath,$(ZUPTSDK_ABS) -Wl,-rpath,'$$ORIGIN/$(ZUPTSDK_DIR)'
LDLIBS  += -lzuptsdk
PQVV_ABS := $(abspath $(PQVV_DIR))
LDFLAGS += -L$(PQVV_DIR) -Wl,-rpath,$(PQVV_ABS) -Wl,-rpath,'$$ORIGIN/$(PQVV_DIR)'
# Installed layout: vendored libs live in $(PREFIX)/lib/$(TARGET)/ — give the
# binary a matching relative rpath so `make install` is self-contained.
LDFLAGS += -Wl,-rpath,'$$ORIGIN/../lib/vaptvupt'
LDLIBS  += -lpqvaptvupt
endif

# --- VAPTVUPT: VaptVupt codec sources (GPL-3.0-or-later; tool is AGPL-3.0-or-later) ---
VV_SOURCES = src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_bcj.c \
             src/vv_huffman.c src/vv_simd.c src/vv_xxh64.c src/vaptvupt_api.c

SOURCES = $(ZUPT_SOURCES) $(VV_SOURCES)

HEADERS  = include/zupt.h include/zupt_keccak.h include/zupt_mlkem.h \
           include/zupt_x25519.h include/zupt_cpuid.h include/zupt_jasmin.h \
           include/zupt_acsl.h \
           include/vaptvupt.h include/vaptvupt_api.h include/vv_huffman.h include/vv_ans.h \
           include/vv_platform.h \
           src/zupt_thread.h src/zupt_parallel.h

TARGET     = vaptvupt
LEGACY_LINK = zupt
MANPAGE    = doc/vaptvupt.1
MANPAGE_GZ = $(TARGET).1.gz

# ═══════════════════════════════════════════════════════════════════
# ARCHITECTURE DETECTION
#
# Jasmin CT assembly:    x86_64 only (pre-compiled .s files)
# AVX2 SIMD decode:      x86_64 only (-mavx2 on VV decode/encode/simd)
# NEON SIMD decode:      aarch64 (auto-detected by compiler, no extra flags)
# Scalar fallback:       all architectures
# ═══════════════════════════════════════════════════════════════════

ARCH := $(shell uname -m)

# --- AVX2: enable SIMD for VaptVupt on x86_64 ---
ifeq ($(ARCH),x86_64)
  VV_SIMD_FLAGS = -mavx2
  SHANI_FLAGS = -msha -mssse3 -msse4.1
else
  VV_SIMD_FLAGS =
  SHANI_FLAGS =
endif

# --- Jasmin: enable only on x86_64 with pre-compiled .s files ---
JAZZ_S = jasmin/zupt_mac_verify.s jasmin/zupt_mlkem_select.s \
         jasmin/zupt_aes_ctr.s jasmin/zupt_x25519_fe.s jasmin/zupt_aes_ctr4.s
JAZZ_O =

ifeq ($(ARCH),x86_64)
  JAZZ_AVAILABLE := $(wildcard $(JAZZ_S))
  ifeq ($(JAZZ_AVAILABLE),$(JAZZ_S))
    CFLAGS += -DZUPT_USE_JASMIN
    JAZZ_O = jasmin/zupt_mac_verify.o jasmin/zupt_mlkem_select.o \
             jasmin/zupt_aes_ctr.o jasmin/zupt_x25519_fe.o jasmin/zupt_aes_ctr4.o
    $(info [jasmin] Enabled (x86_64) — linking CT crypto)
  else
    $(info [jasmin] Assembly not found — using C fallback)
  endif
else
  $(info [jasmin] Disabled on $(ARCH) — using C fallback)
endif

# --- Object files ---
# VV SIMD files need -mavx2 on x86_64 (no-op on other arches)
VV_SIMD_OBJS  = src/vv_encoder.o src/vv_decoder.o src/vv_simd.o

# Vendored codec sources follow the UPSTREAM warning policy (kept byte-exact
# to canonical releases for clean future drop-ins). Two benign clang-only
# categories are silenced here instead of patching upstream files:
#   vv_decoder.c: unused helper retained upstream; vv_ans.c: stats variable.
VV_WPOLICY = -Wno-unused-function -Wno-unused-but-set-variable
$(VV_SOURCES:.c=.o): CFLAGS += $(VV_WPOLICY)
VV_PLAIN_OBJS = src/vv_ans.o src/vv_huffman.o src/vv_xxh64.o src/vv_bcj.o src/vaptvupt_api.o
ZUPT_OBJS     = $(patsubst %.c,%.o,$(ZUPT_SOURCES))
ALL_OBJS      = $(ZUPT_OBJS) $(VV_SIMD_OBJS) $(VV_PLAIN_OBJS)

# ═══════════════════════════════════════════════════════════════════
# ARCH-SAFETY GUARD
#
# If pre-compiled .o files from a different architecture are present
# (e.g. x86_64 .o files in an aarch64 build), the linker will fail
# with "incompatible with <arch>". Detect and remove stale objects.
# This happens when tarballs accidentally include build artifacts,
# or when the same source tree is shared between different machines.
#
# Detection: uses $(CC) -dumpmachine which works on ALL platforms
# including Termux (where /bin/sh does not exist).
# ═══════════════════════════════════════════════════════════════════

STALE_OBJS := $(wildcard src/*.o jasmin/*.o)
ifneq ($(STALE_OBJS),)
  FIRST_OBJ := $(firstword $(STALE_OBJS))
  # Normalise to a canonical token (no '-' / '_' so x86-64 == x86_64).
  OBJ_ARCH := $(shell file $(FIRST_OBJ) 2>/dev/null | grep -oiE 'x86.64|aarch64|arm|powerpc|s390|riscv' | head -1 | tr -d '_-' | tr '[:upper:]' '[:lower:]')
  HOST_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null)
  HOST_ARCH_CC := $(shell echo "$(HOST_TRIPLE)" | grep -oiE 'x86.64|aarch64|arm|powerpc|s390|riscv' | head -1 | tr -d '_-' | tr '[:upper:]' '[:lower:]')
  # Fallback: try uname -m if CC -dumpmachine fails
  ifeq ($(HOST_ARCH_CC),)
    HOST_ARCH_CC := $(shell uname -m 2>/dev/null | grep -oiE 'x86.64|aarch64|arm|powerpc|s390|riscv' | head -1 | tr -d '_-' | tr '[:upper:]' '[:lower:]')
  endif
  ifneq ($(OBJ_ARCH),)
    ifneq ($(HOST_ARCH_CC),)
      ifneq ($(OBJ_ARCH),$(HOST_ARCH_CC))
        $(info [arch] Removing stale $(OBJ_ARCH) objects for $(HOST_ARCH_CC) build)
        $(shell rm -f src/*.o jasmin/*.o)
      endif
    endif
  endif
endif

# ═══════════════════════════════════════════════════════════════════
# BUILD RULES
# ═══════════════════════════════════════════════════════════════════

.PHONY: all clean install uninstall test test-all test-asan test-asan-run test-vectors test-vv fuzz-build fuzz-format fuzz-format-run help audit-licenses dist check

all: $(TARGET)

# ═══════════════════════════════════════════════════════════════════
# audit-licenses — verify every source file carries the correct SPDX
# header. AGPL-3.0-or-later for all Zupt code, GPL-3.0-or-later for
# VaptVupt files (vv_* and vaptvupt*) — see THIRD-PARTY-NOTICES.md
# for the rationale.
# ═══════════════════════════════════════════════════════════════════
audit-licenses:
	@MISSING=0; WRONG=0; \
	for f in $$(find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.hpp' \
	             -o -name '*.py' -o -name '*.sh' -o -name '*.yml' \
	             -o -name '*.jazz' -o -name '*.s' -o -name 'Makefile' \
	             -o -name '*.map' \) \
	             -not -path './build/*' \
	             -not -path './build_obj/*' \
	             -not -path './sdk/build/*' \
	             -not -path './vendor/zuptsdk/include/*'); do \
	    BASE=$$(basename "$$f"); \
	    case "$$BASE" in \
	        vv_*|vaptvupt*) \
	            EXPECTED="SPDX-License-Identifier: GPL-3.0-or-later" ;; \
	        *) \
	            EXPECTED="SPDX-License-Identifier: AGPL-3.0-or-later" ;; \
	    esac; \
	    if ! grep -q "SPDX-License-Identifier" "$$f"; then \
	        echo "  ✗ $$f (missing SPDX)"; \
	        MISSING=$$((MISSING+1)); \
	    elif ! grep -q "$$EXPECTED" "$$f"; then \
	        echo "  ✗ $$f (wrong SPDX, expected: $$EXPECTED)"; \
	        WRONG=$$((WRONG+1)); \
	    fi; \
	done; \
	if [ $$MISSING -eq 0 ] && [ $$WRONG -eq 0 ]; then \
	    echo "  ✓ All source files carry correct SPDX headers"; \
	    echo "    (AGPL-3.0-or-later for Zupt, GPL-3.0-or-later for VaptVupt)"; \
	else \
	    echo ""; \
	    echo "  $$MISSING missing, $$WRONG with wrong SPDX. Aborting."; \
	    exit 1; \
	fi

# Jasmin pre-compiled assembly (x86_64 only)
# Jasmin emits GNU-as syntax (macros with C-style trailing comments);
# clang's integrated assembler rejects it, so assemble with as(1) directly.
jasmin/%.o: jasmin/%.s
	$(Q)as -o $@ $<

# VaptVupt SIMD files: compile with AVX2 on x86_64
$(VV_SIMD_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(VV_SIMD_FLAGS) -c -o $@ $<

# VaptVupt non-SIMD files
$(VV_PLAIN_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Zupt core files (the SHA-NI object has its own rule below with -msha)
ZUPT_OBJS_GENERIC = $(filter-out src/zupt_sha256_shani.o,$(ZUPT_OBJS))
$(ZUPT_OBJS_GENERIC): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# SHA-NI path needs -msha -mssse3 -msse4.1 on x86_64.
# On non-x86_64, SHANI_FLAGS is empty and the file is a no-op TU.
src/zupt_sha256_shani.o: src/zupt_sha256_shani.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(SHANI_FLAGS) -c -o $@ $<

# Final link step. Order matters: CFLAGS before LDFLAGS, then objects,
# then LDLIBS — keeps GCC/Clang happy when LDFLAGS contains -pie or
# similar position-sensitive flags.
$(TARGET): $(ALL_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJS) $(JAZZ_O) -o $(TARGET) $(LDLIBS)
	@# v3.0.0: in-tree legacy symlink. Existing tests, scripts and IDE
	@# launchers reference `./zupt`; we keep that working without
	@# modifying 27 test files. The install rule emits the same symlink
	@# at $(BINDIR)/zupt for runtime users.
	$(Q)ln -sf $(TARGET) $(LEGACY_LINK)
	@echo "Build complete: ./$(TARGET) [$(ARCH)] (legacy: ./$(LEGACY_LINK) -> $(TARGET))"

# ═══════════════════════════════════════════════════════════════════
# INSTALL / UNINSTALL
# ═══════════════════════════════════════════════════════════════════

install: $(TARGET)
	$(Q)mkdir -p $(DESTDIR)$(BINDIR)
	$(Q)install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	# v3.0.0 (INPI Brasil rename): legacy `zupt` symlink so existing
	# scripts and shell history keep working. Distros may strip this
	# after one major version cycle.
	$(Q)ln -sf $(TARGET) $(DESTDIR)$(BINDIR)/$(LEGACY_LINK)

	$(Q)if [ -f "$(MANPAGE)" ]; then \
		mkdir -p $(DESTDIR)$(MAN1DIR); \
		$(GZIP) $(GZIPFLAGS) -c "$(MANPAGE)" > "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
		chmod 0644 "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
		ln -sf "$(MANPAGE_GZ)" "$(DESTDIR)$(MAN1DIR)/$(LEGACY_LINK).1.gz"; \
		echo "Installed: $(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ) (+ $(LEGACY_LINK).1.gz symlink)"; \
	else \
		echo "Warning: man page not found: $(MANPAGE)"; \
	fi

	# Shell completions (v2.4.7+). Honour distro path conventions where
	# possible; downstream packagers can override DESTDIR + the specific
	# dirs as needed.
	$(Q)if [ -f completions/vaptvupt.bash ]; then \
		mkdir -p "$(DESTDIR)$(PREFIX)/share/bash-completion/completions"; \
		install -m 0644 completions/vaptvupt.bash \
			"$(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(TARGET)"; \
		ln -sf "$(TARGET)" "$(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(LEGACY_LINK)"; \
		echo "Installed: $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(TARGET) (+ $(LEGACY_LINK) symlink)"; \
	fi
	$(Q)if [ -f completions/_vaptvupt ]; then \
		mkdir -p "$(DESTDIR)$(PREFIX)/share/zsh/site-functions"; \
		install -m 0644 completions/_vaptvupt \
			"$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(TARGET)"; \
		ln -sf "_$(TARGET)" "$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(LEGACY_LINK)"; \
		echo "Installed: $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(TARGET) (+ _$(LEGACY_LINK) symlink)"; \
	fi
	$(Q)if [ -f completions/vaptvupt.fish ]; then \
		mkdir -p "$(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d"; \
		install -m 0644 completions/vaptvupt.fish \
			"$(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(TARGET).fish"; \
		echo "Installed: $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(TARGET).fish"; \
	fi

	# Vendored runtime libraries — installed ONLY for a WITH_SDK=1 build. In the
	# default source-only build the binary links no external library and there is
	# nothing to install here (the vendored .so are prebuilt binaries kept out of
	# the source tree).
ifeq ($(WITH_SDK),1)
	$(Q)mkdir -p $(DESTDIR)$(PREFIX)/lib/vaptvupt
	$(Q)install -m 755 vendor/zuptsdk/libzuptsdk.so.2.0.0 $(DESTDIR)$(PREFIX)/lib/vaptvupt/libzuptsdk.so.2.0.0
	$(Q)ln -sf libzuptsdk.so.2.0.0 $(DESTDIR)$(PREFIX)/lib/vaptvupt/libzuptsdk.so.2
	$(Q)ln -sf libzuptsdk.so.2.0.0 $(DESTDIR)$(PREFIX)/lib/vaptvupt/libzuptsdk.so
	$(Q)install -m 755 vendor/pqvaptvupt/libpqvaptvupt.so.0.6.0 $(DESTDIR)$(PREFIX)/lib/vaptvupt/libpqvaptvupt.so.0.6.0
	$(Q)ln -sf libpqvaptvupt.so.0.6.0 $(DESTDIR)$(PREFIX)/lib/vaptvupt/libpqvaptvupt.so.0
	$(Q)ln -sf libpqvaptvupt.so.0.6.0 $(DESTDIR)$(PREFIX)/lib/vaptvupt/libpqvaptvupt.so
endif

	@echo "Installed: $(DESTDIR)$(BINDIR)/$(TARGET) (legacy: $(DESTDIR)$(BINDIR)/$(LEGACY_LINK) -> $(TARGET))"

uninstall:
	$(Q)rm -rf $(DESTDIR)$(PREFIX)/lib/vaptvupt
	$(Q)rm -f $(DESTDIR)$(BINDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(LEGACY_LINK)
	$(Q)rm -f $(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ) $(DESTDIR)$(MAN1DIR)/$(LEGACY_LINK).1.gz
	$(Q)rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(TARGET) \
	          $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(LEGACY_LINK)
	$(Q)rm -f $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_zupt
	$(Q)rm -f $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/zupt.fish

# ═══════════════════════════════════════════════════════════════════
# DIST — reproducible source tarball for distro packaging
# ═══════════════════════════════════════════════════════════════════
#
# `make dist` produces zupt-VERSION.tar.gz that is BYTE-IDENTICAL given
# the same input source tree. Properties:
#
#   - Files sorted by name (stable order regardless of filesystem layout)
#   - mtime fixed to SOURCE_DATE_EPOCH (or to the version-string-derived
#     epoch when SOURCE_DATE_EPOCH is unset)
#   - uid/gid fixed to root (0/0) via --owner / --group
#   - gzip wrapped with --no-name (no embedded timestamp/filename)
#   - No binaries, no .o, no .so. Source only.
#
# Used by AUR / Debian / Homebrew / RPM upstream packaging.
# Output: /tmp/zupt-VERSION.tar.gz so it doesn't pollute the source tree.

DIST_VERSION = $(shell grep '^\#define ZUPT_VERSION_STRING' include/zupt.h | awk -F'"' '{print $$2}')
DIST_NAME    = $(TARGET)-$(DIST_VERSION)
DIST_DIR     = /tmp/$(DIST_NAME).distbuild
DIST_TARBALL = /tmp/$(DIST_NAME).tar.gz
SOURCE_DATE_EPOCH ?= 1747699200   # 2025-05-20 UTC — stable epoch for this release line

dist: clean
	$(Q)rm -rf $(DIST_DIR) $(DIST_TARBALL)
	$(Q)mkdir -p $(DIST_DIR)/$(DIST_NAME)
	$(Q)git ls-files 2>/dev/null > $(DIST_DIR)/filelist.txt || \
	    find . \( -type f -o -type l \) \! -path './.git/*' \! -path './*.o' \! -name '*.o' \! -name '$(TARGET)' \
	         \! -name '$(LEGACY_LINK)' \
	         \! -name 'zupt_asan' \! -name 'test_vectors' \! -name 'test_vaptvupt' \
	         \! -name 'fuzz_decompress' \! -name 'fuzz_vv_decompress' \
	         \! -path './.distbuild*' 2>/dev/null | sed 's|^\./||' | sort > $(DIST_DIR)/filelist.txt
	$(Q)tar -cf - --files-from=$(DIST_DIR)/filelist.txt | tar -xf - -C $(DIST_DIR)/$(DIST_NAME)
	$(Q)find $(DIST_DIR)/$(DIST_NAME) -exec touch -d "@$(SOURCE_DATE_EPOCH)" {} +
	$(Q)tar --sort=name \
	       --owner=0 --group=0 --numeric-owner \
	       --mtime="@$(SOURCE_DATE_EPOCH)" \
	       -C $(DIST_DIR) -cf - $(DIST_NAME) \
	    | gzip -9n > $(DIST_TARBALL)
	$(Q)rm -rf $(DIST_DIR)
	@echo ""
	@echo "  Reproducible source tarball:"
	@echo "    $(DIST_TARBALL)"
	@echo "    sha256: `sha256sum $(DIST_TARBALL) | awk '{print $$1}'`"
	@echo "    bytes:  `wc -c < $(DIST_TARBALL)`"
	@echo "  Reproducibility: re-run 'make dist' on the same tree, sha256 MUST match."

# ═══════════════════════════════════════════════════════════════════
# CLEAN
# ═══════════════════════════════════════════════════════════════════

clean:
	$(Q)rm -f $(TARGET) $(MANPAGE_GZ) zupt_asan test_vectors test_vaptvupt \
		fuzz_decompress fuzz_vv_decompress jasmin/*.o src/*.o

# ═══════════════════════════════════════════════════════════════════
# TEST TARGETS
# ═══════════════════════════════════════════════════════════════════

test: $(TARGET)
	$(Q)sh tests/run_quick.sh
	$(Q)bash tests/test_sdk.sh
	$(Q)bash tests/test_audit.sh
	$(Q)bash tests/test_dedup_props.sh
	$(Q)bash tests/test_path_traversal.sh
	$(Q)bash tests/test_arg_order.sh
	$(Q)bash tests/test_block_swap.sh
	$(Q)bash tests/test_dedup_nonce.sh
	$(Q)bash tests/test_mlkem_fips203.sh
	$(Q)bash tests/test_f08_topmac.sh
	$(Q)bash tests/test_f09_preface.sh
	$(Q)bash tests/test_f10_kdf_default.sh
	$(Q)bash tests/test_f11_authfail_message.sh
	$(Q)bash tests/test_f12_comment.sh
	$(Q)bash tests/test_gui_branding.sh
	$(Q)bash tests/test_help_consistency.sh
	$(Q)bash tests/test_static_analysis.sh
	$(Q)bash tests/test_vv_decode_slack.sh
	$(Q)bash tests/test_sha256_shani.sh
	$(Q)bash tests/test_hmac_incremental.sh
	$(Q)bash tests/test_kdf_transparency.sh
	$(Q)bash tests/test_ct_timing.sh
	$(Q)bash tests/test_codec_exact_size.sh
	$(Q)bash tests/test_pqbox.sh
	$(Q)bash tests/test_packaging_syntax.sh
	$(Q)bash tests/test_completions_manpage.sh
	$(Q)bash tests/test_dist_reproducible.sh

test-all: $(TARGET) test-vectors test-vv
	@echo "==============================================="
	@sh tests/regression.sh 2>&1 | tail -3
	@echo ""
	@sh tests/test_threaded.sh 2>&1 | tail -3
	@echo ""
	@sh tests/test_pq.sh ./zupt 2>&1 | tail -3
	@echo ""
	@./test_vectors 2>&1 | tail -2
	@echo ""
	@./test_vaptvupt 2>&1 | tail -2
	@echo "==============================================="

# ═══════════════════════════════════════════════════════════════════
# CHECK — distro-friendly safe subset
# ═══════════════════════════════════════════════════════════════════
#
# Targeted at downstream packagers (openSUSE OBS, Debian, Fedora) who
# need a `%check` / `override_dh_auto_test` target that:
#
#   - Runs in a few minutes (not the full byte-sweep arc)
#   - Doesn't call `make clean` mid-stream (rules out test_dist_reproducible.sh)
#   - Doesn't depend on tools that may be absent in the build chroot
#     (no python3 PyYAML, no ruby, no dpkg-parsechangelog)
#   - Doesn't depend on multi-threading that's flaky under emulation
#     (skips test_threaded.sh and test_pq.sh's MT subset)
#   - Covers the security-critical regressions: F-06 HMAC, F-08 AIT,
#     F-09 byte-level integrity, F-10 KDF default, F-11 auth-fail
#     wording, F-12 comments
#   - Verifies cryptographic primitives against NIST/RFC vectors
#
# This is the recommended target for OBS %check sections.

check: $(TARGET) test-vectors
	$(Q)sh tests/run_quick.sh
	$(Q)bash tests/test_audit.sh
	$(Q)bash tests/test_path_traversal.sh
	$(Q)bash tests/test_arg_order.sh
	$(Q)bash tests/test_block_swap.sh
	$(Q)bash tests/test_dedup_nonce.sh
	$(Q)bash tests/test_mlkem_fips203.sh
	$(Q)bash tests/test_f08_topmac.sh
	$(Q)bash tests/test_f10_kdf_default.sh
	$(Q)bash tests/test_f11_authfail_message.sh
	$(Q)bash tests/test_f12_comment.sh
	$(Q)bash tests/test_gui_branding.sh
	$(Q)bash tests/test_help_consistency.sh
	$(Q)bash tests/test_static_analysis.sh
	$(Q)bash tests/test_vv_decode_slack.sh
	$(Q)bash tests/test_sha256_shani.sh
	$(Q)bash tests/test_hmac_incremental.sh
	$(Q)bash tests/test_kdf_transparency.sh
	$(Q)bash tests/test_ct_timing.sh
	$(Q)bash tests/test_codec_exact_size.sh
	$(Q)bash tests/test_pqbox.sh
	$(Q)./test_vectors
	@echo ""
	@echo "  ═════════════════════════════════════════"
	@echo "  All distro-safe checks passed."
	@echo "  ═════════════════════════════════════════"

test-vectors: tests/test_vectors.c $(HEADERS)
	$(Q)$(CC) -O2 -std=c11 -Iinclude -Isrc $(SHANI_FLAGS) $(LDFLAGS) tests/test_vectors.c \
	    src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_crypto.c src/zupt_aes256.c src/zupt_xxh.c \
	    src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c \
	    src/zupt_mlock.c \
	    -o test_vectors $(LDLIBS)

# F-06 regression — HMAC accept-on-disjoint-bits (Zupt 2.2.5).
# Inherits $(CFLAGS) so ZUPT_USE_JASMIN is defined on x86_64 (exercising
# the original buggy path). Links the same crypto modules as test-vectors
# plus the Jasmin .o files when available.
test-f06: tests/test_f06_hmac.c $(HEADERS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) $(SHANI_FLAGS) $(LDFLAGS) tests/test_f06_hmac.c \
	    src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_crypto.c src/zupt_aes256.c src/zupt_xxh.c \
	    src/zupt_keccak.c src/zupt_cpuid.c src/zupt_mlock.c \
	    src/zupt_x25519.c src/zupt_mlkem.c $(JAZZ_O) \
	    -o test_f06 $(LDLIBS)
	$(Q)./test_f06

# VAPTVUPT: VaptVupt codec unit tests
test-vv: tests/test_vaptvupt.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(VV_SIMD_FLAGS) $(LDFLAGS) tests/test_vaptvupt.c \
	    src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_huffman.c \
	    src/vv_simd.c src/vv_xxh64.c src/vaptvupt_api.c src/zupt_xxh.c src/zupt_cpuid.c \
	    -o test_vaptvupt $(LDLIBS)
	$(Q)./test_vaptvupt

test-asan: $(SOURCES) $(HEADERS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) -fsanitize=address,undefined -g -O1 \
	    $(VV_SIMD_FLAGS) $(SHANI_FLAGS) $(LDFLAGS) \
	    $(SOURCES) $(JAZZ_O) -o zupt_asan $(LDLIBS)
	@echo "ASAN build: ./zupt_asan"

# Build the format-parser fuzz harness. Runs against ./zupt_asan to catch
# memory errors AND crashes in mutation-fuzz of the listing/extract path.
fuzz-format: tests/fuzz_format

tests/fuzz_format: tests/fuzz_format.c
	$(Q)$(CC) -std=c11 -O2 -Wall tests/fuzz_format.c -o tests/fuzz_format
	@echo "Format fuzz harness: ./tests/fuzz_format"

# Run 5000 iterations of mutation fuzz against the ASAN binary.
# Any crash or sanitizer error fails CI.
fuzz-format-run: tests/fuzz_format test-asan $(TARGET)
	@echo "Building seed archive..."
	@echo "fuzz seed file" > /tmp/_zupt_fuzz_input.txt
	@./zupt c /tmp/_zupt_fuzz_seed.zupt /tmp/_zupt_fuzz_input.txt > /dev/null 2>&1
	@ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
	    ./tests/fuzz_format 1000 ./zupt_asan /tmp/_zupt_fuzz_seed.zupt
	@rm -f /tmp/_zupt_fuzz_input.txt /tmp/_zupt_fuzz_seed.zupt
	@echo "  Format fuzz: 1000 iters under ASAN/UBSAN — no crashes."

# Runs the test suites against the ASAN-instrumented binary.
# Catches use-after-free, OOB, leaks, signed-overflow that aren't visible
# in the optimized release build.
test-asan-run: test-asan
	@echo "Running test suites under ASAN/UBSAN..."
	@ZUPT_BIN_OVERRIDE=$$(realpath ./zupt_asan); \
	  cp $$ZUPT_BIN_OVERRIDE zupt.bak 2>/dev/null; \
	  ln -sf zupt_asan zupt_asan_run; \
	  mv zupt zupt.real; \
	  ln -sf zupt_asan zupt; \
	  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 sh tests/run_quick.sh; \
	  rc1=$$?; \
	  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 bash tests/test_sdk.sh; \
	  rc2=$$?; \
	  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 bash tests/test_audit.sh; \
	  rc3=$$?; \
	  rm zupt zupt_asan_run; mv zupt.real zupt; \
	  if [ $$rc1 -eq 0 ] && [ $$rc2 -eq 0 ] && [ $$rc3 -eq 0 ]; then \
	    echo ""; echo "  ASAN/UBSAN: all tests pass cleanly."; \
	  else \
	    echo ""; echo "  ASAN/UBSAN: failures detected (run codes $$rc1 $$rc2 $$rc3)."; exit 1; \
	  fi

# AFL++ fuzzing harnesses (requires afl-clang-fast)
fuzz-build:
	@echo "Building AFL++ fuzzing harnesses..."
	$(Q)afl-clang-fast -fsanitize=address,undefined -g -O1 -std=c11 \
	    -Iinclude -Isrc $(VV_SIMD_FLAGS) $(LDFLAGS) \
	    $(filter-out src/zupt_main.c,$(SOURCES)) tests/fuzz_decompress.c \
	    -o fuzz_decompress $(LDLIBS)
	$(Q)afl-clang-fast -fsanitize=address,undefined -g -O1 -std=c11 \
	    -Iinclude -Isrc $(VV_SIMD_FLAGS) $(LDFLAGS) \
	    tests/fuzz_vv_decompress.c \
	    src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_huffman.c \
	    src/vv_simd.c src/zupt_xxh.c src/zupt_cpuid.c \
	    -o fuzz_vv_decompress $(LDLIBS)
	@echo "Fuzz harnesses built. Run:"
	@echo "  afl-fuzz -i corpus -o findings -- ./fuzz_decompress"
	@echo "  afl-fuzz -i corpus_vv -o findings_vv -- ./fuzz_vv_decompress"

help:
	@echo "Zupt v$(shell grep '^#define ZUPT_VERSION_STRING' include/zupt.h | awk -F'\"' '{print $$2}') build targets:"
	@echo "  make              Build zupt binary"
	@echo "  make V=1          Build with verbose output"
	@echo "  make test         Quick test"
	@echo "  make test-all     Full test suite (regression + threaded + PQ + vectors + VV)"
	@echo "  make test-vv      VaptVupt codec unit tests"
	@echo "  make test-asan    Build with AddressSanitizer"
	@echo "  make fuzz-build   Build AFL++ fuzzing harnesses"
	@echo "  make install      Install to $(PREFIX)"
	@echo "  make uninstall    Remove from $(PREFIX)"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Architecture: $(ARCH)"
	@echo "  x86_64:   Jasmin CT crypto + AVX2 SIMD decode"
	@echo "  aarch64:  C crypto fallback + NEON SIMD decode"
	@echo "  other:    C crypto fallback + scalar decode"

# ─────────────────────────────────────────────────────────────────────
#  SDK targets — see sdk/Makefile.sdk
# ─────────────────────────────────────────────────────────────────────
include sdk/Makefile.sdk
