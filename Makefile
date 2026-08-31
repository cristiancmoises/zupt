# SPDX-License-Identifier: AGPL-3.0-or-later
# ZUPT — backup compression with hybrid post-quantum encryption
# Build system. Pure GNU make, no autotools, no cmake required.
#
# Targets:
#   make                Build the zupt binary
#   make V=1            Verbose: show every command line
#   make install        Install to /usr/local (override with PREFIX=/usr)
#   make check          Run the source-only distribution test suite
#   make test-all       Run the extended upstream test suite
#   make test-asan      Build with AddressSanitizer + UBSan
#   make test-asan-run  Execute the sanitizer smoke test
#   make clean          Remove build artifacts
#
# Build profiles (all controllable via standard env vars):
#   CC=clang make                          Use Clang instead of GCC
#   CFLAGS="-O3 -g" make                   Override the default optimization
#   make PREFIX=/usr DESTDIR=/tmp/stage    Staged install for packagers
#
# The compiler target, rather than the build host, controls architecture
# selection. This keeps cross builds from accidentally enabling host assembly.
CC             ?= cc
CPPFLAGS       ?=
CFLAGS         ?= -O2 -g
LDFLAGS        ?=
LDLIBS         ?=
AR             ?= ar
ARFLAGS        ?= rcs
RANLIB         ?= ranlib
STRIP          ?= strip
PKG_CONFIG     ?= pkg-config
ASFLAGS        ?=

# GNU make has a built-in ARFLAGS=rv. Use archive creation flags by default,
# while preserving values supplied through the environment or command line.
ifeq ($(origin ARFLAGS),default)
  ARFLAGS := rcs
endif

DESTDIR        ?=
PREFIX         ?= /usr/local
BINDIR         ?= $(PREFIX)/bin
LIBDIR         ?= $(PREFIX)/lib
INCLUDEDIR     ?= $(PREFIX)/include
DATADIR        ?= $(PREFIX)/share
MANDIR         ?= $(DATADIR)/man
MAN1DIR        ?= $(MANDIR)/man1
BASHCOMPDIR    ?= $(DATADIR)/bash-completion/completions
ZSHCOMPDIR     ?= $(DATADIR)/zsh/site-functions
FISHCOMPDIR    ?= $(DATADIR)/fish/vendor_completions.d
LICENSEDIR     ?= $(DATADIR)/licenses/zupt
GZIP           ?= gzip
GZIPFLAGS      ?= -9 -n
INSTALL_LEGACY_ALIAS ?= 0
INSTALL_LICENSES ?= 1
LICENSE_FILES  = LICENSE LICENSE-AGPL-3.0 LICENSE-GPL-3.0 \
                 LICENSE-BSD-2-Clause LICENSE-BSD-3-Clause LICENSE-CC0-1.0 \
                 NOTICE THIRD-PARTY-NOTICES.md

# Standard packager variables above are never rewritten. Project-owned flags
# are passed alongside them on every command line.
PROJECT_CPPFLAGS := -D_DEFAULT_SOURCE -Iinclude -Isrc
PROJECT_CFLAGS   := -Wall -Wextra -Woverlength-strings -std=c11
PROJECT_LDFLAGS  :=
PROJECT_CLI_LDFLAGS :=
PROJECT_LDLIBS   := -lm
EXEEXT           :=
CREATE_TEST_ALIAS := 0
FEATURE_CPPFLAGS :=
FEATURE_LDLIBS   :=

# Clang's -Wcast-align diagnoses the pointer casts required by the explicitly
# unaligned x86 load/store intrinsics, and cannot infer alignment through the
# byte-backed VaptVupt arenas.  Those arenas start at malloc alignment and all
# typed offsets are rounded to at least 8 bytes.  Keep the compatibility
# suppression local to the three audited translation units; every other file
# retains a caller-supplied -Wcast-align/-Werror policy.
CLANG_CAST_ALIGN_FLAGS :=
ifneq ($(findstring clang,$(shell $(CC) --version 2>/dev/null | head -n 1)),)
  CLANG_CAST_ALIGN_FLAGS := -Wno-cast-align
endif
CLANG_CAST_ALIGN_OBJS := src/vv_ans.o src/vv_simd.o src/zupt_sha256_shani.o

TARGET_MACHINE ?= $(shell $(CC) -dumpmachine 2>/dev/null)
TARGET_CPU     := $(firstword $(subst -, ,$(TARGET_MACHINE)))
ifeq ($(strip $(TARGET_CPU)),)
  TARGET_CPU := unknown
endif

# The Windows extraction path uses the documented NtCreateFile RootDirectory
# facility so directory components are resolved relative to pinned handles.
# A self-contained PE is required because POSIX-thread MinGW toolchains may
# otherwise add an undeclared libwinpthread-1.dll runtime dependency.
ifneq ($(strip $(findstring mingw,$(TARGET_MACHINE))$(findstring windows,$(TARGET_MACHINE))),)
  EXEEXT := .exe
  CREATE_TEST_ALIAS := 0
  PROJECT_LDFLAGS += -static
  PROJECT_CLI_LDFLAGS += -municode
  PROJECT_LDLIBS += -lntdll
endif

# pthread is part of bionic and the Windows implementation uses native APIs.
ifeq ($(findstring android,$(TARGET_MACHINE)),)
  ifeq ($(findstring mingw,$(TARGET_MACHINE)),)
    ifeq ($(findstring windows,$(TARGET_MACHINE)),)
      PROJECT_CFLAGS += -pthread
      PROJECT_LDLIBS += -pthread
    endif
  endif
endif

ifneq ($(filter $(INSTALL_LEGACY_ALIAS),0 1),$(INSTALL_LEGACY_ALIAS))
  $(error INSTALL_LEGACY_ALIAS must be 0 or 1)
endif
ifneq ($(filter $(INSTALL_LICENSES),0 1),$(INSTALL_LICENSES))
  $(error INSTALL_LICENSES must be 0 or 1)
endif

# --- Verbose build ---
V ?= 0
ifeq ($(V),1)
  Q =
else
  Q = @
endif

# --- ZUPT core sources ---
ZUPT_SOURCES = src/zupt_main.c src/zupt_format.c src/zupt_lz.c src/zupt_lzh.c \
               src/zupt_xxh.c src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_aes256.c src/zupt_crypto.c \
               src/zupt_crypto_sdk.c src/zupt_crypto_pqbox.c \
               src/zupt_predict.c src/zupt_parallel.c src/zupt_keccak.c \
               src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c \
               src/zupt_filetype.c src/zupt_disk.c src/zupt_dedup.c

# --- Optional system libraries (never vendored, never downloaded) ---
WITH_SDK ?= 0
WITH_PQBOX ?= 0

ifneq ($(filter $(WITH_SDK),0 1),$(WITH_SDK))
  $(error WITH_SDK must be 0 or 1)
endif
ifneq ($(filter $(WITH_PQBOX),0 1),$(WITH_PQBOX))
  $(error WITH_PQBOX must be 0 or 1)
endif

ifeq ($(WITH_SDK),1)
  SDK_PKG_CONFIG ?= libvuptsdk
  SDK_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags $(SDK_PKG_CONFIG) 2>/dev/null)
  SDK_LDLIBS   ?= $(shell $(PKG_CONFIG) --libs $(SDK_PKG_CONFIG) 2>/dev/null)
  ifeq ($(strip $(SDK_LDLIBS)),)
    $(error WITH_SDK=1 requires the system libvuptsdk development package; set SDK_CPPFLAGS and SDK_LDLIBS to explicit system paths if no pkg-config file is provided)
  endif
  FEATURE_CPPFLAGS += -DZUPT_WITH_SDK $(SDK_CPPFLAGS)
  FEATURE_LDLIBS   += $(SDK_LDLIBS)
endif

ifeq ($(WITH_PQBOX),1)
  PQBOX_PKG_CONFIG ?= libpqvaptvupt
  PQBOX_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags $(PQBOX_PKG_CONFIG) 2>/dev/null)
  PQBOX_LDLIBS   ?= $(shell $(PKG_CONFIG) --libs $(PQBOX_PKG_CONFIG) 2>/dev/null)
  ifeq ($(strip $(PQBOX_LDLIBS)),)
    $(error WITH_PQBOX=1 requires the system libpqvaptvupt development package; set PQBOX_CPPFLAGS and PQBOX_LDLIBS to explicit system paths if no pkg-config file is provided)
  endif
  FEATURE_CPPFLAGS += -DZUPT_WITH_PQBOX $(PQBOX_CPPFLAGS)
  FEATURE_LDLIBS   += $(PQBOX_LDLIBS)
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
           src/zupt_thread.h src/zupt_parallel.h src/zupt_internal.h

PROGRAM     = zupt
TARGET      = $(PROGRAM)$(EXEEXT)
LEGACY_PROGRAM = vaptvupt
LEGACY_LINK = $(LEGACY_PROGRAM)$(EXEEXT)
MANPAGE    = doc/zupt.1
MANPAGE_GZ = $(PROGRAM).1.gz

# Architecture-specific code is opt-in and isolated. The normal x86_64 build
# stays at the ABI baseline; in particular, no complete codec TU gets -mavx2.
SHANI_FLAGS :=
ifneq ($(filter x86_64 amd64 i386 i486 i586 i686,$(TARGET_CPU)),)
  SHANI_FLAGS := -msha -mssse3 -msse4.1
endif

# Optional textual assembly is disabled by default so every
# compiler/architecture has the audited C fallback. Four files are jasminc
# outputs and zupt_aes_ctr4.s is separately identified as hand-written. When
# requested, the compiler driver assembles them while preserving cross-target
# and sysroot settings.
WITH_JASMIN ?= 0
ifneq ($(filter $(WITH_JASMIN),0 1),$(WITH_JASMIN))
  $(error WITH_JASMIN must be 0 or 1)
endif
JAZZ_S = jasmin/zupt_mac_verify.s jasmin/zupt_mlkem_select.s \
         jasmin/zupt_aes_ctr.s jasmin/zupt_x25519_fe.s jasmin/zupt_aes_ctr4.s
JAZZ_O :=
ifeq ($(WITH_JASMIN),1)
  ifeq ($(filter x86_64 amd64,$(TARGET_CPU)),)
    $(error WITH_JASMIN=1 is supported only for an x86_64 compiler target; detected $(TARGET_MACHINE))
  endif
  ifneq ($(words $(wildcard $(JAZZ_S))),$(words $(JAZZ_S)))
    $(error WITH_JASMIN=1 requested, but one or more optional .s sources are missing)
  endif
  FEATURE_CPPFLAGS += -DZUPT_USE_JASMIN
  JAZZ_O := $(JAZZ_S:.s=.o)
endif

# --- Object files ---
# These objects contain the baseline codec implementation. Optimized SHA-NI
# remains in its own translation unit below and is guarded at runtime.
VV_SIMD_OBJS  = src/vv_encoder.o src/vv_decoder.o src/vv_simd.o

# The bundled codec uses the same warning policy as the application.  Do not
# add broad -Wno-* flags here: localized upstream changes are recorded in
# THIRD-PARTY-NOTICES.md and must compile without masked diagnostics.
VV_PLAIN_OBJS = src/vv_ans.o src/vv_huffman.o src/vv_xxh64.o src/vv_bcj.o src/vaptvupt_api.o
ZUPT_OBJS     = $(patsubst %.c,%.o,$(ZUPT_SOURCES))
ALL_OBJS      = $(ZUPT_OBJS) $(VV_SIMD_OBJS) $(VV_PLAIN_OBJS)

# ═══════════════════════════════════════════════════════════════════
# BUILD RULES
# ═══════════════════════════════════════════════════════════════════

.DELETE_ON_ERROR:
.PHONY: all clean install uninstall test test-all release-check test-asan test-asan-run \
        test-vectors test-f06 test-vv fuzz-build fuzz-format fuzz-format-run \
        help audit-licenses source-audit dist check

all: $(TARGET)

# ═══════════════════════════════════════════════════════════════════
# audit-licenses — verify covered code, build, CI, and packaging files carry
# the correct SPDX marker.  Legal-document completeness is audited separately
# through LICENSE*, NOTICE, and THIRD-PARTY-NOTICES.md; this target is not a
# claim of full REUSE conformance.
# AGPL-3.0-or-later for the application/core, GPL-3.0-or-later for the
# bundled codec files, BSD-2-Clause for the two xxHash-derived units, and
# CC0-1.0 for the pq-crystals/kyber-derived portions of native ML-KEM, and
# BSD-3-Clause for curve25519-donna-derived X25519 portions.
# See THIRD-PARTY-NOTICES.md.
# ═══════════════════════════════════════════════════════════════════
audit-licenses:
	@MISSING=0; WRONG=0; \
	for f in $$(find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.hpp' \
	             -o -name '*.py' -o -name '*.sh' -o -name '*.yml' -o -name '*.yaml' \
	             -o -name '*.jazz' -o -name '*.s' -o -name '*.S' -o -name 'Makefile' \
	             -o -name '*.map' -o -name '*.bat' -o -name '*.command' \
	             -o -name '*.desktop' -o -name '*.nemo_action' -o -name '*.spec' \
	             -o -name '*.rb' -o -name '*.scm' -o -name '*.nix' \
	             -o -name '*.iss' -o -name '*.nsi' -o -name '*.fish' \
	             -o -name 'PKGBUILD' -o -name '_service' -o -name 'rules' \) \
	             -not -path './build/*' \
	             -not -path './build_obj/*' \
	             -not -path './sdk/build/*'); do \
	    case "$$f" in \
	        ./src/zupt_mlkem.c) \
	            EXPECTED_ID="AGPL-3.0-or-later AND CC0-1.0" ;; \
	        ./src/zupt_x25519.c) \
	            EXPECTED_ID="AGPL-3.0-or-later AND BSD-3-Clause" ;; \
	        ./src/zupt_xxh.c) \
	            EXPECTED_ID="AGPL-3.0-or-later AND BSD-2-Clause" ;; \
	        ./src/vv_xxh64.c) \
	            EXPECTED_ID="GPL-3.0-or-later AND BSD-2-Clause" ;; \
	        ./src/vv_*.c|./src/vaptvupt_api.c|./include/vv_*.h|./include/vaptvupt*.h) \
	            EXPECTED_ID="GPL-3.0-or-later" ;; \
	        *) \
	            EXPECTED_ID="AGPL-3.0-or-later" ;; \
	    esac; \
	    HEADER=$$(sed -n '1,12p' "$$f"); \
	    HEADER_COUNT=$$(printf '%s\n' "$$HEADER" | \
	        grep -c 'SPDX-License-Identifier:' || true); \
	    ACTUAL_ID=$$(printf '%s\n' "$$HEADER" | \
	        sed -n 's/^.*SPDX-License-Identifier:[[:space:]]*//p' | \
	        sed 's/[[:space:]]*\*\/[[:space:]]*$$//; s/[[:space:]]*-->[[:space:]]*$$//; s/[[:space:]]*$$//' | \
	        head -n 1); \
	    if [ "$$HEADER_COUNT" -eq 0 ]; then \
	        echo "  ✗ $$f (missing SPDX)"; \
	        MISSING=$$((MISSING+1)); \
	    elif [ "$$HEADER_COUNT" -ne 1 ] || [ "$$ACTUAL_ID" != "$$EXPECTED_ID" ]; then \
	        echo "  ✗ $$f (wrong SPDX header, expected exactly once: $$EXPECTED_ID)"; \
	        WRONG=$$((WRONG+1)); \
	    fi; \
	done; \
	if [ $$MISSING -eq 0 ] && [ $$WRONG -eq 0 ]; then \
	    echo "  ✓ Covered code/build/CI/packaging files carry correct SPDX markers"; \
	    echo "    (AGPL core; GPL codec; BSD-2 XXH64; BSD-3 X25519; CC0 ML-KEM)"; \
	else \
	    echo ""; \
	    echo "  $$MISSING missing, $$WRONG with wrong SPDX. Aborting."; \
	    exit 1; \
	fi

# Optional Jasmin textual assembly (x86_64 only). Use the compiler driver so a
# cross compiler's target, sysroot, assembler and reproducibility flags apply.
jasmin/%.o: jasmin/%.s
	$(Q)$(CC) $(CPPFLAGS) $(ASFLAGS) -c -o $@ $<

# VaptVupt codec files are compiled for the target ABI baseline.
$(VV_SIMD_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) \
		$(if $(filter $@,$(CLANG_CAST_ALIGN_OBJS)),$(CLANG_CAST_ALIGN_FLAGS)) \
		-c -o $@ $<

# VaptVupt non-SIMD files use the same warning policy.
$(VV_PLAIN_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) \
		$(if $(filter $@,$(CLANG_CAST_ALIGN_OBJS)),$(CLANG_CAST_ALIGN_FLAGS)) \
		-c -o $@ $<

# ZUPT core files (the SHA-NI object has its own rule below with -msha)
ZUPT_OBJS_GENERIC = $(filter-out src/zupt_sha256_shani.o,$(ZUPT_OBJS))
$(ZUPT_OBJS_GENERIC): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) -c -o $@ $<

# SHA-NI path needs -msha -mssse3 -msse4.1 on x86_64.
# On non-x86_64, SHANI_FLAGS is empty and the file is a no-op TU.
src/zupt_sha256_shani.o: src/zupt_sha256_shani.c $(HEADERS)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(SHANI_FLAGS) \
		$(if $(filter $@,$(CLANG_CAST_ALIGN_OBJS)),$(CLANG_CAST_ALIGN_FLAGS)) \
		-c -o $@ $<

# Final link step. Order matters: CFLAGS before LDFLAGS, then objects,
# then LDLIBS — keeps GCC/Clang happy when LDFLAGS contains -pie or
# similar position-sensitive flags.
$(TARGET): $(ALL_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) $(PROJECT_CFLAGS) $(LDFLAGS) $(PROJECT_LDFLAGS) $(PROJECT_CLI_LDFLAGS) \
		$(ALL_OBJS) $(JAZZ_O) -o $(TARGET) \
		$(FEATURE_LDLIBS) $(PROJECT_LDLIBS) $(LDLIBS)
	@# In-tree test compatibility only. Installation emits the legacy
	@# alias solely when INSTALL_LEGACY_ALIAS=1 is requested explicitly.
	$(Q)if [ "$(CREATE_TEST_ALIAS)" = 0 ]; then \
		:; \
	elif [ -L "$(LEGACY_LINK)" ]; then \
		test "$$(readlink "$(LEGACY_LINK)")" = "$(TARGET)" || { \
			echo "ERROR: refusing to replace non-ZUPT symlink: $(LEGACY_LINK)" >&2; exit 1; \
		}; \
	elif [ -e "$(LEGACY_LINK)" ]; then \
		echo "ERROR: refusing to replace existing path: $(LEGACY_LINK)" >&2; exit 1; \
	fi; \
	if [ "$(CREATE_TEST_ALIAS)" = 1 ]; then ln -sf "$(TARGET)" "$(LEGACY_LINK)"; fi
	@if [ "$(CREATE_TEST_ALIAS)" = 1 ]; then \
		echo "Build complete: ./$(TARGET) [$(TARGET_MACHINE)] (test alias: ./$(LEGACY_LINK) -> $(TARGET))"; \
	else \
		echo "Build complete: ./$(TARGET) [$(TARGET_MACHINE)] (no in-tree compatibility alias)"; \
	fi

# ═══════════════════════════════════════════════════════════════════
# INSTALL / UNINSTALL
# ═══════════════════════════════════════════════════════════════════

install: $(TARGET)
	$(Q)mkdir -p "$(DESTDIR)$(BINDIR)"
	$(Q)install -m 0755 "$(TARGET)" "$(DESTDIR)$(BINDIR)/$(TARGET)"
	$(Q)if [ "$(INSTALL_LICENSES)" = 1 ]; then \
		mkdir -p "$(DESTDIR)$(LICENSEDIR)"; \
		install -m 0644 $(LICENSE_FILES) "$(DESTDIR)$(LICENSEDIR)/"; \
	fi
	$(Q)if [ "$(INSTALL_LEGACY_ALIAS)" = 1 ]; then \
		ln -sf "$(TARGET)" "$(DESTDIR)$(BINDIR)/$(LEGACY_LINK)"; \
	fi

	$(Q)if [ -f "$(MANPAGE)" ]; then \
		mkdir -p "$(DESTDIR)$(MAN1DIR)"; \
		$(GZIP) $(GZIPFLAGS) -c "$(MANPAGE)" > "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
		chmod 0644 "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
		if [ "$(INSTALL_LEGACY_ALIAS)" = 1 ]; then \
			ln -sf "$(MANPAGE_GZ)" "$(DESTDIR)$(MAN1DIR)/$(LEGACY_PROGRAM).1.gz"; \
		fi; \
		echo "Installed: $(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
	else \
		echo "Warning: man page not found: $(MANPAGE)"; \
	fi

	# Shell completions (v2.4.7+). Honour distro path conventions where
	# possible; downstream packagers can override DESTDIR + the specific
	# dirs as needed.
	$(Q)if [ -f completions/zupt.bash ]; then \
		mkdir -p "$(DESTDIR)$(BASHCOMPDIR)"; \
		install -m 0644 completions/zupt.bash \
			"$(DESTDIR)$(BASHCOMPDIR)/$(PROGRAM)"; \
		if [ "$(INSTALL_LEGACY_ALIAS)" = 1 ]; then \
			ln -sf "$(PROGRAM)" "$(DESTDIR)$(BASHCOMPDIR)/$(LEGACY_PROGRAM)"; \
		fi; \
		echo "Installed: $(DESTDIR)$(BASHCOMPDIR)/$(PROGRAM)"; \
	fi
	$(Q)if [ -f completions/_zupt ]; then \
		mkdir -p "$(DESTDIR)$(ZSHCOMPDIR)"; \
		install -m 0644 completions/_zupt \
			"$(DESTDIR)$(ZSHCOMPDIR)/_$(PROGRAM)"; \
		if [ "$(INSTALL_LEGACY_ALIAS)" = 1 ]; then \
			ln -sf "_$(PROGRAM)" "$(DESTDIR)$(ZSHCOMPDIR)/_$(LEGACY_PROGRAM)"; \
		fi; \
		echo "Installed: $(DESTDIR)$(ZSHCOMPDIR)/_$(PROGRAM)"; \
	fi
	$(Q)if [ -f completions/zupt.fish ]; then \
		mkdir -p "$(DESTDIR)$(FISHCOMPDIR)"; \
		install -m 0644 completions/zupt.fish \
			"$(DESTDIR)$(FISHCOMPDIR)/$(PROGRAM).fish"; \
		if [ "$(INSTALL_LEGACY_ALIAS)" = 1 ]; then \
			ln -sf "$(PROGRAM).fish" "$(DESTDIR)$(FISHCOMPDIR)/$(LEGACY_PROGRAM).fish"; \
		fi; \
		echo "Installed: $(DESTDIR)$(FISHCOMPDIR)/$(PROGRAM).fish"; \
	fi

	@echo "Installed: $(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	$(Q)rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	$(Q)rm -f "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"
	$(Q)rm -f "$(DESTDIR)$(BASHCOMPDIR)/$(PROGRAM)"
	$(Q)rm -f "$(DESTDIR)$(ZSHCOMPDIR)/_$(PROGRAM)"
	$(Q)rm -f "$(DESTDIR)$(FISHCOMPDIR)/$(PROGRAM).fish"
	$(Q)set -eu; for license_file in $(LICENSE_FILES); do \
		rm -f "$(DESTDIR)$(LICENSEDIR)/$${license_file##*/}"; \
	done
	$(Q)for item in \
		"$(DESTDIR)$(BINDIR)/$(LEGACY_LINK):$(TARGET)" \
		"$(DESTDIR)$(MAN1DIR)/$(LEGACY_PROGRAM).1.gz:$(MANPAGE_GZ)" \
		"$(DESTDIR)$(BASHCOMPDIR)/$(LEGACY_PROGRAM):$(PROGRAM)" \
		"$(DESTDIR)$(ZSHCOMPDIR)/_$(LEGACY_PROGRAM):_$(PROGRAM)" \
		"$(DESTDIR)$(FISHCOMPDIR)/$(LEGACY_PROGRAM).fish:$(PROGRAM).fish"; do \
		path=$${item%:*}; expected=$${item##*:}; \
		if [ -L "$$path" ] && [ "$$(readlink "$$path")" = "$$expected" ]; then rm -f "$$path"; fi; \
	done

# ═══════════════════════════════════════════════════════════════════
# DIST — reproducible source tarball for distro packaging
# ═══════════════════════════════════════════════════════════════════
#
# `make dist` produces zupt-VERSION.tar.gz that is BYTE-IDENTICAL given
# the same input source tree. Properties:
#
#   - Files sorted by name (stable order regardless of filesystem layout)
#   - mtime fixed to SOURCE_DATE_EPOCH (`.source-date-epoch`, then HEAD fallback)
#   - uid/gid fixed to root (0/0) via --owner / --group
#   - gzip wrapped with --no-name (no embedded timestamp/filename)
#   - No binaries, no .o, no .so. Source only.
#
# The archive always represents the tree of committed HEAD, never ignored build
# output or uncommitted files.  Archiving the tree object also avoids Git's
# commit-ID PAX header, so an export-ignored-only commit cannot change its bytes.
# Override DIST_TARBALL for a packaging work directory.
DIST_VERSION = $(shell sed -n 's/^\#define ZUPT_VERSION_STRING "\([^"]*\)".*/\1/p' include/zupt.h)
DIST_NAME = $(PROGRAM)-$(DIST_VERSION)
DIST_TARBALL ?= /tmp/$(DIST_NAME).tar.gz
SOURCE_DATE_EPOCH ?= $(shell epoch=$$(sed -n 's/^[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$$/\1/p' .source-date-epoch 2>/dev/null | head -n 1); if test -n "$$epoch"; then printf '%s' "$$epoch"; else git log -1 --format=%ct HEAD 2>/dev/null; fi)
SOURCE_AUDIT ?= scripts/check-source-only.sh

source-audit:
	$(Q)test -f "$(SOURCE_AUDIT)" || { \
		echo "ERROR: source-only scanner not found: $(SOURCE_AUDIT)" >&2; \
		exit 1; \
	}
	$(Q)bash "$(SOURCE_AUDIT)"

dist:
	$(Q)set -eu; \
	export LC_ALL=C; \
	umask 022; \
	unset TAR_OPTIONS; \
	test -n "$(DIST_VERSION)" || { echo "ERROR: cannot determine source version" >&2; exit 1; }; \
	test -n "$(SOURCE_DATE_EPOCH)" || { echo "ERROR: SOURCE_DATE_EPOCH is empty" >&2; exit 1; }; \
	case "$(SOURCE_DATE_EPOCH)" in *[!0-9]*) echo "ERROR: SOURCE_DATE_EPOCH must be an integer" >&2; exit 1;; esac; \
	test -f "$(SOURCE_AUDIT)" || { echo "ERROR: source-only scanner not found: $(SOURCE_AUDIT)" >&2; exit 1; }; \
	git rev-parse --verify 'HEAD^{commit}' >/dev/null; \
	git rev-parse --verify 'HEAD^{tree}' >/dev/null; \
	tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/zupt-dist.XXXXXXXX"); \
	trap 'rm -rf -- "$$tmp"' EXIT HUP INT TERM; \
	git archive --format=tar --mtime="@$(SOURCE_DATE_EPOCH)" \
		--prefix="$(DIST_NAME)/" 'HEAD^{tree}' | \
		$(GZIP) $(GZIPFLAGS) > "$$tmp/$(DIST_NAME).tar.gz"; \
	bash "$(SOURCE_AUDIT)" --archive "$$tmp/$(DIST_NAME).tar.gz"; \
	mkdir -p "$$(dirname "$(DIST_TARBALL)")"; \
	mv -f "$$tmp/$(DIST_NAME).tar.gz" "$(DIST_TARBALL)"; \
	trap - EXIT HUP INT TERM; \
	rm -rf -- "$$tmp"; \
	if command -v sha256sum >/dev/null 2>&1; then \
		digest=$$(sha256sum "$(DIST_TARBALL)" | awk '{print $$1}'); \
	elif command -v shasum >/dev/null 2>&1; then \
		digest=$$(shasum -a 256 "$(DIST_TARBALL)" | awk '{print $$1}'); \
	else \
		echo "ERROR: sha256sum or shasum is required" >&2; exit 1; \
	fi; \
	bytes=$$(wc -c < "$(DIST_TARBALL)"); \
	printf '\n  Reproducible source tarball:\n    %s\n    sha256: %s\n    bytes: %s\n' \
		"$(DIST_TARBALL)" "$$digest" "$$bytes"

# ═══════════════════════════════════════════════════════════════════
# CLEAN
# ═══════════════════════════════════════════════════════════════════

clean:
	$(Q)rm -f $(PROGRAM) $(PROGRAM).exe $(LEGACY_PROGRAM) $(LEGACY_PROGRAM).exe $(MANPAGE_GZ) \
		zupt_asan \
		test_vectors test_f06 test_vaptvupt \
		fuzz_decompress fuzz_vv_decompress tests/fuzz_format \
		*.gcda *.gcno *.profraw *.profdata \
		src/*.o src/*.gcda src/*.gcno jasmin/*.o jasmin/*.gcda jasmin/*.gcno \
		tests/*.gcda tests/*.gcno sdk/*.gcda sdk/*.gcno
	$(Q)for link in $(LEGACY_PROGRAM) $(LEGACY_PROGRAM).exe; do \
		if [ -L "$$link" ]; then \
			case "$$(readlink "$$link")" in $(PROGRAM)|$(PROGRAM).exe) rm -f "$$link" ;; esac; \
		fi; \
	done
	$(Q)rm -rf sdk/build build build_obj coverage

# ═══════════════════════════════════════════════════════════════════
# TEST TARGETS
# ═══════════════════════════════════════════════════════════════════

test: check

test-all: check
	$(Q)bash tests/regression.sh ./$(TARGET)
	$(Q)sh tests/test_threaded.sh ./$(TARGET)
	$(Q)sh tests/test_pq.sh ./$(TARGET)
	$(Q)bash tests/test_dedup_props.sh ./$(TARGET)
	$(Q)bash tests/test_ct_timing.sh
	$(Q)bash tests/test_codec_exact_size.sh
	$(Q)bash tests/test_mlkem_fips203.sh
	$(Q)bash tests/test_sdk.sh
	$(Q)bash tests/test_pqbox.sh
	$(Q)bash tests/test_audit.sh
	$(Q)bash tests/test_kdf_transparency.sh

# Release-only gates need a committed Git checkout and packaging metadata.
# Keep them out of downstream %check, which intentionally has no dist rebuild.
release-check: test-all audit-licenses
	$(Q)$(MAKE) sdk-test
	$(Q)bash tests/test_static_analysis.sh
	$(Q)bash tests/test_packaging_syntax.sh
	$(Q)bash scripts/test-installed-zupt.sh ./$(TARGET)
	$(Q)if [ "$(WITH_SDK)" = 1 ]; then \
		bash tests/test_audit_flake.sh "$${AUDIT_FLAKE_RUNS:-3}"; \
	else \
		echo "SKIP: audit flake stress needs WITH_SDK=1 and system libvuptsdk"; \
	fi
	$(Q)$(MAKE) clean
	$(Q)bash "$(SOURCE_AUDIT)"
	$(Q)bash tests/test_dist_reproducible.sh

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
#   - Covers the source-only CLI, archive safety, HMAC/integrity regressions,
#     codec checks and cryptographic primitive vectors
#   - Verifies cryptographic primitives against NIST/RFC vectors
#
# This is the recommended target for OBS %check sections.

check: $(TARGET) test-vectors test-f06 test-vv
	$(Q)sh tests/run_quick.sh ./$(TARGET)
	$(Q)bash tests/test_path_traversal.sh ./$(TARGET)
	$(Q)bash tests/test_arg_order.sh ./$(TARGET)
	$(Q)bash tests/test_password_sources.sh ./$(TARGET)
	$(Q)bash tests/test_password_prompt_signal.sh ./$(TARGET)
	$(Q)bash tests/test_key_files.sh ./$(TARGET)
	$(Q)ZUPT_BIN="$(CURDIR)/$(TARGET)" bash tests/test_f08_topmac.sh
	$(Q)ZUPT_BIN="$(CURDIR)/$(TARGET)" bash tests/test_f09_preface.sh
	$(Q)ZUPT_BIN="$(CURDIR)/$(TARGET)" bash tests/test_f10_kdf_default.sh
	$(Q)ZUPT_BIN="$(CURDIR)/$(TARGET)" bash tests/test_f11_authfail_message.sh
	$(Q)ZUPT_BIN="$(CURDIR)/$(TARGET)" bash tests/test_f12_comment.sh
	$(Q)bash tests/test_atomic_archive_output.sh ./$(TARGET)
	$(Q)bash tests/test_legacy_disk_5_2_1.sh ./$(TARGET)
	$(Q)bash tests/test_disk_device_capacity.sh ./$(TARGET)
	$(Q)bash tests/test_block_swap.sh ./$(TARGET)
	$(Q)bash tests/test_block_type_confusion.sh ./$(TARGET)
	$(Q)bash tests/test_authenticated_dedup_reorder.sh ./$(TARGET)
	$(Q)bash tests/test_format_little_endian.sh ./$(TARGET)
	$(Q)bash tests/test_dedup_nonce.sh ./$(TARGET)
	$(Q)bash tests/test_gui_branding.sh ./$(TARGET)
	$(Q)bash tests/test_help_consistency.sh ./$(TARGET)
	$(Q)bash tests/test_benchmark_temp_safety.sh ./$(TARGET)
	$(Q)bash tests/test_vv_decode_slack.sh ./$(TARGET)
	$(Q)bash tests/test_sha256_shani.sh
	$(Q)bash tests/test_hmac_incremental.sh
	$(Q)bash tests/test_completions_manpage.sh
	$(Q)bash tests/test_source_only.sh
	$(Q)./test_vectors
	@echo ""
	@echo "  ═════════════════════════════════════════"
	@echo "  All executed distro-safe checks passed (see SKIP lines above)."
	@echo "  ═════════════════════════════════════════"

TEST_CRYPTO_SOURCES = src/zupt_sha256.c src/zupt_sha256_shani.c \
	src/zupt_crypto.c src/zupt_aes256.c src/zupt_xxh.c src/zupt_keccak.c \
	src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c
TEST_CRYPTO_OBJS = $(TEST_CRYPTO_SOURCES:.c=.o)

test-vectors: tests/test_vectors.c $(HEADERS) $(TEST_CRYPTO_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(LDFLAGS) $(PROJECT_LDFLAGS) \
		tests/test_vectors.c $(TEST_CRYPTO_OBJS) $(JAZZ_O) \
		-o test_vectors $(FEATURE_LDLIBS) $(PROJECT_LDLIBS) $(LDLIBS)

# F-06 regression — HMAC accept-on-disjoint-bits (ZUPT 2.2.5).
# Inherits $(CFLAGS) so ZUPT_USE_JASMIN is defined on x86_64 (exercising
# the original buggy path). Links the same crypto modules as test-vectors
# plus the Jasmin .o files when available.
test-f06: tests/test_f06_hmac.c $(HEADERS) $(TEST_CRYPTO_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(LDFLAGS) $(PROJECT_LDFLAGS) \
		tests/test_f06_hmac.c $(TEST_CRYPTO_OBJS) $(JAZZ_O) -o test_f06 \
		$(FEATURE_LDLIBS) $(PROJECT_LDLIBS) $(LDLIBS)
	$(Q)./test_f06

# VAPTVUPT: VaptVupt codec unit tests
TEST_VV_OBJS = $(VV_SIMD_OBJS) $(VV_PLAIN_OBJS) src/zupt_xxh.o src/zupt_cpuid.o
test-vv: tests/test_vaptvupt.c $(HEADERS) $(TEST_VV_OBJS)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(PROJECT_CFLAGS) \
		$(LDFLAGS) $(PROJECT_LDFLAGS) tests/test_vaptvupt.c $(TEST_VV_OBJS) \
		-o test_vaptvupt $(PROJECT_LDLIBS) $(LDLIBS)
	$(Q)./test_vaptvupt

ASAN_BUILD_DIR = build/asan
ASAN_CFLAGS ?= -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
ASAN_LDFLAGS ?= -fsanitize=address,undefined
ASAN_OBJS = $(patsubst src/%.c,$(ASAN_BUILD_DIR)/%.o,$(SOURCES))

$(ASAN_BUILD_DIR):
	$(Q)mkdir -p "$@"

$(ASAN_BUILD_DIR)/zupt_sha256_shani.o: src/zupt_sha256_shani.c $(HEADERS) | $(ASAN_BUILD_DIR)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) $(SHANI_FLAGS) -c -o $@ $<

$(ASAN_BUILD_DIR)/vv_%.o: src/vv_%.c $(HEADERS) | $(ASAN_BUILD_DIR)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) -c -o $@ $<

$(ASAN_BUILD_DIR)/vaptvupt_api.o: src/vaptvupt_api.c $(HEADERS) | $(ASAN_BUILD_DIR)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) -c -o $@ $<

$(ASAN_BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(ASAN_BUILD_DIR)
	$(Q)$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) -c -o $@ $<

test-asan: $(ASAN_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) \
		$(LDFLAGS) $(PROJECT_LDFLAGS) $(ASAN_LDFLAGS) \
		$(ASAN_OBJS) $(JAZZ_O) -o zupt_asan \
		$(FEATURE_LDLIBS) $(PROJECT_LDLIBS) $(LDLIBS)
	@echo "ASAN build: ./zupt_asan"

# Build the format-parser fuzz harness. Runs against ./zupt_asan to catch
# memory errors AND crashes in mutation-fuzz of the listing/extract path.
fuzz-format: tests/fuzz_format

tests/fuzz_format: tests/fuzz_format.c
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(PROJECT_CFLAGS) \
		$(LDFLAGS) $(PROJECT_LDFLAGS) tests/fuzz_format.c \
		-o tests/fuzz_format $(PROJECT_LDLIBS) $(LDLIBS)
	@echo "Format fuzz harness: ./tests/fuzz_format"

# Run 5000 iterations of mutation fuzz against the ASAN binary.
# Any crash or sanitizer error fails CI.
fuzz-format-run: tests/fuzz_format test-asan $(TARGET)
	$(Q)set -eu; \
	tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/zupt-fuzz.XXXXXXXX"); \
	trap 'rm -rf -- "$$tmp"' EXIT HUP INT TERM; \
	printf '%s\n' 'fuzz seed file' > "$$tmp/input.txt"; \
	./$(TARGET) c "$$tmp/seed.zupt" "$$tmp/input.txt" >/dev/null; \
	ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
		./tests/fuzz_format 1000 ./zupt_asan "$$tmp/seed.zupt"
	@echo "  Format fuzz: 1000 iterations under ASAN/UBSAN — no crashes."

# Runs a round-trip smoke test against the ASAN/UBSAN/LSAN-instrumented binary.
# The exhaustive codec exact-size sanitizer loop remains part of test-all.
test-asan-run: test-asan
	$(Q)set -eu; \
	tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/zupt-asan.XXXXXXXX"); \
	trap 'rm -rf -- "$$tmp"' EXIT HUP INT TERM; \
	export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1; \
	export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; \
	printf '%s\n' 'sanitizer round-trip' > "$$tmp/input.txt"; \
	./zupt_asan c "$$tmp/archive.zupt" "$$tmp/input.txt" >/dev/null; \
	./zupt_asan t "$$tmp/archive.zupt" >/dev/null; \
	mkdir "$$tmp/out"; \
	(cd "$$tmp/out" && "$(CURDIR)/zupt_asan" x "$$tmp/archive.zupt" >/dev/null); \
	extracted=$$(find "$$tmp/out" -type f -print -quit); \
	test -n "$$extracted"; \
	cmp "$$tmp/input.txt" "$$extracted"; \
	dd if=/dev/urandom of="$$tmp/block" bs=65536 count=1 2>/dev/null; \
	cp "$$tmp/block" "$$tmp/disk.img"; \
	dd if="$$tmp/block" of="$$tmp/disk.img" bs=65536 seek=1 conv=notrunc 2>/dev/null; \
	printf '%s\n' 'sanitizer-disk-password' > "$$tmp/password"; \
	./zupt_asan disk backup --dedup -b 65536 --pass-file "$$tmp/password" -s \
		"$$tmp/disk.zupt" "$$tmp/disk.img" >/dev/null; \
	./zupt_asan t --pass-file "$$tmp/password" "$$tmp/disk.zupt" >/dev/null; \
	./zupt_asan disk restore --pass-file "$$tmp/password" \
		"$$tmp/disk.zupt" "$$tmp/restored.img" >/dev/null; \
	cmp "$$tmp/disk.img" "$$tmp/restored.img"; \
	./zupt_asan --help >/dev/null; \
	./zupt_asan --version >/dev/null
	@echo "  ASAN/UBSAN: source-only smoke test passed."

# AFL++ fuzzing harnesses (requires afl-clang-fast). Compile every source with
# instrumentation while retaining translation-unit-local ISA flags.
AFL_CC ?= afl-clang-fast
FUZZ_BUILD_DIR = build/fuzz
FUZZ_SOURCES = $(filter-out src/zupt_main.c,$(SOURCES))
FUZZ_OBJS = $(patsubst src/%.c,$(FUZZ_BUILD_DIR)/%.o,$(FUZZ_SOURCES))
FUZZ_VV_OBJS = $(addprefix $(FUZZ_BUILD_DIR)/,vv_encoder.o vv_decoder.o \
	vv_ans.o vv_huffman.o vv_simd.o zupt_xxh.o zupt_cpuid.o)

$(FUZZ_BUILD_DIR):
	$(Q)mkdir -p "$@"

$(FUZZ_BUILD_DIR)/zupt_sha256_shani.o: src/zupt_sha256_shani.c $(HEADERS) | $(FUZZ_BUILD_DIR)
	$(Q)$(AFL_CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) $(SHANI_FLAGS) -c -o $@ $<

$(FUZZ_BUILD_DIR)/vv_%.o: src/vv_%.c $(HEADERS) | $(FUZZ_BUILD_DIR)
	$(Q)$(AFL_CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) $(VV_WARNING_FLAGS) \
		$(if $(filter $(FUZZ_BUILD_DIR)/vv_decoder.o,$@),$(VV_DECODER_WARNING_FLAGS)) -c -o $@ $<

$(FUZZ_BUILD_DIR)/vaptvupt_api.o: src/vaptvupt_api.c $(HEADERS) | $(FUZZ_BUILD_DIR)
	$(Q)$(AFL_CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) $(VV_WARNING_FLAGS) -c -o $@ $<

$(FUZZ_BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(FUZZ_BUILD_DIR)
	$(Q)$(AFL_CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) -c -o $@ $<

fuzz_decompress: tests/fuzz_decompress.c $(FUZZ_OBJS)
	$(Q)$(AFL_CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(FEATURE_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) \
		$(LDFLAGS) $(PROJECT_LDFLAGS) $(ASAN_LDFLAGS) \
		tests/fuzz_decompress.c $(FUZZ_OBJS) -o $@ \
		$(FEATURE_LDLIBS) $(PROJECT_LDLIBS) $(LDLIBS)

fuzz_vv_decompress: tests/fuzz_vv_decompress.c $(FUZZ_VV_OBJS)
	$(Q)$(AFL_CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) \
		$(CFLAGS) $(PROJECT_CFLAGS) $(ASAN_CFLAGS) \
		$(LDFLAGS) $(PROJECT_LDFLAGS) $(ASAN_LDFLAGS) \
		tests/fuzz_vv_decompress.c $(FUZZ_VV_OBJS) -o $@ \
		$(PROJECT_LDLIBS) $(LDLIBS)

fuzz-build: fuzz_decompress fuzz_vv_decompress
	@echo "Fuzz harnesses built. Run:"
	@echo "  afl-fuzz -i corpus -o findings -- ./fuzz_decompress"
	@echo "  afl-fuzz -i corpus_vv -o findings_vv -- ./fuzz_vv_decompress"

help:
	@echo "ZUPT v$(DIST_VERSION) build targets:"
	@echo "  make              Build zupt binary"
	@echo "  make V=1          Build with verbose output"
	@echo "  make check        Distro-safe source-only test suite"
	@echo "  make test-all     Complete runtime suite; unavailable integrations SKIP"
	@echo "  make release-check Runtime, static, packaging, source and dist gates"
	@echo "  make test-vv      VaptVupt codec unit tests"
	@echo "  make test-asan    Build with AddressSanitizer"
	@echo "  make fuzz-build   Build AFL++ fuzzing harnesses"
	@echo "  make dist         Reproducible, audited source archive"
	@echo "  make source-audit Audit tracked, worktree and HEAD archive content"
	@echo "  make install      Install to $(PREFIX)"
	@echo "  make uninstall    Remove from $(PREFIX)"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Compiler target: $(TARGET_MACHINE)"
	@echo "Optional integrations (off by default):"
	@echo "  WITH_SDK=1       system libvuptsdk via pkg-config/overrides"
	@echo "  WITH_PQBOX=1     system libpqvaptvupt via pkg-config/overrides"
	@echo "  WITH_JASMIN=1    optional textual assembly on x86_64"
	@echo "  INSTALL_LEGACY_ALIAS=1 installs opt-in 'vaptvupt' compatibility links"

# ─────────────────────────────────────────────────────────────────────
#  SDK targets — see sdk/Makefile.sdk
# ─────────────────────────────────────────────────────────────────────
include sdk/Makefile.sdk
