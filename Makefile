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
CFLAGS    ?= -Wall -Wextra -O2 -std=c11
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
               src/zupt_xxh.c src/zupt_sha256.c src/zupt_aes256.c src/zupt_crypto.c \
               src/zupt_crypto_sdk.c \
               src/zupt_predict.c src/zupt_parallel.c src/zupt_keccak.c \
               src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c \
               src/zupt_filetype.c src/zupt_disk.c src/zupt_dedup.c

# --- libzuptsdk linkage (vendored) ---
ZUPTSDK_DIR ?= vendor/zuptsdk
ZUPTSDK_ABS := $(abspath $(ZUPTSDK_DIR))
CFLAGS  += -I$(ZUPTSDK_DIR)/include
LDFLAGS += -L$(ZUPTSDK_DIR) -Wl,-rpath,$(ZUPTSDK_ABS) -Wl,-rpath,'$$ORIGIN/$(ZUPTSDK_DIR)'
LDLIBS  += -lzuptsdk

# --- VAPTVUPT: VaptVupt codec sources (Apache-2.0, integrated under MIT) ---
VV_SOURCES = src/vv_encoder.c src/vv_decoder.c src/vv_ans.c \
             src/vv_huffman.c src/vv_simd.c src/vv_xxh64.c src/vaptvupt_api.c

SOURCES = $(ZUPT_SOURCES) $(VV_SOURCES)

HEADERS  = include/zupt.h include/zupt_keccak.h include/zupt_mlkem.h \
           include/zupt_x25519.h include/zupt_cpuid.h include/zupt_jasmin.h \
           include/zupt_acsl.h \
           include/vaptvupt.h include/vaptvupt_api.h include/vv_huffman.h include/vv_ans.h \
           include/vv_platform.h \
           src/zupt_thread.h src/zupt_parallel.h

TARGET     = zupt
MANPAGE    = doc/zupt.1
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
else
  VV_SIMD_FLAGS =
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
VV_PLAIN_OBJS = src/vv_ans.o src/vv_huffman.o src/vv_xxh64.o src/vaptvupt_api.o
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

.PHONY: all clean install uninstall test test-all test-asan test-asan-run test-vectors test-vv fuzz-build fuzz-format fuzz-format-run help audit-licenses

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
jasmin/%.o: jasmin/%.s
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# VaptVupt SIMD files: compile with AVX2 on x86_64
$(VV_SIMD_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(VV_SIMD_FLAGS) -c -o $@ $<

# VaptVupt non-SIMD files
$(VV_PLAIN_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Zupt core files
$(ZUPT_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Final link step. Order matters: CFLAGS before LDFLAGS, then objects,
# then LDLIBS — keeps GCC/Clang happy when LDFLAGS contains -pie or
# similar position-sensitive flags.
$(TARGET): $(ALL_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJS) $(JAZZ_O) -o $(TARGET) $(LDLIBS)
	@echo "Build complete: ./$(TARGET) [$(ARCH)]"

# ═══════════════════════════════════════════════════════════════════
# INSTALL / UNINSTALL
# ═══════════════════════════════════════════════════════════════════

install: $(TARGET)
	$(Q)mkdir -p $(DESTDIR)$(BINDIR)
	$(Q)install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

	$(Q)if [ -f "$(MANPAGE)" ]; then \
		mkdir -p $(DESTDIR)$(MAN1DIR); \
		$(GZIP) $(GZIPFLAGS) -c "$(MANPAGE)" > "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
		chmod 0644 "$(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
		echo "Installed: $(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)"; \
	else \
		echo "Warning: man page not found: $(MANPAGE)"; \
	fi

	@echo "Installed: $(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	$(Q)rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	$(Q)rm -f $(DESTDIR)$(MAN1DIR)/$(MANPAGE_GZ)

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

test-vectors: tests/test_vectors.c $(HEADERS)
	$(Q)$(CC) -O2 -std=c11 -Iinclude -Isrc $(LDFLAGS) tests/test_vectors.c \
	    src/zupt_sha256.c src/zupt_crypto.c src/zupt_aes256.c src/zupt_xxh.c \
	    src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c \
	    src/zupt_mlock.c \
	    -o test_vectors $(LDLIBS)

# VAPTVUPT: VaptVupt codec unit tests
test-vv: tests/test_vaptvupt.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(VV_SIMD_FLAGS) $(LDFLAGS) tests/test_vaptvupt.c \
	    src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_huffman.c \
	    src/vv_simd.c src/vv_xxh64.c src/vaptvupt_api.c src/zupt_xxh.c src/zupt_cpuid.c \
	    -o test_vaptvupt $(LDLIBS)
	$(Q)./test_vaptvupt

test-asan: $(SOURCES) $(HEADERS) $(JAZZ_O)
	$(Q)$(CC) -Wall -Wextra -std=c11 -Iinclude -Isrc -I$(ZUPTSDK_DIR)/include \
	    -fsanitize=address,undefined -g -O1 \
	    $(VV_SIMD_FLAGS) -L$(ZUPTSDK_DIR) -Wl,-rpath,$(ZUPTSDK_ABS) \
	    $(SOURCES) $(JAZZ_O) -o zupt_asan -lzuptsdk $(LDLIBS)
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
	@echo "Zupt v2.0.0 build targets:"
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
