# Zupt v2.1.1 — Makefile with VaptVupt codec + Jasmin integration
#
# Multi-architecture: builds on x86_64, aarch64, armhf, ppc64le, s390x, riscv64.
# Tested on: Linux, macOS, Windows (MSYS2), Termux (Android aarch64).
# Jasmin CT crypto:    x86_64 only (C fallback on all other architectures).
# AVX2 SIMD decode:    x86_64 only (NEON on aarch64, scalar elsewhere).
#
# Packaging:
#   make                     Build with defaults
#   make V=1                 Verbose build output
#   make install DESTDIR=/   Staged install for packaging
#   make CFLAGS="..." LDFLAGS="..." Override for distro policy (PIE, hardening)
#
# rpmlint / OBS compliance:
#   - LDFLAGS honored on link line (before objects for PIE)
#   - LDLIBS after objects (correct link order)
#   - DESTDIR support for staged installs
#   - Man page compressed and installed to $(MANDIR)/man1

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
               src/zupt_predict.c src/zupt_parallel.c src/zupt_keccak.c \
               src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c \
               src/zupt_filetype.c

# --- VAPTVUPT: VaptVupt codec sources (Apache-2.0, integrated under MIT) ---
VV_SOURCES = src/vv_encoder.c src/vv_decoder.c src/vv_ans.c \
             src/vv_huffman.c src/vv_simd.c src/vaptvupt_api.c

SOURCES = $(ZUPT_SOURCES) $(VV_SOURCES)

HEADERS  = include/zupt.h include/zupt_keccak.h include/zupt_mlkem.h \
           include/zupt_x25519.h include/zupt_cpuid.h include/zupt_jasmin.h \
           include/zupt_acsl.h \
           include/vaptvupt.h include/vaptvupt_api.h include/vv_huffman.h include/vv_ans.h \
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
VV_PLAIN_OBJS = src/vv_ans.o src/vv_huffman.o src/vaptvupt_api.o
ZUPT_OBJS     = $(patsubst %.c,%.o,$(ZUPT_SOURCES))
ALL_OBJS      = $(ZUPT_OBJS) $(VV_SIMD_OBJS) $(VV_PLAIN_OBJS)

# ═══════════════════════════════════════════════════════════════════
# ARCH-SAFETY GUARD
#
# If pre-compiled .o files from a different architecture are present
# (e.g. x86_64 .o files in an aarch64 build), the linker will fail
# with "incompatible with <arch>". Detect and remove stale objects.
# This happens when tarballs accidentally include build artifacts.
# ═══════════════════════════════════════════════════════════════════

STALE_OBJS := $(wildcard src/*.o jasmin/*.o)
ifneq ($(STALE_OBJS),)
  # Check if any existing .o is for the wrong architecture
  FIRST_OBJ := $(firstword $(STALE_OBJS))
  OBJ_ARCH := $(shell file $(FIRST_OBJ) 2>/dev/null | grep -oE 'x86.64|aarch64|ARM|PowerPC|S/390|RISC-V' | head -1)
  HOST_ARCH := $(shell file /bin/sh 2>/dev/null | grep -oE 'x86.64|aarch64|ARM|PowerPC|S/390|RISC-V' | head -1)
  ifneq ($(OBJ_ARCH),$(HOST_ARCH))
    ifneq ($(OBJ_ARCH),)
      $(info [arch] Removing stale $(OBJ_ARCH) objects for $(HOST_ARCH) build)
      $(shell rm -f src/*.o jasmin/*.o)
    endif
  endif
endif

# ═══════════════════════════════════════════════════════════════════
# BUILD RULES
# ═══════════════════════════════════════════════════════════════════

.PHONY: all clean install uninstall test test-all test-asan test-vectors test-vv fuzz-build help

all: $(TARGET)

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

# Link: LDFLAGS before objects (for PIE), LDLIBS after (for -lm -lpthread)
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
	    src/vv_simd.c src/vaptvupt_api.c src/zupt_xxh.c src/zupt_cpuid.c \
	    -o test_vaptvupt $(LDLIBS)
	$(Q)./test_vaptvupt

test-asan: $(SOURCES) $(HEADERS) $(JAZZ_O)
	$(Q)$(CC) -Wall -Wextra -std=c11 -Iinclude -Isrc \
	    -fsanitize=address,undefined -g -O1 \
	    $(VV_SIMD_FLAGS) $(LDFLAGS) \
	    $(SOURCES) $(JAZZ_O) -o zupt_asan $(LDLIBS)
	@echo "ASAN build: ./zupt_asan"

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
