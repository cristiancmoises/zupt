# Zupt v2.0.0 — Makefile with VaptVupt codec + Jasmin integration
CC        ?= gcc
CFLAGS    ?= -Wall -Wextra -O2 -std=c11
CFLAGS    += -Iinclude -Isrc
LDLIBS    ?= -lm -lpthread
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
MANDIR    ?= $(PREFIX)/share/man
MAN1DIR   ?= $(MANDIR)/man1
GZIP      ?= gzip
GZIPFLAGS ?= -9 -n

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
             src/vv_huffman.c src/vv_simd.c

SOURCES = $(ZUPT_SOURCES) $(VV_SOURCES)

HEADERS  = include/zupt.h include/zupt_keccak.h include/zupt_mlkem.h \
           include/zupt_x25519.h include/zupt_cpuid.h include/zupt_jasmin.h \
           include/vaptvupt.h include/vv_huffman.h include/vv_ans.h \
           src/zupt_thread.h src/zupt_parallel.h

TARGET     = zupt
MANPAGE    = doc/zupt.1
MANPAGE_GZ = $(TARGET).1.gz

# --- AVX2 detection: enable SIMD for VaptVupt on x86-64 ---
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  VV_SIMD_FLAGS = -mavx2
else
  VV_SIMD_FLAGS =
endif

# --- Jasmin: use pre-compiled .s files if present ---
JAZZ_S = jasmin/zupt_mac_verify.s jasmin/zupt_mlkem_select.s jasmin/zupt_aes_ctr.s jasmin/zupt_x25519_fe.s jasmin/zupt_aes_ctr4.s
JAZZ_AVAILABLE := $(wildcard $(JAZZ_S))

ifeq ($(JAZZ_AVAILABLE),$(JAZZ_S))
  CFLAGS += -DZUPT_USE_JASMIN
  JAZZ_O = jasmin/zupt_mac_verify.o jasmin/zupt_mlkem_select.o jasmin/zupt_aes_ctr.o jasmin/zupt_x25519_fe.o jasmin/zupt_aes_ctr4.o
  $(info [jasmin] Verified assembly found - linking CT crypto)
else
  JAZZ_O =
  $(info [jasmin] Assembly not found - using C fallback)
endif

# --- Object files for per-file CFLAGS (VV SIMD files need -mavx2) ---
VV_SIMD_OBJS  = src/vv_encoder.o src/vv_decoder.o src/vv_simd.o
VV_PLAIN_OBJS = src/vv_ans.o src/vv_huffman.o
ZUPT_OBJS     = $(patsubst %.c,%.o,$(ZUPT_SOURCES))
ALL_OBJS      = $(ZUPT_OBJS) $(VV_SIMD_OBJS) $(VV_PLAIN_OBJS)

.PHONY: all clean install uninstall test test-all test-asan test-vectors test-vv fuzz-build help

all: $(TARGET)

jasmin/%.o: jasmin/%.s
	$(Q)$(CC) -c -o $@ $<

# VaptVupt SIMD files: compile with AVX2
$(VV_SIMD_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(VV_SIMD_FLAGS) -c -o $@ $<

# VaptVupt non-SIMD files
$(VV_PLAIN_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Zupt core files
$(ZUPT_OBJS): src/%.o: src/%.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(ALL_OBJS) $(JAZZ_O)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJS) $(JAZZ_O) -o $(TARGET) $(LDLIBS)
	@echo "Build complete: ./$(TARGET)"

clean:
	$(Q)rm -f $(TARGET) $(MANPAGE_GZ) zupt_asan test_vectors test_vaptvupt \
		fuzz_decompress fuzz_vv_decompress jasmin/*.o src/*.o

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
	$(Q)$(CC) -O2 -std=c11 -Iinclude -Isrc tests/test_vectors.c \
	    src/zupt_sha256.c src/zupt_crypto.c src/zupt_aes256.c src/zupt_xxh.c \
	    src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c \
	    src/zupt_mlock.c \
	    $(LDLIBS) -o test_vectors

# VAPTVUPT: VaptVupt codec unit tests
test-vv: tests/test_vaptvupt.c $(HEADERS)
	$(Q)$(CC) $(CFLAGS) $(VV_SIMD_FLAGS) tests/test_vaptvupt.c \
	    src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_huffman.c \
	    src/vv_simd.c src/zupt_xxh.c src/zupt_cpuid.c \
	    $(LDLIBS) -o test_vaptvupt
	$(Q)./test_vaptvupt

test-asan: $(SOURCES) $(HEADERS) $(JAZZ_O)
	$(Q)$(CC) -Wall -Wextra -std=c11 -Iinclude -Isrc \
	    -fsanitize=address,undefined -g -O1 \
	    $(VV_SIMD_FLAGS) \
	    $(SOURCES) $(JAZZ_O) $(LDLIBS) -o zupt_asan
	@echo "ASAN build: ./zupt_asan"

# AFL++ fuzzing harnesses (requires afl-clang-fast)
fuzz-build:
	@echo "Building AFL++ fuzzing harnesses..."
	$(Q)afl-clang-fast -fsanitize=address,undefined -g -O1 -std=c11 \
	    -Iinclude -Isrc $(VV_SIMD_FLAGS) \
	    $(filter-out src/zupt_main.c,$(SOURCES)) tests/fuzz_decompress.c \
	    $(LDLIBS) -o fuzz_decompress
	$(Q)afl-clang-fast -fsanitize=address,undefined -g -O1 -std=c11 \
	    -Iinclude -Isrc $(VV_SIMD_FLAGS) \
	    tests/fuzz_vv_decompress.c \
	    src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_huffman.c \
	    src/vv_simd.c src/zupt_xxh.c src/zupt_cpuid.c \
	    $(LDLIBS) -o fuzz_vv_decompress
	@echo "Fuzz harnesses built. Run:"
	@echo "  afl-fuzz -i corpus -o findings -- ./fuzz_decompress"
	@echo "  afl-fuzz -i corpus_vv -o findings_vv -- ./fuzz_vv_decompress"

help:
	@echo "make / make V=1 / make test / make install / make test-all / make test-asan / make test-vv / make fuzz-build / make clean"
