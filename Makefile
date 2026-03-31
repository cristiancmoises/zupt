# Zupt v1.5.2 — Makefile with Jasmin integration
CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2 -std=c11
CFLAGS   += -Iinclude -Isrc
LDLIBS   = -lm -lpthread
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

SOURCES  = src/zupt_main.c src/zupt_format.c src/zupt_lz.c src/zupt_lzh.c \
           src/zupt_xxh.c src/zupt_sha256.c src/zupt_aes256.c src/zupt_crypto.c \
           src/zupt_predict.c src/zupt_parallel.c src/zupt_keccak.c \
           src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c

HEADERS  = include/zupt.h include/zupt_keccak.h include/zupt_mlkem.h \
           include/zupt_x25519.h include/zupt_cpuid.h include/zupt_jasmin.h \
           src/zupt_thread.h src/zupt_parallel.h

TARGET   = zupt

# Detect target architecture from compiler triple
TARGET_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null)
IS_X86_64 := $(filter x86_64-% amd64-%,$(TARGET_TRIPLE))

# Jasmin: enable only on x86_64 and only if assembly sources are present
JAZZ_S = jasmin/zupt_mac_verify.s jasmin/zupt_mlkem_select.s
JAZZ_AVAILABLE := $(wildcard $(JAZZ_S))

ifeq ($(IS_X86_64),)
  JAZZ_O =
  $(info [jasmin] Non-x86_64 target ($(TARGET_TRIPLE)) — using C fallback)
else
  ifeq ($(JAZZ_AVAILABLE),$(JAZZ_S))
    CFLAGS += -DZUPT_USE_JASMIN
    JAZZ_O = jasmin/zupt_mac_verify.o jasmin/zupt_mlkem_select.o
    $(info [jasmin] x86_64 target ($(TARGET_TRIPLE)) with assembly found : linking CT crypto)
  else
    JAZZ_O =
    $(info [jasmin] x86_64 target ($(TARGET_TRIPLE)) but assembly not found : using C fallback)
  endif
endif

.PHONY: all clean install uninstall test test-all test-asan test-vectors help

all: $(TARGET)

jasmin/%.o: jasmin/%.s
	$(CC) -c -o $@ $<

$(TARGET): $(SOURCES) $(HEADERS) $(JAZZ_O)
	$(CC) $(CFLAGS) $(SOURCES) $(JAZZ_O) $(LDLIBS) -o $(TARGET)
	@echo "Build complete: ./$(TARGET)"

clean:
	rm -f $(TARGET) zupt_asan test_vectors jasmin/*.o

install: $(TARGET)
	@mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Installed: $(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

test: $(TARGET)
	@sh tests/run_quick.sh

test-all: $(TARGET) test-vectors
	@echo "═══════════════════════════════════════════════"
	@sh tests/regression.sh 2>&1 | tail -3
	@echo ""
	@sh tests/test_threaded.sh 2>&1 | tail -3
	@echo ""
	@sh tests/test_pq.sh ./zupt 2>&1 | tail -3
	@echo ""
	@./test_vectors 2>&1 | tail -2
	@echo "═══════════════════════════════════════════════"

test-vectors: tests/test_vectors.c $(SOURCES) $(HEADERS)
	$(CC) -O2 -std=c11 -Iinclude -Isrc tests/test_vectors.c \
	    src/zupt_sha256.c src/zupt_crypto.c src/zupt_aes256.c src/zupt_xxh.c \
	    src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c \
	    $(LDLIBS) -o test_vectors

test-asan: $(SOURCES) $(HEADERS) $(JAZZ_O)
	$(CC) -Wall -Wextra -std=c11 -Iinclude -Isrc \
	    -fsanitize=address,undefined -g -O1 \
	    $(SOURCES) $(JAZZ_O) $(LDLIBS) -o zupt_asan
	@echo "ASAN build: ./zupt_asan"

help:
	@echo "make / make test / make install / make test-all / make test-asan / make clean"
