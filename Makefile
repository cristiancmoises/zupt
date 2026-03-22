# ZUPT v0.7.0 - Makefile (Linux / macOS)

CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -std=c11 -Iinclude -Isrc
SOURCES  = src/zupt_main.c src/zupt_format.c src/zupt_lz.c src/zupt_lzh.c src/zupt_xxh.c \
           src/zupt_sha256.c src/zupt_aes256.c src/zupt_crypto.c src/zupt_predict.c \
           src/zupt_parallel.c src/zupt_keccak.c src/zupt_x25519.c src/zupt_mlkem.c
LDFLAGS  = -lm -lpthread
TARGET   = zupt

.PHONY: all clean test test-all test-asan install

all: $(TARGET)

$(TARGET): $(SOURCES) include/zupt.h src/zupt_thread.h src/zupt_parallel.h
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(TARGET)
	@echo "Build complete: ./$(TARGET)"

clean:
	rm -f $(TARGET) zupt_asan

# Quick self-test (9 tests)
test: $(TARGET)
	@echo "=== Zupt v0.5.1 Self-Test ==="
	@rm -rf /tmp/zupt_test && mkdir -p /tmp/zupt_test/input/subdir
	@echo "Hello, Zupt!" > /tmp/zupt_test/input/hello.txt
	@dd if=/dev/urandom bs=1024 count=100 of=/tmp/zupt_test/input/random.bin 2>/dev/null
	@yes "AAAA BBBB CCCC DDDD EEEE FFFF " | head -c 1000000 > /tmp/zupt_test/input/repeat.txt
	@echo '{"key": "value", "arr": [1,2,3]}' > /tmp/zupt_test/input/subdir/data.json
	@seq 1 10000 > /tmp/zupt_test/input/subdir/numbers.txt
	@echo ""
	@echo "--- Test 1: Unencrypted compress (recursive directory) ---"
	@./zupt compress -v -l 7 /tmp/zupt_test/plain.zupt /tmp/zupt_test/input
	@echo ""
	@echo "--- Test 2: List ---"
	@./zupt list /tmp/zupt_test/plain.zupt
	@echo "--- Test 3: Integrity test ---"
	@./zupt test -v /tmp/zupt_test/plain.zupt
	@echo ""
	@echo "--- Test 4: Extract + verify ---"
	@./zupt extract -v -o /tmp/zupt_test/out_plain /tmp/zupt_test/plain.zupt
	@diff /tmp/zupt_test/input/hello.txt /tmp/zupt_test/out_plain/tmp/zupt_test/input/hello.txt && echo "  hello.txt: OK"
	@diff /tmp/zupt_test/input/random.bin /tmp/zupt_test/out_plain/tmp/zupt_test/input/random.bin && echo "  random.bin: OK"
	@diff /tmp/zupt_test/input/repeat.txt /tmp/zupt_test/out_plain/tmp/zupt_test/input/repeat.txt && echo "  repeat.txt: OK"
	@diff /tmp/zupt_test/input/subdir/data.json /tmp/zupt_test/out_plain/tmp/zupt_test/input/subdir/data.json && echo "  subdir/data.json: OK"
	@diff /tmp/zupt_test/input/subdir/numbers.txt /tmp/zupt_test/out_plain/tmp/zupt_test/input/subdir/numbers.txt && echo "  subdir/numbers.txt: OK"
	@echo ""
	@echo "--- Test 5: Encrypted compress ---"
	@./zupt compress -v -l 8 -p "TestP@ss123!" /tmp/zupt_test/enc.zupt /tmp/zupt_test/input
	@echo ""
	@echo "--- Test 6: Encrypted list ---"
	@./zupt list -p "TestP@ss123!" /tmp/zupt_test/enc.zupt
	@echo "--- Test 7: Encrypted test ---"
	@./zupt test -v -p "TestP@ss123!" /tmp/zupt_test/enc.zupt
	@echo ""
	@echo "--- Test 8: Encrypted extract + verify ---"
	@./zupt extract -v -o /tmp/zupt_test/out_enc -p "TestP@ss123!" /tmp/zupt_test/enc.zupt
	@diff /tmp/zupt_test/input/hello.txt /tmp/zupt_test/out_enc/tmp/zupt_test/input/hello.txt && echo "  hello.txt: OK"
	@diff /tmp/zupt_test/input/random.bin /tmp/zupt_test/out_enc/tmp/zupt_test/input/random.bin && echo "  random.bin: OK"
	@diff /tmp/zupt_test/input/repeat.txt /tmp/zupt_test/out_enc/tmp/zupt_test/input/repeat.txt && echo "  repeat.txt: OK"
	@diff /tmp/zupt_test/input/subdir/data.json /tmp/zupt_test/out_enc/tmp/zupt_test/input/subdir/data.json && echo "  subdir/data.json: OK"
	@diff /tmp/zupt_test/input/subdir/numbers.txt /tmp/zupt_test/out_enc/tmp/zupt_test/input/subdir/numbers.txt && echo "  subdir/numbers.txt: OK"
	@echo ""
	@echo "--- Test 9: Wrong password should fail ---"
	@./zupt list -p "WrongPass" /tmp/zupt_test/enc.zupt 2>/dev/null && echo "  FAIL: should have rejected" || echo "  Wrong password correctly rejected: OK"
	@echo ""
	@rm -rf /tmp/zupt_test
	@echo "=== ALL TESTS PASSED ==="

# Full regression test suite
test-all: $(TARGET)
	@echo "=== Running full regression suite ==="
	sh tests/regression.sh

# Build with AddressSanitizer + UndefinedBehaviorSanitizer
test-asan: $(SOURCES) include/zupt.h src/zupt_thread.h src/zupt_parallel.h
	$(CC) -Wall -Wextra -std=c11 -Iinclude -Isrc -fsanitize=address,undefined -g -O1 \
	    $(SOURCES) -lm -lpthread -o zupt_asan
	@echo "ASAN build complete: ./zupt_asan"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
