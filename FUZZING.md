# Fuzzing Zupt with AFL++

## Setup

```bash
# Install AFL++
apt install afl++ afl++-clang

# Build instrumented binary
export CC=afl-clang-fast
make clean
make CFLAGS="-Wall -Wextra -O2 -std=c11 -Iinclude -Isrc -fsanitize=address"

# Or build a harness that reads from stdin
cat > fuzz_decompress.c << 'EOF'
#include "zupt.h"
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    /* Read archive from stdin, attempt to extract */
    char tmpfile[] = "/tmp/zupt_fuzz_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return 1;
    char buf[4096];
    ssize_t n;
    while ((n = read(0, buf, sizeof(buf))) > 0) write(fd, buf, n);
    close(fd);
    zupt_options_t opts;
    zupt_default_options(&opts);
    opts.quiet = 1;
    zupt_extract_archive(tmpfile, "/tmp/zupt_fuzz_out", &opts);
    unlink(tmpfile);
    return 0;
}
EOF
afl-clang-fast -Wall -O2 -std=c11 -Iinclude -Isrc -fsanitize=address \
    fuzz_decompress.c src/zupt_format.c src/zupt_lz.c src/zupt_lzh.c \
    src/zupt_xxh.c src/zupt_sha256.c src/zupt_aes256.c src/zupt_crypto.c \
    src/zupt_predict.c src/zupt_parallel.c src/zupt_keccak.c \
    src/zupt_x25519.c src/zupt_mlkem.c -lm -lpthread -o fuzz_zupt
```

## Corpus

```bash
mkdir -p corpus
# Generate seed archives
echo "test" > /tmp/t.txt
./zupt compress corpus/normal.zupt /tmp/t.txt
./zupt compress -p "pw" corpus/encrypted.zupt /tmp/t.txt
./zupt compress --solid corpus/solid.zupt /tmp/t.txt
./zupt compress -s corpus/store.zupt /tmp/t.txt
./zupt compress -f corpus/fast.zupt /tmp/t.txt
# PQ mode
./zupt keygen -o /tmp/k.key
./zupt keygen --pub -o /tmp/pub.key -k /tmp/k.key
./zupt compress --pq /tmp/pub.key corpus/pq.zupt /tmp/t.txt
# Truncated/corrupt
head -c 64 corpus/normal.zupt > corpus/truncated.zupt
dd if=/dev/urandom bs=200 count=1 of=corpus/random.zupt 2>/dev/null
```

## Run

```bash
mkdir -p findings
afl-fuzz -i corpus -o findings -m none -- ./fuzz_zupt
```

## Expected Coverage

The decompress harness exercises:
- Archive header parsing (magic, version, flags)
- Block header parsing (magic, codec, flags, varint sizes)
- LZ decompression (match/literal parsing, bounds checks)
- LZH decompression (Huffman table decode, code-length parsing)
- LZHP decompression (prediction decode + LZH)
- Index parsing (varint, path, sizes)
- Encryption header parsing (enc_type dispatch, PBKDF2 vs PQ)
- Encrypted block handling (HMAC verify, AES-CTR decrypt)

## Target: 72 hours, expect ~10K executions/sec

Known hard-to-reach paths:
- PQ decryption requires a valid ML-KEM ciphertext (unlikely from random fuzzing)
- Password decryption requires correct HMAC (rejected before any decompression)
- Solid mode decompression (requires valid solid flag + index)
