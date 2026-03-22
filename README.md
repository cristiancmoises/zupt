# Zupt

**Backup compression with AES-256 authenticated encryption and post-quantum key encapsulation.**

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-1.0.0-orange)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

Zupt compresses and encrypts backup archives. LZ77+Huffman compression, AES-256-CTR + HMAC-SHA256 per-block authentication, multi-threaded, and optional ML-KEM-768 + X25519 post-quantum hybrid encryption. Pure C11, zero dependencies, ~5,000 lines.

---

## Why Zupt

- **Post-quantum encryption** (v0.7+). `--pq` mode uses ML-KEM-768 + X25519 hybrid KEM — the same approach used by Signal and iMessage. Protects against "harvest now, decrypt later" quantum attacks.
- **Encrypted backups in one command.** `zupt compress -p backup.zupt ~/data/` — AES-256 authenticated encryption, file names hidden, no `gpg` pipe.
- **Multi-threaded.** `-t 0` auto-detects cores. Batch-parallel compression pipeline.
- **Per-block integrity.** XXH64 checksum + HMAC-SHA256 per block. Wrong password/key rejected instantly.
- **Zero dependencies.** ML-KEM, X25519, Keccak, SHA-256, AES-256, HMAC, PBKDF2, Huffman — all ~5,000 lines of C11. Builds with `gcc` or `cl` alone.
- **Compression on par with gzip.** ([Benchmarks →](#benchmark-results))

---

## Quick Start

```bash
# Build
git clone https://github.com/cristiancmoises/zupt.git && cd zupt && make

# Password-encrypted backup
zupt compress -p backup.zupt ~/Documents/
zupt extract -o ~/restored/ -p backup.zupt

# Post-quantum encrypted backup
zupt keygen -o mykey.key                              # Generate keypair
zupt keygen --pub -o pub.key -k mykey.key             # Export public key
zupt compress --pq pub.key backup.zupt ~/Documents/   # Encrypt with public key
zupt extract --pq mykey.key -o ~/restored/ backup.zupt # Decrypt with private key
```

---

## Post-Quantum Encryption

v0.7.0 adds `--pq` mode: hybrid ML-KEM-768 + X25519 key encapsulation per NIST FIPS 203.

```
Recipient's public key → ML-KEM-768 Encaps + X25519 ECDH → hybrid shared secret
                        → SHA3-512(ss ‖ transcript) → enc_key[32] + mac_key[32]
                        → AES-256-CTR + HMAC-SHA256 per block (unchanged from password mode)
```

**Security model:** Secure if EITHER ML-KEM-768 (post-quantum) OR X25519 (classical) is secure. Both must be broken to compromise the archive.

**Password mode (`-p`) is NOT quantum-safe.** Use `--pq` for long-term protection.

---

## Benchmark Results

### Zupt vs gzip vs zstd — Level 7

| File Type | Zupt L7 | gzip -6 | zstd -7 |
|-----------|---------|---------|---------|
| English text | 629 KB (3.3:1) | 643 KB (3.3:1) | 638 KB (3.3:1) |
| JSON data | 296 KB (7.1:1) | 281 KB (7.5:1) | 242 KB (8.7:1) |
| Server logs | 908 KB (3.5:1) | 839 KB (3.7:1) | 797 KB (3.9:1) |
| Sparse binary | 467 KB (2.2:1) | 478 KB (2.2:1) | 463 KB (2.3:1) |

Ratio ≈ gzip. Zupt's value: encryption + integrity + PQ protection + zero dependencies.

---

## Feature Comparison

| Feature | Zupt | gzip | zstd | 7-Zip |
|---------|------|------|------|-------|
| Compression ratio | ≈ gzip | Baseline | 2–3× better | 2–3× better |
| Multi-threaded | ✓ | ✗ (pigz) | ✓ | ✓ |
| Post-quantum encryption | **✓ (ML-KEM-768)** | ✗ | ✗ | ✗ |
| Password encryption | AES-256 + HMAC | ✗ | ✗ | AES-256 |
| Integrity | XXH64 per-block | CRC32 | XXH64 | CRC32 |
| Recursive backup | ✓ | ✗ | ✗ | ✓ |
| Zero dependencies | ✓ | ✓ | ✗ | ✗ |
| License | MIT | GPL | BSD | LGPL |

---

## Security

```
Password mode:  Password → PBKDF2-SHA256 (600K iter) → enc_key + mac_key
PQ hybrid mode: Public key → ML-KEM-768 Encaps + X25519 ECDH → enc_key + mac_key
Per-block:      AES-256-CTR(enc_key, nonce ⊕ seq) + HMAC-SHA256(mac_key)
```

See [SECURITY.md](SECURITY.md) for threat model. See [AUDIT.md](AUDIT.md) for audit checklist.

---

## Usage

```
zupt compress [OPTIONS] <output.zupt> <files/dirs...>
zupt extract  [OPTIONS] <archive.zupt>
zupt list     [OPTIONS] <archive.zupt>
zupt test     [OPTIONS] <archive.zupt>
zupt keygen   [-o file] [--pub] [-k privkey]
zupt bench    <files/dirs...>
```

| Option | Description |
|--------|-------------|
| `-l <1-9>` | Compression level (default: 7) |
| `-t <N>` | Thread count (0=auto, 1=single, 2–64) |
| `-p [PW]` | Password encryption (PBKDF2) |
| `--pq <keyfile>` | Post-quantum hybrid encryption |
| `-o <DIR>` | Output directory (extract) |
| `-s` | Store without compression |
| `-f` | Fast LZ codec |
| `-v` | Verbose |
| `--solid` | Solid mode |

---

## Building

```bash
make                        # Linux/macOS
make test-all               # 16 regression tests
sh tests/test_threaded.sh   # 14 multi-threaded tests
sh tests/test_pq.sh         # 10 post-quantum tests
make test-asan              # AddressSanitizer
build.bat                   # Windows
```

---

## Roadmap

| Version | Status | Description |
|---------|--------|-------------|
| v0.5 | ✅ | Security hardening, Huffman codec fix |
| v0.6 | ✅ | Multi-threaded compression |
| v0.7 | ✅ | Post-quantum hybrid encryption (ML-KEM-768 + X25519) |
| **v1.0** | **✅ Current** | **Stable release, format frozen, security audit** |

---

## License

MIT - see [LICENSE](LICENSE).

Security vulnerabilities: see [SECURITY.md](SECURITY.md).

---

© 2026 Cristian Cezar Moisés - [github.com/cristiancmoises](https://github.com/cristiancmoises)
