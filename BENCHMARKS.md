# VaptVupt Benchmarks

All numbers here are **measured**, not aspirational. Each table states the
machine, the build, and the method. Where VaptVupt loses to a competitor,
the table shows it.

> **Superseded data note.** The v3.8.0 edition of this file was measured
> on a different machine (Xeon 2.80 GHz, no SHA-NI) against a different
> generation of the synthetic fixtures. Absolute numbers below are not
> comparable to that edition; the codec-stability question is settled by
> the same-input gate table (§1), not by cross-edition comparison.

## Test environment

| Property | Value |
|----------|-------|
| CPU | Intel Xeon @ 2.10 GHz |
| Cores used | 1 (single-threaded measurement) |
| Hardware accel present | AES-NI, **SHA-NI**, AVX2 (codec) |
| Build | VaptVupt 4.0.0, `make` defaults, `-O2`, Jasmin AES-NI path active |
| Codec | VaptVupt **2.60.4** (LZ + ANS, canonical BCJ) |
| Method | best of 3 runs, wall clock |

## 1. Codec ratio gate: 2.53.3-era vs 2.60.4, identical inputs

Upstream 2.60.4 claims compressed output byte-identical to prior
releases. Verified here by compressing the **same fixture bytes** with
the shipped 3.8.0 binary and the 4.0.0 binary (L9, plain):

| Fixture | 3.8.0 archive | 4.0.0 archive | Δ |
|---------|--------------:|--------------:|---|
| text | 1 990 322 B | 1 990 322 B | **0.00 %** |
| source | 1 698 907 B | 1 698 907 B | **0.00 %** |
| redundant | 3 344 B | 3 344 B | **0.00 %** |
| binary | 3 119 605 B | 3 356 213 B | +7.58 % — **not comparable**: the 3.8.0 stream is the F-16 *corrupt* output (undecodable by any version); 4.0.0 emits the canonical BCJ stream that actually decodes |

Gate **holds** everywhere a valid stream exists on both sides.

## 2. Compression ratio + throughput (plain, level 9, this box's fixtures)

| Fixture | In (MB) | Ratio | Encode (MB/s) | Decode (MB/s) |
|---------|--------:|------:|--------------:|--------------:|
| text | 10.0 | 5.27 | 2 | 314 |
| binary | 7.5 | 2.34 | 2 | 209 |
| source | 10.0 | 6.17 | 1 | 304 |
| redundant | 10.0 | 3135.69 | 299 | 692 |
| random | 5.0 | 1.00 | 24 | 570 |

Decode 209–692 MB/s; L9 encode remains 1–2 MB/s on compressible data
(optimal parser) — use lower levels when encode speed matters.

## 3. SHA-256: scalar vs SHA-NI (measured, same box)

The v3.2.0 SHA-NI path could only be **estimated** (3–8×) because the
old measurement box lacked the instruction set. Measured now, 256 MiB
single buffer, runtime dispatch vs forced scalar:

| Path | Throughput |
|------|-----------:|
| scalar C | 204 MB/s |
| SHA-NI | **1184 MB/s** |
| **speedup** | **5.8×** |

(Independently consistent with libpqvaptvupt 0.6.0's own measurement of
5.9× on its SHA-256.) The estimate label is hereby retired.

## 4. Encryption overhead (store mode isolates crypto from the codec)

Per-MB ≈ (t₄₀MB − t₁MB) ÷ 39; KDF ≈ t₁MB − per-MB.

| Mode | Per-MB crypto | One-time KDF |
|------|--------------:|-------------:|
| plain (no encryption) | 1.94 ms (515 MB/s) | ≈3 ms |
| password — Argon2id (default) | 3.42 ms (**293 MB/s**) | ≈839 ms |
| password — PBKDF2 | 3.58 ms (280 MB/s) | ≈550 ms |
| **pq-box** (`--pq-box`, v4.0.0) | same as plain + MAC path | seal ≈3 ms / open ≈3 ms |

Readings:
- Encrypted per-block throughput is **~2× the 3.8.0-era figure on a
  slower clock** (293 MB/s at 2.10 GHz vs 146 MB/s at 2.80 GHz) — the
  HMAC-SHA256 Encrypt-then-MAC second pass now runs on SHA-NI.
- The Argon2id one-time cost (~0.8 s) is memory-hardness working as
  designed, not a target for optimization.
- PBKDF2's KDF also benefits from SHA-NI (~550 ms here vs ~1.56 s on the
  old non-SHA-NI box) — but Argon2id remains the default for its
  memory-hardness, not its speed.
- `--pq-box` adds ~3 ms one-time seal/open for the 32-byte session key
  (ML-KEM-768 + X25519 + HKDF); per-block cost is the standard AES-NI +
  SHA-NI path.

## 5. What the product is

The codec is competitive on decode, not the reason to use VaptVupt
(zstd-19 wins pure ratio). The reason is the combination: post-quantum
hybrid recipient encryption (three modes, newest = HKDF-domain-separated
sealed box), Argon2id by default with a self-describing KDF header,
per-block Encrypt-then-MAC with every security-critical comparison
routed through one audited measured-constant-time primitive, canonical
CBMC-verified BCJ filters, and 16 NIST/RFC known-answer vectors in CI.

## Reproducing

```sh
make
./vaptvupt c -l 9 /tmp/a.zupt fixtures/text.dat       # ratio/speed
./vaptvupt c -s -p PW /tmp/p.zupt big.dat             # crypto overhead
./vaptvupt keygen --box -o k && \
  ./vaptvupt c -s --pq-box k.pub /tmp/b.zupt big.dat  # pq-box
make test-vectors && ./test_vectors                    # NIST/RFC vectors
```

Absolute numbers vary by machine; the shape (KDF-dominated password
cost, SHA-NI ≈6× on SHA-256, ~3 ms pq-box envelope) is stable.
