# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.** Email **ethicalhacker@riseup.net** with description, reproduction steps, and impact assessment. Response within 48 hours, fix within 30 days for critical issues.

## Encryption Modes

| Mode | Flag | Quantum-Safe | Key Type |
|------|------|-------------|----------|
| Password | `-p` | No | PBKDF2-SHA256 → AES-256 |
| PQ Hybrid | `--pq` | **Yes** | ML-KEM-768 + X25519 → AES-256 |

**Password mode is NOT quantum-safe.** It uses PBKDF2-SHA256 which provides only classical security. For protection against "harvest now, decrypt later" attacks, use `--pq` mode.

## Threat Model

**Protects against:** Stolen archives, brute-force passwords (600K PBKDF2), archive tampering (per-block HMAC-SHA256), wrong-password/key disclosure, data corruption (per-block XXH64), future quantum computers (`--pq` mode only).

**Does NOT protect against:** Known password/key, cache-timing side channels (table-based AES/SHA-256), memory forensics, traffic analysis/deniability.

## Algorithms

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Post-quantum KEM | ML-KEM-768 | FIPS 203 |
| Classical KEM | X25519 | RFC 7748 |
| Hybrid KDF | SHA3-512(ml_ss ⊕ x_ss ‖ transcript) | Custom (documented) |
| Block encryption | AES-256-CTR | FIPS 197 |
| Block authentication | HMAC-SHA256 | RFC 2104 |
| Password KDF | PBKDF2-SHA256 | RFC 8018 |
| Integrity | XXH64 | xxHash spec |
| Hashing | SHA3-256, SHA3-512, SHAKE-128/256 | FIPS 202 |
| Random | /dev/urandom / RtlGenRandom | OS CSPRNG |
