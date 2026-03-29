# Zupt  — Platform Compatibility

## Tested Platforms

| Platform | Compiler | Status | Notes |
|----------|----------|--------|-------|
| Linux x86-64 (Ubuntu 24) | gcc 13, `-Wall -Wextra -O2 -std=c11` | **PASS** | Primary development target. Zero warnings. |
| Linux x86-64 (ASAN+UBSAN) | gcc 13, `-fsanitize=address,undefined -O1` | **PASS** | Zero memory errors across all modes. |

## Expected to Work (same code, untested in this cycle)

| Platform | Compiler | Notes |
|----------|----------|-------|
| Linux ARM64 | gcc / clang | No platform-specific code. LE serialization is portable. |
| macOS (Apple Silicon) | clang, Xcode | Uses `/dev/urandom`, POSIX APIs. `lstat` available. |
| macOS (Intel) | clang, Xcode | Same as above. |
| Windows (MinGW-w64) | gcc | `build.bat` auto-detects. Uses `_mkdir`, `FindFirstFile`. |
| Windows (MSVC) | cl | `build.bat` + CMake both support MSVC. `/D_CRT_SECURE_NO_WARNINGS`. |
| FreeBSD / OpenBSD | gcc / clang | POSIX-compliant. `explicit_bzero` available natively. |

## Portability Measures (v0.5.1 fixes)

- **Endianness:** All multi-byte on-disk fields use explicit little-endian serialization (`zupt_le16_put/get`, `zupt_le64_put/get`). Safe on big-endian systems.
- **Strict aliasing:** No type-punning via pointer casts. All multi-byte reads use `memcpy`.
- **No compiler builtins:** No `__int128`, no `__builtin_*` without fallback.
- **C11 only:** No C23 features. No POSIX-only APIs without `#ifdef _WIN32` alternatives.
- **Secure wipe:** `zupt_secure_wipe()` uses `explicit_bzero` (glibc 2.25+), `SecureZeroMemory` (MSVC), or volatile-pointer fallback.
- **CSPRNG:** `/dev/urandom` on Unix, `RtlGenRandom` on Windows. No `rand()` fallback.

## Known Limitations

1. **Solid mode buffer size:** Solid archives load the entire uncompressed stream into memory. Archives with total content >4 GB will be refused during extraction. Non-solid mode has no such limit (processes one block at a time).

2. **Maximum file count:** 2,000,000 files per archive (`ZUPT_MAX_FILES`).

3. **Maximum path length:** 4096 bytes (`ZUPT_MAX_PATH`).

4. **Maximum block size:** 256 MB (`ZUPT_MAX_BLOCK_SZ`). Default is auto-selected by compression level (128 KB – 512 KB).

5. **Symlinks:** Skipped with a warning. Not preserved in the archive.

6. **Special files:** Device files, FIFOs, sockets, and other non-regular files are skipped with a warning.

7. **File permissions:** Stored as a 32-bit attribute field but not currently restored on extraction (always creates with default permissions).

8. **Timestamps:** Modification time stored with nanosecond precision on Unix, second precision on Windows.

9. **Thread safety:** All functions are thread-safe by design (no global mutable state). However, multi-threaded compression (roadmap v0.4) is not yet implemented.

10. **Archive format:** v1.2. Forward-compatible: older decompressors will reject unknown codec IDs cleanly. Backward-compatible: v0.5.1 reads all v0.3+ archives.

## Build Requirements

- C11 compiler (gcc 5+, clang 3.5+, MSVC 2015+)
- Standard C library with `<math.h>` (link with `-lm`)
- No external dependencies
