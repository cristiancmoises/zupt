# libzuptsdk

Public C ABI for the [Zupt](https://git.securityops.co/cristiancmoises/zupt) backup compression library.

Provides post-quantum encrypted compression as a stable, embeddable shared library — completely independent of the `zupt` CLI.No dependency on any other compression library; everything is built from Zupt's own implementations.

- **Version:** 1.0.0
- **License:** AGPL-3.0-or-later
- **ABI:** Stable across 1.x via versioned symbols (`ZUPTSDK_1.0`)
- **C standard:** Public header is C99; C11 implementation; works in C++17

## Features

- **Hybrid post-quantum encryption** — ML-KEM-768 + X25519 KEM
- **Authenticated encryption** — AES-256-CTR + HMAC-SHA256, PBKDF2-SHA256 KDF
- **Hardware-adaptive compression** — VaptVupt on AVX2/NEON, LZHP elsewhere
- **Streaming I/O** — read/write callbacks for sockets, pipes, encrypted volumes
- **Secure memory** — mlock-backed buffers for passwords and keys, zeroed on destroy
- **Constant-time crypto** — Jasmin-verified assembly on x86_64
- **Per-context state** — no globals; safe to use from any thread on distinct contexts
- **Custom allocator hooks** — embed cleanly in any runtime

## Quick start (C)

```c
#include <zuptsdk.h>

zuptsdk_ctx_t *ctx;
zuptsdk_ctx_create(&ctx);

zuptsdk_secure_buf_t *pw;
zuptsdk_secure_buf_from_data((const uint8_t *)"mypassword", 10, &pw);

uint8_t *archive;
size_t archive_sz;
zuptsdk_compress_buffer(ctx, NULL, "data.bin",
                        my_data, my_data_size,
                        pw, NULL,
                        &archive, &archive_sz);

/* ... store archive somewhere ... */

uint8_t *out;
size_t out_sz;
zuptsdk_extract_buffer(ctx, archive, archive_sz, pw, NULL, &out, &out_sz);

zuptsdk_free(archive);
zuptsdk_free(out);
zuptsdk_secure_buf_destroy(pw);
zuptsdk_ctx_destroy(ctx);
```

Build with `pkg-config`:

```sh
gcc myapp.c $(pkg-config --cflags --libs zuptsdk) -o myapp
```

## Quick start (Python)

```python
import zuptsdk

with zuptsdk.Context() as ctx:
    archive = ctx.compress_buffer(b"hello world",
                                   name="hello.txt",
                                   password=b"secret")

    data = ctx.extract_buffer(archive, password=b"secret")
    assert data == b"hello world"
```

Post-quantum mode:

```python
with zuptsdk.Context() as ctx:
    kp = ctx.generate_keypair()
    kp.save("/tmp/mykey")  # writes mykey.key (priv, 0600) + mykey.pub (pub, 0644)

    archive = ctx.compress_buffer(b"secret data",
                                   name="s.txt",
                                   public_key=kp.public)

    data = ctx.extract_buffer(archive, private_key=kp.private)
```

## Build & install

```sh
git clone https://git.securityops.co/cristiancmoises/zupt
cd zupt
make            # builds CLI (required: produces jasmin/*.o assembly objects)
make sdk        # builds libzuptsdk.so.1.0.0 + libzuptsdk.a + zuptsdk.pc
make sdk-test   # runs C roundtrip suite (15 tests)
sudo make sdk-install PREFIX=/usr/local
```

This installs:
- `/usr/local/include/zuptsdk.h`
- `/usr/local/lib/libzuptsdk.so.1.0.0` (with versioned `.so.1` and `.so` symlinks)
- `/usr/local/lib/libzuptsdk.a`
- `/usr/local/lib/pkgconfig/zuptsdk.pc`

## Symbol visibility

The shared library exports **only** the 55 documented public symbols, all prefixed with `zuptsdk_`. Internal `zupt_*` and `vv_*` symbols are hidden via a linker version script.

Verify yourself:

```sh
make sdk-verify-symbols
# [sdk-verify] checking exported symbols in sdk/build/libzuptsdk.so.1.0.0
#   55 exported / 55 declared in version script
#   PASS: no symbol leakage, all declared symbols exported
```

## ABI stability policy

Every symbol declared in `zuptsdk.h` is part of the stable v1.0 ABI and is gated under the linker tag `ZUPTSDK_1.0`.

- **New symbols** in v1.x get added under new tags (`ZUPTSDK_1.1`, ...)
- **Existing symbols** never change signature within v1.x
- **Breaking changes** require a major bump (`libzuptsdk.so.2`)

Do not link against internal `zupt_*` symbols even if you find them in the static archive — they will disappear without notice.

## Thread safety

- Concurrent calls on **distinct contexts** are safe (MT-Safe).
- Concurrent calls on the **same context** are not safe.

For parallel work, create one context per worker thread.

## Memory ownership

Every output pointer documents its destroyer. Always use the documented function (`zuptsdk_free`, `zuptsdk_*_destroy`) to release memory — never bare `free()` — because the library may have been built with a custom allocator.

Function parameter conventions:
- `[in]` — caller owns, library reads only
- `[out]` — caller owns, library writes
- `[in,out]` — caller owns, library reads and writes
- `[transfers]` — ownership moves caller ↔ library
- `[borrowed]` — pointer valid only for the duration of the call

## Error handling

Functions return `int` where 0 = success, negative = `zuptsdk_error_t` code.

```c
int rc = zuptsdk_compress_buffer(...);
if (rc != ZUPTSDK_OK) {
    fprintf(stderr, "%s\n", zuptsdk_strerror(rc));
    fprintf(stderr, "  detail: %s\n", zuptsdk_last_error_detail());
    return rc;
}
```

`zuptsdk_last_error_detail()` returns a thread-local string with file:line context.

## Components

```
sdk/
├── include/zuptsdk.h              # Public C99 header (55 functions, 7 opaque types)
├── src/zuptsdk.c                  # Implementation (wraps zupt internals)
├── zuptsdk.map                    # Linker version script (gates exports)
├── Makefile.sdk                   # Build integration
├── bindings/python/zuptsdk.py     # Python cffi reference bindings
├── tests/test_sdk_roundtrip.c     # C roundtrip suite
└── tests/test_python.py           # Python test suite
```

## License

libzuptsdk is licensed under **AGPL-3.0-or-later** (see `sdk/LICENSE`).

The AGPL allows everyone to use the library freely, but anyone running it as a network service must publish their source code modifications. This protects the project from enterprise exploitation while keeping it usable by individuals, small businesses, and the open-source community.

## Contact

- Repository: https://git.securityops.co/cristiancmoises/zupt
- Website: https://zupt.securityops.co
- Email: zupt@riseup.net
