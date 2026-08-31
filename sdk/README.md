# libzuptsdk

Public C ABI for the [ZUPT](https://github.com/cristiancmoises/zupt) backup compression library.

Provides post-quantum encrypted compression as a stable, embeddable shared library, independent of the `zupt` CLI and of any external compression library — everything is built from ZUPT's own implementations.

- **Version:** 1.0.0
- **License of the built library:** AGPL-3.0-or-later AND GPL-3.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND CC0-1.0
- **ABI:** Stable across 1.x via versioned symbols (`ZUPTSDK_1.0`)
- **C standard:** Public header is C99; C11 implementation; works in C++17

This in-tree compatibility SDK is named **libzuptsdk**. It is not the separately
packaged **libvuptsdk** dependency used by the CLI's optional `WITH_SDK=1`
integration. Running `make sdk` builds `libzuptsdk` from this repository; it does
not enable `--pq-sdk` or the libvuptsdk-backed Argon2id path in `zupt`.

## Features

- **Hybrid post-quantum encryption** — ML-KEM-768 + X25519 KEM
- **Authenticated encryption** — AES-256-CTR + HMAC-SHA256, PBKDF2-SHA256 KDF
- **Hardware-adaptive compression** — VaptVupt on AVX2/NEON, LZHP elsewhere
- **Streaming I/O** — read/write callbacks for sockets, pipes, encrypted volumes
- **Secure memory** — mlock-backed buffers for passwords and keys, zeroed on destroy
- **Optional assembly path** — textual Jasmin sources on supported x86_64 builds
- **Per-context state** — no globals; safe to use from any thread on distinct contexts
- **Custom allocator hooks** — supply your own malloc/free

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
git clone https://github.com/cristiancmoises/zupt
cd zupt
make            # builds the portable CLI (WITH_JASMIN=0 by default)
make sdk        # builds libzuptsdk.so.1.0.0 + libzuptsdk.a + zuptsdk.pc
make sdk-test   # runs C roundtrip suite (15 tests)
sudo make sdk-install PREFIX=/usr/local
```

This SDK is built from source via `make sdk`; the previously vendored prebuilt
`vendor/zuptsdk/libzuptsdk.so` has been removed from the tree. Build output is
written below the ignored `sdk/build/` directory and is never part of Git or an
upstream source archive.

The wrapper and application portions are AGPL-3.0-or-later. The library also
incorporates the bundled VaptVupt codec sources identified as
GPL-3.0-or-later, plus the BSD-2-Clause xxHash-derived routines and CC0-1.0
pq-crystals/kyber-derived ML-KEM portions, together with BSD-3-Clause
curve25519-donna-derived X25519 portions. Redistribution of the resulting
shared or static library must preserve all five scopes, `LICENSE-AGPL-3.0`,
`LICENSE-GPL-3.0`, `LICENSE-BSD-2-Clause`, `LICENSE-BSD-3-Clause`,
`LICENSE-CC0-1.0`, `NOTICE`, and `THIRD-PARTY-NOTICES.md`; see `sdk/LICENSE`
for the concise scope notice.

This installs:
- `/usr/local/include/zuptsdk.h`
- `/usr/local/lib/libzuptsdk.so.1.0.0` (with versioned `.so.1` and `.so` symlinks)
- `/usr/local/lib/libzuptsdk.a`
- `/usr/local/lib/pkgconfig/zuptsdk.pc`
- `/usr/local/share/licenses/libzuptsdk/` (all applicable texts and notices)

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

The built libzuptsdk contains AGPL-3.0-or-later wrapper/application code and
GPL-3.0-or-later bundled codec code; its complete SPDX expression is
**AGPL-3.0-or-later AND GPL-3.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND
CC0-1.0** (see `sdk/LICENSE`).

Redistributors must comply with the applicable terms and preserve all license
texts and notices. Consult the license texts rather than this summary for the
precise source-correspondence and network-use obligations.

## Contact

- Repository: https://github.com/cristiancmoises/zupt
- Project: https://github.com/cristiancmoises/zupt
- Email: sac@securityops.co
