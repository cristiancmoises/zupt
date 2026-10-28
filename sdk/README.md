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
- **Per-context operations** — concurrent calls use distinct contexts; allocator hooks are process-wide
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
make sdk-test   # SDK runtime tests and focused regression groups
sudo make sdk-install PREFIX=/usr/local
```

This SDK is built from source via `make sdk`; the previously vendored prebuilt
`vendor/zuptsdk/libzuptsdk.so` has been removed from the tree. Build output is
written below the ignored `sdk/build/` directory and is never part of Git or an
upstream source archive.

The in-tree SDK shares the CLI's `WITH_JASMIN` selection: on supported x86_64
targets, `WITH_JASMIN=1` enables the checked-in assembly and its C call sites in
both builds. The SDK receives only the assembly-selection macro, without the
CLI's external SDK/PQBOX provider definitions or libraries. The public ABI and
archive format are unchanged.

Assembly selection and symbol references do not establish hardware AES
dispatch. Normal SDK calls do not initialize the internal CPU feature state,
so SDK AES operations retain the portable C path. SDK hardware AES dispatch
is not qualified by these build checks.

### Check SDK build flags

```sh
make test-sdk-build-flags
```

This target is required by `check` and `sdk-test`. Its 25 controls inspect GNU
make recipes for caller `CPPFLAGS`, assembly selection on/off across SDK object
rules, and isolation from external CLI provider flags and libraries. The target
uses dry runs with an x86_64 target model; it does not compile code, execute
assembly, or establish target CPU support.

Test the compiled SDK separately on supported x86_64 targets, cleaning before
each feature profile because make does not track compiler or flag changes as
object dependencies:

```sh
make clean
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  SDK_BUILD_DIR=build/sdk-gcc-c CFLAGS='-O2 -g -Werror' sdk-test sdk-verify-symbols
make clean
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 \
  SDK_BUILD_DIR=build/sdk-gcc-jasmin CFLAGS='-O2 -g -Werror' sdk-test sdk-verify-symbols
```

Repeat with `CC=clang` in a clean checkout to check that compiler. These commands
run the SDK tests and export checks; AES-NI dispatch requires separate evidence.

### Audit the callback interface

Run `make sdk-test-stream-errors` for the focused callback tests. They cover
byte-exact compression/decompression, read errors after partial output,
short/negative callback returns, input lengths greater than the supplied
buffer, close failures, cleanup, and preservation of the first error. A read
callback must return at most `max_bytes`. Stream failures can leave a prefix
with the output callback; callers must discard that output when the operation
returns an error.

The stream interface currently uses temporary files; decompression also buffers
the archive and extracted data in memory. It is not an incremental decoder.
These tests require a libc with `fopencookie` and a linker with `--wrap` support.
They are separate from the optional external `libvuptsdk` integration.

Use a caller-owned private temporary directory (`0700` on POSIX) and trusted
parent directories for SDK operations. `TMPDIR` selects that directory on
POSIX. A process that can replace entries in the chosen temporary parent can
also interfere with later reopen/cleanup operations; exclusive file creation
alone does not protect against that directory owner.

`make sdk-test-temp-paths` checks temporary-name formatting failures and real
directory hierarchies that exceed the internal path buffer. All public callers
reject a failed/truncated name with `ZUPTSDK_ERR_IO` before using that name.
The 26 checks include fixture validation and final allocation cleanup; they
verify foreign-file bytes/identity, output pointers, callbacks and descriptors.
Nested failures also clean up staging files already owned by the operation.
Windows directory-query checks do not constitute native Windows qualification.

`make sdk-test-staging` checks all five public staging paths. It verifies
owner-only mode and close-on-exec under `umask 000`, preservation of existing
regular files/symlinks/hardlinks, descriptor cleanup, and errors from permission
setup, stdio conversion, writing and closing. The staging opener shares the
key-file writer's exclusive creation and Windows protected-DACL construction;
it retains the original handle through stdio conversion.

`make sdk-test-file-reads` checks file sizing, seek/read/close and allocation
failures through the real buffer/file and decompression-stream APIs. A failure
does not publish a buffer or invoke the decompression output callback. The
tests check cleanup, wiping incomplete buffers, first-error preservation when
closing also fails, and valid empty files with a zero-allocation-rejecting
allocator. Returned buffers must still be released with `zuptsdk_free()`.

`make sdk-test-key-ownership` checks generated-key cleanup after allocation
failure and repeated public-key export/destruction. Generated files are owned
by their SDK handles; destroying a loaded key handle never removes the
caller-owned file. Files saved with `zuptsdk_keypair_save_*()` also remain
caller-owned. These POSIX tests preserve bytes and inode identity of colliding
regular files, symlinks and hardlinks. They do not cover every core key-write
failure or native Windows behavior.

`make sdk-test-read-stop` covers 18 key-copy and archive-readback cases. Reads
stop after EOF or error even if `fread` returned a positive byte count. The
output callback receives that prefix once; a read failure remains the reported
cause if delivery or close also fails. A callback's nested failed SDK call must
not replace the outer read diagnostic. Tests check exact delivered bytes,
positive short returns, destination bytes/inode identity and temporary cleanup.
Discard partial callback output whenever the operation returns an error.

`make sdk-test-key-write-errors` runs 74 checks for SDK temporary key generation
and public-key export. Internal creation flags distinguish owned partial files
from failures before creation and from regular-file/symlink/hardlink collisions.
The SDK removes its own failed outputs and preserves the first error even when
close, unlink or a custom allocator changes `errno`. The existing CLI key
writer deliberately retains incomplete or synchronization-uncertain files for
the user to inspect; its signatures, output format and behavior stay unchanged.
These tests exercise POSIX cleanup, not native Windows deletion or DACLs.

Use separate build directories to compare compilers and sanitizers:

```sh
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test sdk-verify-symbols
make CC=clang SDK_BUILD_DIR=build/sdk-ubsan \
  CFLAGS='-O1 -g -Werror -fsanitize=undefined -fno-sanitize-recover=all' \
  sdk-test sdk-verify-symbols
```

See the [English audit guide](../docs/USER_GUIDE.md#sdk-callback-tests) and
[instruções em português](../docs/GUIA_USUARIO.pt-BR.md#testes-de-callbacks-do-sdk)
for scope and reproduction details.

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

For parallel work, create one context per worker thread. Allocator hooks are
global: install them with `zuptsdk_set_allocator()` before any other
`zuptsdk_*` call, and do not change them after first use or concurrently with
SDK operations. Passing NULL to restore libc allocation is also valid only
before first use. Custom hooks must support the application's concurrent calls.
Error details use thread-local storage; internal CPU feature state is shared.

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
