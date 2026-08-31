# Third-party and bundled-component notices

This file records bundled source, generated textual source and optional system
dependencies. Preserve it with LICENSE, NOTICE, and the applicable license
texts.

## Bundled VaptVupt codec

The compression codec in src/vv_*.c, src/vaptvupt_api.c,
include/vaptvupt*.h, and include/vv_*.h is bundled as source and licensed
GPL-3.0-or-later.

- Recorded codec release: 2.65.3
- Recorded upstream tag: v2.65.3
- Standalone upstream: https://git.securityops.co/cristiancmoises/vaptvupt-codec
- Integration commit in this repository:
  59f9ebc59ea13c6edf1d199ca795cdbf00e62226

The integration commit records an in-tree ANS safe-zone reserve applied on top
of that tag. Earlier integration commit a2350dd also records wrapper-default
changes used by the CLI. This repository did not retain the standalone tag
object hash, so the tag name and the immutable integration commits are the
provenance evidence available here; no unverified external hash is asserted.

The openSUSE package truthfully declares
bundled(vaptvupt-codec) = 2.65.3. No compiled codec object or library is
distributed in the source tree or source archive.

## Jasmin and textual assembly

Files under `jasmin/` include AGPL-licensed `.jazz` source or algorithm
descriptions and textual GNU assembly `.s`. The assembly is source, not an
object file. Provenance is recorded per production unit rather than treating
every `.s` file as generated:

- `zupt_mac_verify.s`, `zupt_mlkem_select.s`, and `zupt_x25519_fe.s` identify
  themselves as output of Jasmin Compiler 2026.03.0;
- `zupt_aes_ctr.s` is recorded in its file header as `jasminc` output, but the
  exact compiler version was not retained in that file, so no version stronger
  than the repository record is asserted;
- `zupt_aes_ctr4.s` is hand-written production assembly matching the algorithm
  documented by `zupt_aes_ctr4.jazz`; that `.jazz` file is not compiled.

Regeneration of files identified as compiler output uses the external
`jasminc` compiler:

- Upstream: https://github.com/jasmin-lang/jasmin
- Compiler license: MIT

The compiler itself is not bundled or redistributed. Hand-written assembly
must not be represented as generated or formally verified merely because a
corresponding `.jazz` description exists.

## Optional system libraries

The default WITH_SDK=0 WITH_PQBOX=0 build uses the operating system's C runtime,
math and threading libraries and does not bundle a shared library.

WITH_SDK=1 and WITH_PQBOX=1 are opt-in integrations. They use only headers and
libraries supplied by the system/toolchain configuration and fail explicitly
when those dependencies are unavailable:

- libvuptsdk: enables --pq-sdk and the Argon2id-backed SDK path;
- libpqvaptvupt: enables --pq-box.

The former vendor/vuptsdk and vendor/pqvaptvupt header snapshots and all
fallbacks to local precompiled libraries were removed. No download occurs in
make, packaging build, or package checks.

## xxHash-derived source

`src/zupt_xxh.c` and `src/vv_xxh64.c` contain adapted XXH64 routines based on
xxHash by Yann Collet. xxHash is BSD-2-Clause, not public domain. The upstream
copyright, conditions, and disclaimer are preserved in
`LICENSE-BSD-2-Clause`; those obligations apply in addition to the AGPL or GPL
scope identified by each source file.

- Upstream: https://github.com/Cyan4973/xxHash
- Upstream license: https://github.com/Cyan4973/xxHash/blob/dev/LICENSE

## pq-crystals/kyber-derived ML-KEM source

`src/zupt_mlkem.c` contains portions adapted from the pq-crystals/kyber
reference implementation, including its NTT, base multiplication, Montgomery
conversion, and related representation conventions. The upstream project
offers that reference code under either CC0-1.0 or Apache-2.0; ZUPT elects
the CC0-1.0 option for those portions. Local integration and modifications
remain under AGPL-3.0-or-later, as recorded by the compound per-file SPDX
identifier.

- Upstream: https://github.com/pq-crystals/kyber
- Upstream license record: https://github.com/pq-crystals/kyber/blob/main/LICENSE
- Local introduction commit: c80332778fb10364a606bf0380f440dc7be66ced
- Local FIPS 203 correction commit: 862f4a2df6c756ebd0369e176ea68b5ac506f422

The repository did not retain an immutable upstream Kyber revision for the
original adaptation. No unverified upstream commit is asserted. The complete
CC0-1.0 legal text is in `LICENSE-CC0-1.0`.

## curve25519-donna-derived X25519 source

`src/zupt_x25519.c` contains portions adapted from the 5x51-bit
curve25519-donna implementation, including its field representation, packing,
constant-time swap, and inversion-chain approach. The upstream source file
describes the code as public domain, while the repository preserves a
BSD-3-Clause notice. This distribution conservatively retains that complete
BSD-3-Clause notice in `LICENSE-BSD-3-Clause`; local integration and
modifications remain AGPL-3.0-or-later under the compound per-file SPDX
identifier.

- Upstream: https://github.com/agl/curve25519-donna
- Upstream license record: https://github.com/agl/curve25519-donna/blob/master/LICENSE.md
- Upstream copyright: Copyright 2008, Google Inc.
- Upstream author record: Adam Langley
- Local introduction commit: c80332778fb10364a606bf0380f440dc7be66ced

The repository did not retain an immutable upstream revision for the original
adaptation. No unverified upstream commit is asserted, and the historical
reference to libsodium is treated as an implementation comparison rather than
an unsupported claim that libsodium was the copied source.

## LZMA SDK x86 BCJ source

The x86 state machine in `src/vv_bcj.c` is adapted from Igor Pavlov's
`C/Bra86.c` in the LZMA SDK. The official LZMA SDK is placed in the public
domain. The AArch64 filter in the same file is separately documented local
code and is not represented as LZMA SDK source.

- Upstream: https://www.7-zip.org/sdk.html
- Upstream author: Igor Pavlov
- Upstream status: public domain

The exact SDK version or revision used by the original integration was not
retained, so none is asserted. The former `clean-room` description was removed
because repository evidence cannot establish that development process.

## SHA-Intrinsics SHA-NI source

The SHA-NI compression path in `src/zupt_sha256_shani.c` is adapted from
Jeffrey Walton's public-domain `SHA-Intrinsics/sha256-x86.c` reference, which
records that it is based on Intel and Sean Gulley's miTLS material. The
immutable upstream reference below explicitly places the code in the public
domain; it therefore adds no separate package-license term. Local integration
and modifications remain AGPL-3.0-or-later.

- Upstream: https://github.com/noloader/SHA-Intrinsics
- Audited source revision: d03795497f3e4576083fc2cd8fe0b924f24d0bb2
- Upstream source: https://github.com/noloader/SHA-Intrinsics/blob/d03795497f3e4576083fc2cd8fe0b924f24d0bb2/sha256-x86.c
- Upstream author: Jeffrey Walton
- Upstream status: public domain
- Local introduction commit: 544a2cd64758478690e33a923b2ab75347122f51

## GUI image data

The PNG and ICO files under gui/assets/ are non-executable first-party GUI data.
Their purpose, Git provenance and license scope, including the historical MIT
grant attached to their unchanged Git blobs, are recorded in
`gui/assets/README.md`.

## AppImage type-2 runtime

No AppImage is a promised or promoted 5.2.5 release asset. The upstream
type-2 runtime inspected during the 5.2.2 review statically linked musl, libfuse,
squashfuse, zstd, zlib, and mimalloc, but its own license notice did not list
mimalloc and the available release inputs did not provide a complete
LGPL-compatible source/relink handoff. ZUPT therefore does not
redistribute that runtime.

`packaging/build-appimage.sh` remains an offline downstream helper. It accepts
no network input and requires the operator to supply both a locally verified
runtime and `APPIMAGE_RUNTIME_COMPLIANCE_FILE`, containing the license notices,
source correspondence or offer, and relink information applicable to those
exact runtime bytes. An artifact produced independently with that helper is
not covered by the 5.2.5 upstream release gates.

## Reporting attribution issues

Report incomplete or incorrect attribution to sac@securityops.co with the
subject [third-party].
