THIRD-PARTY NOTICES
===================

**VaptVupt contains no third-party source code.** Every line of source in
this repository is the work of Cristian Cezar Moisés. This document
exists for transparency about runtime dependencies and build-time
tools.

If you redistribute VaptVupt, you must preserve this attribution document
along with the LICENSE file.

-------------------------------------------------------------------------
Components shipped in this repository (all original work)
-------------------------------------------------------------------------

| Component | Location | License | Author |
|---|---|---|---|
| vaptvupt CLI | src/, include/ | AGPL-3.0-or-later | Cristian Cezar Moisés |
| libzuptsdk | sdk/, vendor/zuptsdk/include/ | AGPL-3.0-or-later | Cristian Cezar Moisés |
| VaptVupt LZ codec | src/vv_*.c, src/vaptvupt_api.c, include/vaptvupt*.h | **GPL-3.0-or-later** | Cristian Cezar Moisés |
| Jasmin constant-time crypto | jasmin/*.jazz, jasmin/*.s | AGPL-3.0-or-later | Cristian Cezar Moisés |
| VaptVupt GUI (Python) | gui/ | AGPL-3.0-or-later | Cristian Cezar Moisés |

**Note on VaptVupt licensing**: VaptVupt is licensed GPL-3.0-or-later
(not AGPL like the rest of VaptVupt) so that, with sufficient maturity, it
can be considered for upstreaming into the Linux or BSD kernels, which
require GPL-compatible licenses. The author retains the right to dual-
license VaptVupt under other terms for commercial use; contact
sac@securityops.co for inquiries.

The rest of the project (vaptvupt CLI, libzuptsdk, Jasmin source, GUI) is
licensed AGPL-3.0-or-later. Commercial licenses (relief from AGPL
network-use clause) are available; contact sac@securityops.co.

-------------------------------------------------------------------------
Build-time tool (not redistributed)
-------------------------------------------------------------------------

**jasminc** — the Jasmin language compiler

The constant-time cryptographic primitives in jasmin/*.jazz are
compiled to native assembly (jasmin/*.s) using the external `jasminc`
compiler. The jasminc tool is not bundled with VaptVupt; the AGPL .jazz
source files and their AGPL-licensed .s assembly output are bundled.

  Upstream:  https://github.com/jasmin-lang/jasmin
  License:   MIT (the compiler itself; not relevant to VaptVupt's licensing)
  Used by:   VaptVupt's build system, only when re-generating jasmin/*.s
             from jasmin/*.jazz (most users won't need to do this —
             pre-built .s files ship in this repo).

-------------------------------------------------------------------------
Runtime system libraries (linked from the OS, never bundled)
-------------------------------------------------------------------------

These are standard system libraries provided by the operating system's
package manager (apt, dnf, pacman, etc.). They are dynamically linked
at runtime and are NOT redistributed as part of VaptVupt.

**libargon2** — Argon2id password hashing function (RFC 9106)

  Linked at runtime:  libargon2.so.1
  Version expected:   1.0+ (Debian/Ubuntu: libargon2-1)
  Upstream:           https://github.com/P-H-C/phc-winner-argon2
  License:            Apache-2.0 OR CC0-1.0 (dual)
  Copyright:          (c) 2015 The Argon2 Authors
  Used by:            Password-derived encryption mode

**OpenSSL libcrypto** — AES, SHA-256, AES-NI hardware backends

  Linked at runtime:  libcrypto.so.3
  Version expected:   3.0+
  Upstream:           https://www.openssl.org
  License:            Apache-2.0
  Copyright:          (c) 1998-2026 The OpenSSL Project
  Used by:            AES-256-CTR, SHA-256, hardware-accelerated paths

-------------------------------------------------------------------------
Compatibility with public standards
-------------------------------------------------------------------------

Where VaptVupt implements public standards, it does so independently
from any reference implementation. No code has been copied from
external projects. Standards followed:

  - FIPS 197  (AES)
  - FIPS 202  (Keccak / SHA-3)
  - FIPS 203  (ML-KEM)
  - RFC 5297  (AES-SIV)
  - RFC 5869  (HKDF)
  - RFC 7748  (X25519)
  - RFC 8032  (Ed25519)
  - RFC 8439  (ChaCha20-Poly1305)
  - RFC 9106  (Argon2)
  - RFC 9180  (HPKE)

The VaptVupt project was designed independently. Other projects in the
post-quantum hybrid encryption space (libsodium, age, Tink, rustls,
etc.) were referenced as prior art during design but no code was
copied. VaptVupt does not include any code from these projects.

-------------------------------------------------------------------------
Reporting attribution issues
-------------------------------------------------------------------------

If you believe VaptVupt redistributes code from a project not listed here,
or if attribution information is incomplete, please email:

   sac@securityops.co

with the subject "[third-party]" and details of the issue.

-------------------------------------------------------------------------
License summary
-------------------------------------------------------------------------

  VaptVupt CLI, libzuptsdk, Jasmin source, GUI:  AGPL-3.0-or-later
  VaptVupt LZ codec:                          GPL-3.0-or-later
  Commercial license (any component):         contact sac@securityops.co

  Project home:  https://git.securityops.co/cristiancmoises/vaptvupt
