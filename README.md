# ZUPT

[English](README.md) | [Português do Brasil](README.pt-BR.md)

ZUPT is a backup archiver with VaptVupt compression, authenticated encryption,
multithreaded operation, and an optional Python/Qt graphical interface. The
command-line application is written in C11.

This checkout documents **ZUPT 5.2.10**. For published packages and their
checksums, use the [latest official release](https://github.com/cristiancmoises/zupt/releases/latest).

| Version | Reference | Bundled VaptVupt codec |
| --- | --- | --- |
| 5.2.9 | Release history | 2.65.11 |
| 5.2.10 | Source version documented here | 2.65.13 |

Source: [release history](CHANGELOG.md), reviewed 2026-11-12 UTC. The update
is described in the [user guide](docs/USER_GUIDE.md) and
[codec notices](THIRD-PARTY-NOTICES.md).

## Download and installation

Use the [official release page](https://github.com/cristiancmoises/zupt/releases/latest)
for available packages and their checksums. Follow the
[installation guide](INSTALL.md) for your platform and verify downloaded files
before running them. Development version strings do not identify a release.

### openSUSE Tumbleweed

ZUPT is available through the community OBS project
[`home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators).
Select your distribution and architecture on the
[openSUSE package page](https://software.opensuse.org/package/zupt). Review the
matching repository and its signing key before enabling it. After configuring
that repository on a non-transactional system:

```sh
sudo zypper refresh
sudo zypper install zupt
zupt --version
```

For an installed package, use `sudo zypper update zupt` and review the proposed
transaction. Keep signature checks enabled. These are community packages;
this is not a claim of inclusion in the default distribution repositories.
See the [Tumbleweed instructions](docs/USER_GUIDE.md#install-from-opensuse-tumbleweed)
for repository and update details.

Thanks to Alessandro de Oliveira Faria
([Cabelo](https://build.opensuse.org/users/cabelo)) for helping maintain the
community openSUSE package.

### Build from source

The default build needs a C11 compiler, GNU Make and the system C, math and
threading libraries. The build does not download dependencies. Bash and
Python 3 are used by the test suite. This example builds the `5.2.10` version
branch; see the guide below for a build pinned to a published signed tag.

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git switch 5.2.10
make -j2 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
```

See the [source-build guide](docs/USER_GUIDE.md#build-from-source) for staged
installation, uninstall, optional integrations and platform requirements.

## Basic usage

Create, inspect, check and extract an archive:

```sh
zupt compress backup.zupt documents/
zupt list backup.zupt
zupt test backup.zupt
mkdir -p restored
zupt extract -o restored backup.zupt
```

An unencrypted archive detects accidental corruption; it does not provide
confidentiality or cryptographic authentication. To encrypt a backup, enter the
password interactively:

```sh
zupt compress --password-prompt encrypted.zupt documents/
zupt extract --password-prompt -o restored-encrypted encrypted.zupt
```

Keep passwords and private keys out of command history and process arguments.
The [user guide](docs/USER_GUIDE.md#command-line-workflow) explains password
files, inherited descriptors, post-quantum modes and restore verification.
Use `zupt --help` or `man zupt` for available options. Keep the original data
until you have verified a restored copy.

Software bundles also use `.zupt`. Check a bundle with `zupt test` before
extracting it; extraction does not restore executable permissions. Follow the
[bundle instructions](docs/USER_GUIDE.md#working-with-zupt-bundles) before running
an extracted program.

## Web and graphical interfaces

Try [ZUPT Web](https://zupt-web.securityops.co) with non-sensitive sample files
and disposable credentials. Uploaded data is processed on the server. The web
service has its own version, limits and trust boundary.

The optional desktop interface invokes the local CLI and requires Python 3
with PySide6 or PyQt6. See the [GUI guide](gui/README.md) and the
[documented workflows](docs/USER_GUIDE.md#gui-workflow).

## Documentation and tests

- [English user guide](docs/USER_GUIDE.md) and
  [guia de usuário em pt-BR](docs/GUIA_USUARIO.pt-BR.md): installation, commands,
  compatibility, troubleshooting and complete test instructions.
- [Audit guide](AUDIT.md): executed checks, assumptions and unresolved coverage.
- [Distribution guide](DISTRIBUTION.md): package contents and release gates.
- [Security policy](SECURITY.md) and [threat model](THREAT_MODEL.md).
- [Changelog](CHANGELOG.md) and [Portuguese documentation](DOCUMENTACAO.pt-BR.md).

The user guides contain the test commands, supported tools and validation
limits, including Frama-C, Jasmin and sanitizer checks.

## Source, license and contact

Sources: [Security Ops](https://git.securityops.co/cristiancmoises/zupt),
[GitHub](https://github.com/cristiancmoises/zupt),
[Codeberg](https://codeberg.org/berkeley/zupt) and
[Security Ops Brazil](https://git.securityops.com.br/cristiancmoises/zupt).
Project website: [zupt.securityops.co](https://zupt.securityops.co).

Copyright © 2025–2026 Cristian Cezar Moisés. The application and tool code use
**AGPL-3.0-or-later**; separately identified bundled codec files use
**GPL-3.0-or-later**. Preserve the applicable BSD, CC0 and public-domain notices,
license texts and per-file SPDX headers. See [LICENSE](LICENSE),
[NOTICE](NOTICE) and [third-party notices](THIRD-PARTY-NOTICES.md). Earlier
grants for exact published revisions remain recorded in those licensing
materials. [Commercial licensing](LICENSE-COMMERCIAL) is an inquiry notice,
not a replacement for the public licenses.

**Official contact: [sac@securityops.co](mailto:sac@securityops.co).** This is the
project's only official email address. `zupt@riseup.net` is not associated with
ZUPT. Report vulnerabilities through the [security policy](SECURITY.md).
