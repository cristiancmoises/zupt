# ZUPT

[English](README.md) | [Português do Brasil](README.pt-BR.md)

ZUPT is a C11 backup archiver with VaptVupt compression and optional
authenticated encryption. It archives files and directories in `.zupt`
containers, supports multithreaded operation and provides a Python/Qt desktop
interface.

[Downloads](https://github.com/cristiancmoises/zupt/releases/latest) ·
[Installation](INSTALL.md) · [User guide](docs/USER_GUIDE.md) ·
[Website](https://zupt.securityops.co)

## Install

Download CLI bundles, desktop bundles and native packages from the
[release page](https://github.com/cristiancmoises/zupt/releases/latest).
See [INSTALL.md](INSTALL.md) for platform requirements, checksum verification
and installation instructions.

- **openSUSE Tumbleweed:** community packages are maintained in
  [OBS `home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators);
  see the [package page](https://software.opensuse.org/package/zupt).
- **GNU Guix:** the custom
  [Security Ops channel](https://git.securityops.com.br/cristiancmoises/securityops-channel)
  provides package definitions and channel setup instructions.
- **Other platforms:** use the release downloads or build from source below.

Thanks to Alessandro de Oliveira Faria
([Cabelo](https://build.opensuse.org/users/cabelo)) for helping maintain the
community openSUSE package.

## Command line

Create an archive, list its contents, test its integrity and restore it:

```sh
zupt compress backup.zupt documents/
zupt list backup.zupt
zupt test backup.zupt
mkdir -p restored
zupt extract -o restored backup.zupt
```

To encrypt a backup, enter the password interactively:

```sh
zupt compress --password-prompt encrypted.zupt documents/
mkdir -p restored-encrypted
zupt extract --password-prompt -o restored-encrypted encrypted.zupt
```

Unencrypted archives detect accidental corruption; they do not provide
confidentiality or cryptographic authentication. Keep the original data until
you have checked a restored copy. See `zupt --help`, `man zupt` and the
[user guide](docs/USER_GUIDE.md) for password files, post-quantum encryption
and additional options.

## Desktop interface

Run `zupt-gui` after installing the desktop package. The GUI uses the local
CLI and requires Python 3 with PySide6 or PyQt6. From a source checkout with
those dependencies installed:

```sh
ZUPT_BIN="$PWD/zupt" python3 gui/src/zupt_gui.py
```

See the [GUI guide](gui/README.md) for setup and desktop workflows.

## Web interface

Open [ZUPT Web](https://zupt-web.securityops.co) to try the browser interface.
Uploaded files are processed on the server. Use non-sensitive sample files;
use the local CLI or desktop interface for confidential data.

## Build from source

The CLI needs a C11 compiler and GNU Make. Tests also use Bash and Python 3.

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git switch 5.2.10
make -j2 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
```

See the [source-build guide](docs/USER_GUIDE.md#build-from-source) for platform
requirements, installation and optional integrations.

## Documentation

- [English user guide](docs/USER_GUIDE.md) and [guia em português](docs/GUIA_USUARIO.pt-BR.md).
- [GUI guide](gui/README.md) and [Portuguese reference](DOCUMENTACAO.pt-BR.md).
- [Security policy](SECURITY.md), [threat model](THREAT_MODEL.md) and [audit guide](AUDIT.md).
- [Distribution guide](DISTRIBUTION.md) and [changelog](CHANGELOG.md).

| ZUPT version | Bundled VaptVupt codec |
| --- | --- |
| 5.2.9 | 2.65.11 |
| 5.2.10 | 2.65.13 |

Sources: [GitHub](https://github.com/cristiancmoises/zupt),
[Security Ops](https://git.securityops.co/cristiancmoises/zupt),
[Security Ops Brazil](https://git.securityops.com.br/cristiancmoises/zupt) and
[Codeberg](https://codeberg.org/berkeley/zupt).

## License and contact

Copyright © 2025–2026 Cristian Cezar Moisés. The application and GUI use
[AGPL-3.0-or-later](LICENSE-AGPL-3.0); the identified codec files use
[GPL-3.0-or-later](LICENSE-GPL-3.0). Component licenses and notices are detailed
in [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

**Official contact: [sac@securityops.co](mailto:sac@securityops.co).**
This is the project's only official email address. `zupt@riseup.net` is not
associated with ZUPT. Report vulnerabilities through [SECURITY.md](SECURITY.md).
