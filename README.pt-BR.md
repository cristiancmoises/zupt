<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ZUPT

[English](README.md) | [Português do Brasil](README.pt-BR.md)

O ZUPT é um arquivador de backups em C11 com compressão VaptVupt e
criptografia autenticada opcional. Reúne arquivos e diretórios em contêineres
`.zupt`, oferece processamento com múltiplas threads e conta com uma interface
de desktop em Python/Qt.

[Downloads](https://github.com/cristiancmoises/zupt/releases/latest) ·
[Instalação](INSTALL.md) · [Guia de usuário](docs/GUIA_USUARIO.pt-BR.md) ·
[Site](https://zupt.securityops.co)

## Instalação

Baixe os bundles da CLI, da interface gráfica e os pacotes nativos na
[página de releases](https://github.com/cristiancmoises/zupt/releases/latest).
Consulte [INSTALL.md](INSTALL.md) para requisitos de cada plataforma,
verificação das somas de integridade e instruções de instalação.

- **openSUSE Tumbleweed:** os pacotes comunitários são mantidos no
  [OBS `home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators);
  consulte a [página do pacote](https://software.opensuse.org/package/zupt).
- **GNU Guix:** o
  [canal personalizado Security Ops](https://git.securityops.com.br/cristiancmoises/securityops-channel)
  contém definições de pacotes e instruções de configuração do canal.
- **Outras plataformas:** use os downloads ou compile a partir da fonte abaixo.

Agradecemos a Alessandro de Oliveira Faria
([Cabelo](https://build.opensuse.org/users/cabelo)) pela ajuda na manutenção do
pacote comunitário para openSUSE.

## Linha de comando

Crie um arquivo, liste seu conteúdo, teste a integridade e restaure os dados:

```sh
zupt compress backup.zupt documentos/
zupt list backup.zupt
zupt test backup.zupt
mkdir -p restaurado
zupt extract -o restaurado backup.zupt
```

Para criptografar um backup, informe a senha de forma interativa:

```sh
zupt compress --password-prompt criptografado.zupt documentos/
mkdir -p restaurado-criptografado
zupt extract --password-prompt -o restaurado-criptografado criptografado.zupt
```

Arquivos sem criptografia detectam corrupção acidental, mas não oferecem
confidencialidade nem autenticação criptográfica. Preserve os dados originais
até conferir uma cópia restaurada. Consulte `zupt --help`, `man zupt` e o
[guia de usuário](docs/GUIA_USUARIO.pt-BR.md) para arquivos de senha, criptografia
pós-quântica e outras opções.

## Interface de desktop

Execute `zupt-gui` após instalar o pacote da interface gráfica. A GUI usa a
CLI local e precisa de Python 3 com PySide6 ou PyQt6. Em uma cópia do código-fonte
com essas dependências instaladas:

```sh
ZUPT_BIN="$PWD/zupt" python3 gui/src/zupt_gui.py
```

Consulte o [guia da GUI](gui/README.md) para configuração e uso no desktop.

## Interface web

Acesse o [ZUPT Web](https://zupt-web.securityops.co) para experimentar a
interface no navegador. Os arquivos enviados são processados no servidor.
Use exemplos sem dados sensíveis; para dados confidenciais, use a CLI ou
a interface de desktop local.

## Compilação a partir da fonte

A CLI precisa de compilador C11 e GNU Make. Os testes também usam Bash e Python 3.

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git switch 5.2.10
make -j2 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
```

Consulte o [guia de compilação](docs/GUIA_USUARIO.pt-BR.md#compilação-a-partir-do-código-fonte)
para requisitos de plataforma, instalação e integrações opcionais.

## Documentação

- [Guia de usuário em português](docs/GUIA_USUARIO.pt-BR.md) e [English user guide](docs/USER_GUIDE.md).
- [Guia da GUI](gui/README.md) e [referência em português](DOCUMENTACAO.pt-BR.md).
- [Política de segurança](SECURITY.md), [modelo de ameaças](THREAT_MODEL.md) e [guia de auditoria](AUDIT.md).
- [Guia de distribuição](DISTRIBUTION.md) e [changelog](CHANGELOG.md).

| Versão do ZUPT | Codec VaptVupt integrado |
| --- | --- |
| 5.2.9 | 2.65.11 |
| 5.2.10 | 2.65.13 |

Fontes: [GitHub](https://github.com/cristiancmoises/zupt),
[Security Ops](https://git.securityops.co/cristiancmoises/zupt),
[Security Ops Brasil](https://git.securityops.com.br/cristiancmoises/zupt) e
[Codeberg](https://codeberg.org/berkeley/zupt).

## Licença e contato

Copyright © 2025–2026 Cristian Cezar Moisés. O aplicativo e a GUI usam
[AGPL-3.0-or-later](LICENSE-AGPL-3.0); os arquivos identificados do codec usam
[GPL-3.0-or-later](LICENSE-GPL-3.0). As licenças e os avisos dos componentes estão
em [LICENSE](LICENSE), [NOTICE](NOTICE) e [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

**Contato oficial: [sac@securityops.co](mailto:sac@securityops.co).**
Este é o único e-mail oficial do projeto. `zupt@riseup.net` não tem relação
com o ZUPT. Relate vulnerabilidades conforme [SECURITY.md](SECURITY.md).
