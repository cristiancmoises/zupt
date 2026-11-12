<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ZUPT

[English](README.md) | [Português do Brasil](README.pt-BR.md)

O ZUPT é um arquivador de backups com compressão VaptVupt, criptografia
autenticada, operação com múltiplas threads e interface gráfica opcional em
Python/Qt. O aplicativo de linha de comando é escrito em C11.

**Versão oficial: [5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).**
A versão **5.2.10 está em validação e não é um download oficial**. Sua entrega
anterior foi retirada. Use a versão oficial nas instalações.

| Versão | Status | Codec VaptVupt integrado |
| --- | --- | --- |
| 5.2.9 | Versão oficial publicada | 2.65.11 |
| 5.2.10 | Fonte em desenvolvimento e validação | 2.65.13 |

Fonte: [histórico de versões](CHANGELOG.md), conferido em 2026-11-12 UTC. A
atualização está descrita no [guia de usuário](docs/GUIA_USUARIO.pt-BR.md) e nos
[avisos do codec](THIRD-PARTY-NOTICES.md).

## Download e instalação

Use a [página oficial da 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9)
para obter os pacotes publicados e suas somas de verificação. Siga o
[guia de instalação](INSTALL.md) da sua plataforma e verifique os arquivos
antes de executá-los. A versão indicada em uma fonte em desenvolvimento não
identifica uma release.

### openSUSE Tumbleweed

O ZUPT está disponível pelo projeto comunitário OBS
[`home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators).
Selecione a distribuição e a arquitetura na
[página do pacote openSUSE](https://software.opensuse.org/package/zupt). Confira
o repositório correspondente e sua chave de assinatura antes de habilitá-lo.
Após configurar esse repositório em um sistema não transacional:

```sh
sudo zypper refresh
sudo zypper install zupt
zupt --version
```

Para atualizar um pacote instalado, use `sudo zypper update zupt` e confira a
transação proposta. Mantenha a verificação de assinaturas habilitada. São
pacotes comunitários; isso não significa inclusão nos repositórios padrão da
distribuição. Consulte as
[instruções do Tumbleweed](docs/GUIA_USUARIO.pt-BR.md#instalação-no-opensuse-tumbleweed)
para detalhes de repositório e atualização.

Agradecemos a Alessandro de Oliveira Faria
([Cabelo](https://build.opensuse.org/users/cabelo)) pela ajuda na manutenção do
pacote comunitário para openSUSE.

### Compilação a partir da fonte

O build padrão precisa de compilador C11, GNU Make e bibliotecas de C,
matemática e threads do sistema. O build não baixa dependências. A suíte de
testes usa Bash e Python 3.

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git checkout v5.2.9
make -j2 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
```

Consulte o [guia de compilação](docs/GUIA_USUARIO.pt-BR.md#compilação-a-partir-do-código-fonte)
para instalação em staging, remoção, integrações opcionais e requisitos de
plataformas.

## Uso básico

Crie, liste, verifique e extraia um arquivo:

```sh
zupt compress backup.zupt documentos/
zupt list backup.zupt
zupt test backup.zupt
mkdir -p restaurado
zupt extract -o restaurado backup.zupt
```

Um arquivo sem criptografia detecta corrupção acidental; ele não oferece
confidencialidade nem autenticação criptográfica. Para criptografar um backup,
informe a senha de forma interativa:

```sh
zupt compress --password-prompt criptografado.zupt documentos/
zupt extract --password-prompt -o restaurado-criptografado criptografado.zupt
```

Mantenha senhas e chaves privadas fora do histórico do shell e dos argumentos
dos processos. O [guia de usuário](docs/GUIA_USUARIO.pt-BR.md#fluxo-da-linha-de-comando)
explica arquivos de senha, descritores herdados, modos pós-quânticos e
verificação da restauração. Use `zupt --help` ou `man zupt` para consultar as
opções. Preserve os dados originais até conferir uma cópia restaurada.

Os bundles de software também usam `.zupt`. Verifique o bundle com `zupt test`
antes de extraí-lo; a extração não restaura permissões de execução. Siga as
[instruções dos bundles](docs/GUIA_USUARIO.pt-BR.md#uso-de-bundles-zupt) antes de
executar um programa extraído.

## Interfaces web e gráfica

Experimente o [ZUPT Web](https://zupt-web.securityops.co) com arquivos de exemplo
não sensíveis e credenciais descartáveis. Os dados enviados são processados no
servidor. O serviço web tem versão, limites e fronteira de confiança próprios.

A interface de desktop opcional executa a CLI local e precisa de Python 3 com
PySide6 ou PyQt6. Consulte o [guia da GUI](gui/README.md) e os
[fluxos documentados](docs/GUIA_USUARIO.pt-BR.md#interface-gráfica).

## Documentação e testes

- [Guia de usuário em pt-BR](docs/GUIA_USUARIO.pt-BR.md) e
  [English user guide](docs/USER_GUIDE.md): instalação, comandos, compatibilidade,
  solução de problemas e instruções completas dos testes.
- [Guia de auditoria](AUDIT.md): checks executados, hipóteses e cobertura pendente.
- [Guia de distribuição](DISTRIBUTION.md): conteúdo dos pacotes e gates de release.
- [Política de segurança](SECURITY.md) e [modelo de ameaças](THREAT_MODEL.md).
- [Changelog](CHANGELOG.md) e [documentação em português](DOCUMENTACAO.pt-BR.md).

Os guias de usuário contêm os comandos dos testes, as ferramentas compatíveis
e os limites da validação, incluindo Frama-C, Jasmin e sanitizadores.

## Fonte, licença e contato

Fontes: [Security Ops](https://git.securityops.co/cristiancmoises/zupt),
[GitHub](https://github.com/cristiancmoises/zupt),
[Codeberg](https://codeberg.org/berkeley/zupt) e
[Security Ops Brasil](https://git.securityops.com.br/cristiancmoises/zupt).
Site do projeto: [zupt.securityops.co](https://zupt.securityops.co).

Copyright © 2025–2026 Cristian Cezar Moisés. O aplicativo e suas ferramentas
usam **AGPL-3.0-or-later**; os arquivos identificados do codec integrado usam
**GPL-3.0-or-later**. Preserve os avisos BSD, CC0 e de domínio público
aplicáveis, os textos das licenças e os cabeçalhos SPDX de cada arquivo.
Consulte [LICENSE](LICENSE), [NOTICE](NOTICE) e os
[avisos de terceiros](THIRD-PARTY-NOTICES.md). As concessões anteriores para
revisões publicadas específicas continuam registradas nesses materiais de
licenciamento. O [licenciamento comercial](LICENSE-COMMERCIAL) é um aviso para
consulta, sem substituir as licenças públicas.

**Contato oficial: [sac@securityops.co](mailto:sac@securityops.co).** Este é o
único e-mail oficial do projeto. `zupt@riseup.net` não tem relação com o ZUPT.
Relate vulnerabilidades pela [política de segurança](SECURITY.md).
