<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ZUPT

[English](README.md) | Português do Brasil

A versão oficial publicada é a
[ZUPT 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
A **5.2.10 está em desenvolvimento**, não é um download oficial. Sua tag e
entrega anteriores foram retiradas; a versão corrigida só será publicada após
validação. Versões no código e tags locais não comprovam publicação.

ZUPT é um arquivador de backup em C11. Ele combina o codec VaptVupt incluído
como código-fonte com criptografia autenticada AES-256-CTR + HMAC-SHA256,
criptografia híbrida ML-KEM-768/X25519, verificação de integridade, execução
multithread e uma interface gráfica opcional em Python/Qt.

Disponível para openSUSE: [download e atualização](#pacotes-opensuse).

Experimente o [ZUPT Web online](https://zupt-web.securityops.co) com arquivos
de exemplo sem dados sensíveis e senhas ou chaves descartáveis. Os dados enviados
são processados no servidor. Os recursos, a versão e os limites disponíveis
podem diferir dos da CLI/GUI local.

## Versão oficial 5.2.9

A versão oficial 5.2.9 inclui VaptVupt 2.65.11 e preserva o formato de arquivo
1.6 e o identificador `0x0010`. Baixe seus pacotes pela
[release 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9)
e confira os checksums que a acompanham. Os pacotes existentes não mudaram.

## O que muda na versão 5.2.10 em desenvolvimento

- Atualiza o codec incluído de 2.65.11 para 2.65.13.
- Prepara somente buckets alcançáveis para entradas pequenas em
  BALANCED/EXTREME e no pré-passe do primeiro bloco, dimensiona o histórico
  hash3 pela cadeia real e inicializa explicitamente a raiz da árvore Huffman.
- Preserva a política do adaptador do ZUPT e sua verificação por
  descompactação e comparação antes de aceitar um bloco comprimido.
- Desativa o eco antes de mostrar o prompt POSIX de senha e usa uma espera
  atômica por sinais. Leituras não bloqueantes evitam travamento quando o
  terminal descarta a entrada; ao sair, restaura a configuração do terminal
  e os flags originais do descritor. Os testes cobrem os quatro sinais,
  confirmação, entrada descartada e limites de tamanho de senha.
- Não altera o formato de arquivo 1.6, o identificador de codec `0x0010`, a
  interface de linha de comando nem a ABI pública do SDK.

O suporte a contexto FAST sem alocação faz parte da biblioteca VaptVupt, mas o
ZUPT continua usando quadros independentes pela API tradicional. O programa não
depende de módulo do kernel.

O prompt Windows e a gramática dos arquivos permanecem inalterados.

## Pacotes openSUSE

O ZUPT está disponível para openSUSE pelo projeto comunitário OBS
[`home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators).
Use a [página do pacote openSUSE](https://software.opensuse.org/package/zupt)
para selecionar sua distribuição ou consulte os repositórios de download
verificados para
[Leap 16.0](https://download.opensuse.org/repositories/home:/cabelo:/innovators/16.0/)
e [Tumbleweed](https://download.opensuse.org/repositories/home:/cabelo:/innovators/openSUSE_Tumbleweed/).
Escolha a versão do sistema e a arquitetura corretas; confira o repositório e
sua chave de assinatura antes de habilitá-lo. São pacotes comunitários, não uma
alegação de aceitação no Factory ou inclusão nos repositórios padrão.

Na verificação de 2026-09-30, ambos os repositórios x86_64 oferecem ZUPT
**5.2.9**. Essa versão downstream é diferente do código **5.2.10 em
desenvolvimento**; não presuma que inclui a atualização de codec em andamento.

Depois de habilitar o repositório correspondente em um sistema openSUSE não
transacional:

```sh
sudo zypper refresh
sudo zypper install zupt
```

Para atualizar um pacote já instalado pelos repositórios configurados:

```sh
sudo zypper refresh
sudo zypper update zupt
zupt --version
```

Revise a transação proposta; não desative verificações de assinatura nem force
a troca de fornecedor. Esses comandos não fazem uma atualização de distribuição
do Tumbleweed. Consulte o
[guia do Zypper](https://doc.opensuse.org/documentation/tumbleweed/zypper/)
para gerenciar repositórios e atualizações do sistema.

Agradecemos a Alessandro de Oliveira Faria
([Cabelo](https://build.opensuse.org/users/cabelo)) pela ajuda na manutenção do
pacote comunitário openSUSE. Essa colaboração downstream não implica autoria do
código-fonte upstream.

## Compilação rápida

Requisitos do perfil padrão: compilador C11, GNU Make, biblioteca C, `libm` e
threads do sistema. O processo de compilação não baixa dependências.

```sh
make clean
make -j2 WITH_SDK=0 WITH_PQBOX=0 V=1
make WITH_SDK=0 WITH_PQBOX=0 check
```

Para executar também os testes estendidos:

```sh
make WITH_SDK=0 WITH_PQBOX=0 test-all
```

## Uso básico

```sh
# Criar um arquivo
zupt compress backup.zupt documentos/

# Listar e testar sem extrair
zupt list backup.zupt
zupt test backup.zupt

# Extrair para um diretório novo
zupt extract -o restaurado backup.zupt
```

Consulte `zupt --help` e a página de manual `zupt(1)` para todas as opções.
Para senhas, prefira o prompt interativo, `--pass-file` com arquivo de modo
privado ou `--pass-fd`. Colocar a senha diretamente nos argumentos pode expô-la
na lista de processos e no histórico do shell.

## Integridade, compatibilidade e segurança

- Nos modos criptografados, HMAC-SHA256 autentica metadados e blocos. Arquivos
  sem criptografia usam apenas verificações XXH64 não criptográficas.
- A leitura exige o trailer de integridade por padrão.
- O ZUPT rejeita componentes de caminho perigosos e evita seguir links durante
  a publicação e a extração.
- `--allow-legacy-no-ait` deve ser usado somente para um arquivo antigo,
  conhecido e confiável. Ele reduz a garantia de integridade.
- XXH64 detecta corrupção acidental; não substitui autenticação criptográfica.
- Cópias de segurança continuam exigindo testes periódicos de restauração e
  uma estratégia externa de redundância.

O modelo de ameaças completo permanece em [THREAT_MODEL.md](THREAT_MODEL.md) e
a política de segurança em [SECURITY.md](SECURITY.md). A orientação operacional
em português está em [DOCUMENTACAO.pt-BR.md](DOCUMENTACAO.pt-BR.md).

## Artefatos planejados da 5.2.10 (não publicados)

Os nomes e verificações abaixo descrevem a release planejada, não downloads
disponíveis. Os cinco bundles deverão ser arquivos `.zupt` genuínos, sem
criptografia, comprimidos com VaptVupt no nível 9, testados com `zupt test` e
comparação integral após a extração. DEB/RPM/SRPM mantêm seus formatos nativos.
Registre a tag do runtime e o commit usado na compilação separadamente.

| Arquivo | Validação exigida antes da publicação |
| --- | --- |
| `zupt-5.2.10-source.zupt` | Árvore de fonte comparada integralmente aos blobs Git da tag oficial validada. |
| `zupt-5.2.10-linux-x86_64.zupt` | CLI Linux x86_64 e avisos completos; teste funcional da extração. |
| `zupt-5.2.10-windows-x86_64.zupt` | CLI nativa Windows x86_64, cinco avisos de runtime e round trips Unicode/PATH restrito. |
| `zupt-5.2.10-macos-arm64.zupt` | DMG da CLI nativa arm64 dentro do bundle; verificação e teste do binário montado no macOS. Não é universal. |
| `zupt-gui-5.2.10-portable.zupt` | Fonte da interface, scripts e avisos; requer Python, Qt e CLI compatível externos. |
| `zupt_5.2.10_amd64.deb` | Compilação DEB real, dependências e conteúdo; teste da CLI extraída ou instalada. |
| `zupt-5.2.10-0.x86_64.rpm` e `zupt-5.2.10-0.src.rpm` | Compilação RPM/SRPM real, procedência, conteúdo e teste funcional. |
| `zupt-gui_5.2.10_all.deb`, `zupt-gui-5.2.10-1.noarch.rpm`, `zupt-gui-5.2.10-1.src.rpm` | Metadados, dependências, avisos e integração GUI/CLI off-screen. |
| `SHA256SUMS`, `SHA256SUMS.asc`, `release-key.asc` | Hashes exatos, assinatura destacada verificada e chave pública. |

As verificações históricas da entrega retirada têm escopos distintos. Elas não
validam uma futura release 5.2.10 corrigida:

- O run nativo Windows/macOS [36858438699](https://github.com/cristiancmoises/zupt/actions/runs/36858438699)
  passou no commit de testes/empacotamento P `4a66b0cab55900bc64699428fb41c48c07de126a`.
  `src`, `include`, `jasmin`, `sdk/src` e `Makefile` são iguais à tag C
  `24995eb7652a31eedc46386bab14c63cbb31e050`; não é CI da tag C exata.
- O job GUI DEB da tag C no run [36849573076](https://github.com/cristiancmoises/zupt/actions/runs/36849573076)
  passou. RPM/SRPM da GUI e o frontend portátil com fonte C também passaram;
  isso não transforma o workflow C, que falhou, em PASS global.
- A CLI C e a GUI com graft estão instaladas na geração 85 do perfil Guix
  local; versão, operação/PTY da CLI e GUI off-screen com seis abas passaram.
  A geração 84 foi preservada e as 39 entradas não relacionadas não mudaram.
- A CLI local static-musl e testes dos DEB/RPM extraídos passaram, mas não
  equivalem a instalação nativa Ubuntu/openSUSE. A falha GCC estrita permanece.

Só está publicado o arquivo presente no inventário assinado com hash correto.
Confirme por um canal independente a impressão digital da chave 6C registrada:
`CF8BA569591B6E7F4D24B0736C95BFAE0646DCCA`. Verifique com
`gpg --verify SHA256SUMS.asc SHA256SUMS` e `sha256sum --check SHA256SUMS`.
Veja [INSTALL.md](INSTALL.md) e [DOCUMENTACAO.pt-BR.md](DOCUMENTACAO.pt-BR.md).
AppImage, AppDir, Flatpak, instaladores GUI nativos e outras arquiteturas ficam
excluídos. Releases anteriores preservam seus formatos e arquivos.

A extração `.zupt` restaura conteúdo, não permissões de execução. Depois de
verificar o bundle Linux, use `chmod u+x` somente no arquivo `zupt`; invoque o
launcher portátil com `bash zupt-gui.sh`. Os helpers de fonte também exigem
permissões pontuais, conforme [INSTALL.md](INSTALL.md).

O fluxo antigo de promoção de 13 arquivos fica desativado para v5.2.10 ou
posterior. Tarballs RPM/OBS e arquivos CI são entradas internas de construção;
não são os novos downloads públicos. Nunca descreva um pacote sem assinatura
como assinado.

## Código-fonte e procedência do codec

A tag e a release anteriores `v5.2.10` foram retiradas. Não use pins antigos
das receitas AUR, Homebrew ou Guix como fonte oficial de instalação. As receitas
e seus hashes precisam ser finalizados contra a fonte oficial validada antes da
publicação. Testes históricos de pacotes ou do perfil não validam essa futura
release.

O codec incluído integra o VaptVupt 2.65.13 no commit
`e30dc9329be7cf9f233b1ac0b1fc9ed31f530391`, com adaptações do ZUPT preservadas.
Não é uma cópia byte a byte da árvore canônica: mantém os limites do parser,
o fallback de limpeza segura Darwin/NetBSD e a política do adaptador.
Os arquivos do aplicativo usam AGPL-3.0-or-later; os arquivos do codec usam
GPL-3.0-or-later. As rotinas derivadas de xxHash também preservam BSD-2-Clause.
Veja [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) e os arquivos `LICENSE*`.

Repositório canônico: <https://github.com/cristiancmoises/zupt>.

Espelhos:

- <https://codeberg.org/berkeley/zupt>
- <https://git.securityops.co/cristiancmoises/zupt>
- <https://git.securityops.com.br/cristiancmoises/zupt>

## Relato de vulnerabilidade

Não publique detalhes exploráveis antes da coordenação. Siga o contato e o
processo descritos em [SECURITY.md](SECURITY.md).
