<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ZUPT 5.2.10

[English](README.md) | Português do Brasil

Este README descreve o código-fonte 5.2.10. Os downloads publicados e seu estado
de validação estão na [página de releases](https://github.com/cristiancmoises/zupt/releases/latest);
a versão do código ou uma tag Git, isoladamente, não significa que os pacotes
já foram publicados.

ZUPT é um arquivador de backup em C11. Ele combina o codec VaptVupt incluído
como código-fonte com criptografia autenticada AES-256-CTR + HMAC-SHA256,
criptografia híbrida ML-KEM-768/X25519, verificação de integridade, execução
multithread e uma interface gráfica opcional em Python/Qt.

Disponível para openSUSE: [download e atualização](#pacotes-opensuse).

## O que muda na versão 5.2.10

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
**5.2.9**. Essa versão downstream é diferente da **5.2.10** deste repositório;
não presuma que inclui a atualização de codec desta versão.

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

## Pacotes e artefatos de release

Publique somente arquivos compilados e validados a partir da tag exata.
Novos arquivos de fonte e Linux usam `.zupt` sem criptografia, com
`zupt test`, extração e comparação integral antes da publicação.

| Arquivo | Validação exigida antes da publicação |
| --- | --- |
| `zupt-5.2.10-src.zupt` | Árvore de fonte sem credenciais ou prompts; extração igual à tag. |
| `zupt-5.2.10-linux-x86_64.zupt` | CLI Linux x86_64 e avisos completos; teste funcional da extração. |
| `zupt_5.2.10_amd64.deb` | Compilação DEB real, dependências e conteúdo; teste da CLI extraída ou instalada. |
| `zupt-5.2.10-0.x86_64.rpm` e `zupt-5.2.10-0.src.rpm` | Compilação RPM/SRPM real, procedência, conteúdo e teste funcional. |
| `SHA256SUMS`, `SHA256SUMS.asc`, `release-key.asc` | Hashes exatos, assinatura destacada verificada e chave pública. |

Um pacote sem sua compilação ou seu teste exigido não é publicado. Testes
locais do pacote extraído não equivalem a instalação em Ubuntu/openSUSE.
Windows, macOS, instaladores GUI e outras arquiteturas precisam de builds
nativos novos e não são prometidos nesta versão. Releases anteriores
preservam seus formatos e arquivos.

O fluxo antigo de promoção de 13 arquivos fica desativado para v5.2.10 ou
posterior. Tarballs RPM/OBS e arquivos CI são entradas internas de construção;
não são os novos downloads públicos. Nunca descreva um pacote sem assinatura
como assinado.

## Código-fonte e procedência do codec

A tag imutável `v5.2.10` mantém as receitas históricas AUR, Homebrew e Guix
da versão 5.2.9. Uma atualização de empacotamento separada fixa essas receitas
no arquivo de fonte verificado, gerado pelo forge para a tag exata 5.2.10,
sem alterar a tag ou publicar um novo tarball. A verificação dos pins não
representa teste nativo de instalação AUR, Homebrew ou Guix.

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
