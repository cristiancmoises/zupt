<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ZUPT 5.2.9

[English](README.md) | Português do Brasil

ZUPT é um arquivador de backup em C11. Ele combina o codec VaptVupt incluído
como código-fonte com criptografia autenticada AES-256-CTR + HMAC-SHA256,
criptografia híbrida ML-KEM-768/X25519, verificação de integridade, execução
multithread e uma interface gráfica opcional em Python/Qt.

## O que muda na versão 5.2.9

- Atualiza o codec incluído de 2.65.3 para 2.65.11.
- Traz validações adicionais de limites no decodificador, rejeição de fluxos
  truncados, correções de capacidade de saída e de XXH64 e reaproveitamento de
  alocações internas.
- Preserva a política do adaptador do ZUPT e sua verificação por
  descompactação e comparação antes de aceitar um bloco comprimido.
- Não altera o formato de arquivo 1.6, o identificador de codec `0x0010`, a
  interface de linha de comando nem a ABI pública do SDK.

O suporte a contexto FAST sem alocação faz parte da biblioteca VaptVupt, mas o
ZUPT continua usando quadros independentes pela API tradicional. O programa não
depende de módulo do kernel.

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

A versão só deve ser publicada depois de todos os testes aplicáveis ao alvo.
O contrato da release 5.2.9 prevê exatamente os 13 arquivos abaixo:

| Arquivo | Alvo e limite da validação |
| --- | --- |
| `zupt-5.2.9.tar.gz` | Código-fonte reproduzível; duas exportações idênticas, auditoria de conteúdo e SHA-256. |
| `zupt-5.2.9.tar.gz.sha256` | Arquivo auxiliar com o SHA-256 do código-fonte reproduzível. |
| `zupt_5.2.9_amd64.deb` | Ubuntu 24.04 amd64; instalação, ciclo funcional e remoção. |
| `zupt-5.2.9-0.x86_64.rpm` | openSUSE Tumbleweed x86_64; inspeção, instalação, ciclo funcional e remoção. |
| `zupt-5.2.9-0.src.rpm` | RPM fonte correspondente exatamente ao RPM binário validado. |
| `zupt-5.2.9-linux-x86_64.tar.xz` | CLI Linux x86_64 e avisos públicos completos; dependências permitidas e teste do pacote extraído. |
| `zupt-gui_5.2.9_all.deb` | GUI Python/Qt independente de arquitetura; dependências, conteúdo e integração GUI/CLI instalada em modo sem tela. |
| `zupt-gui-5.2.9-1.noarch.rpm` | GUI Python/Qt noarch; inspeção e integração GUI/CLI instalada em modo sem tela. |
| `zupt-gui-5.2.9-1.src.rpm` | RPM fonte correspondente exatamente ao RPM noarch da GUI. |
| `zupt-gui-5.2.9-portable.zip` | GUI e inicializadores portáteis somente com código-fonte, sem runtime compilado; licenças, procedência, lista exata de membros e integração GUI/CLI extraída em modo sem tela. |
| `zupt-5.2.9-windows-x86_64.zip` | Executável nativo Windows x86_64 com avisos; ciclo funcional a partir do ZIP extraído. |
| Um entre `ZUPT-5.2.9-macOS-x86_64.dmg` e `ZUPT-5.2.9-macOS-arm64.dmg` | Imagem nativa macOS; ciclo funcional do executável montado, com a arquitetura real do executor no nome. |
| `SHA256SUMS` | Manifesto determinístico dos outros 12 arquivos promovidos. |

Um artefato ausente ou sem seu teste nativo deve ser informado como não
publicado. AppImage, AppDir, Flatpak, instaladores gráficos nativos e executáveis
soltos não fazem parte desse conjunto.

## Código-fonte e procedência do codec

O codec incluído corresponde ao VaptVupt 2.65.11 no commit
`1cc78bce90619dbf97e0ed1ad449c3c4f6329041`, com adaptações do ZUPT preservadas.
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
