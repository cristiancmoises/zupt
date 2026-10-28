<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Documentação operacional do ZUPT

Este documento reúne instalação, uso seguro, distribuição e validação para a
versão em português do Brasil. Os documentos técnicos em inglês continuam
sendo a referência detalhada: [INSTALL.md](INSTALL.md),
[DISTRIBUTION.md](DISTRIBUTION.md), [SECURITY.md](SECURITY.md) e
[THREAT_MODEL.md](THREAT_MODEL.md).

Para a versão oficial, use a
[release 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9)
e seu `SHA256SUMS`. A 5.2.9 inclui VaptVupt 2.65.11 e mantém o formato 1.6.
Os pacotes antigos preservam seus formatos tar/ZIP/DMG ou nativos; não os
extraia como `.zupt`. A 5.2.10 está em desenvolvimento e sua entrega anterior
foi retirada. Os exemplos dos novos bundles `.zupt` são instruções para a
próxima versão oficial, não downloads disponíveis neste momento.

## 1. Instalação a partir do código-fonte

O perfil padrão não usa bibliotecas opcionais empacotadas no repositório.
Instale um compilador C11, GNU Make, Bash, Python 3, `file`, `tar`, `gzip` e as
ferramentas de desenvolvimento da plataforma.

Se a fonte veio do bundle `.zupt` já verificado, entre no diretório extraído
e aplique `chmod u+x scripts/check-source-only.sh` antes de compilar: o formato
não preserva permissões executáveis. Um checkout Git preserva esses modos.

```sh
make clean
make -j2 CC=gcc V=1 WITH_SDK=0 WITH_PQBOX=0
make CC=gcc V=1 WITH_SDK=0 WITH_PQBOX=0 check
```

Instalação local padrão:

```sh
sudo make install
```

Empacotadores devem usar uma raiz temporária, sem gravar diretamente em
`/usr`:

```sh
destino=$(mktemp -d)
make DESTDIR="$destino" PREFIX=/usr WITH_SDK=0 WITH_PQBOX=0 \
  INSTALL_LEGACY_ALIAS=0 install
find "$destino" -print
```

Para remover uma instalação feita pelo Makefile:

```sh
sudo make uninstall
```

O alias histórico `vaptvupt` é opcional e fica desativado por padrão. Ative
`INSTALL_LEGACY_ALIAS=1` somente após verificar conflitos de pacote e
propriedade dos caminhos.

### Interface gráfica

A GUI executa a CLI como subprocesso; compactação, análise dos arquivos e
criptografia permanecem no programa C. Verifique primeiro a CLI que será usada:

```sh
/caminho/absoluto/para/zupt --version
ZUPT_BIN=/caminho/absoluto/para/zupt python3 gui/src/zupt_gui.py
```

Use Python 3.9 ou mais recente, PySide6 ou PyQt6 e uma sessão gráfica.
Prefira a biblioteca Qt gerenciada pela distribuição. A GUI e a CLI devem ser
da mesma versão; `ZUPT_BIN` seleciona explicitamente o executável.
Os limites de execução, cancelamento e exposição de argumentos estão na
[seção de testes](#6-testes-para-uma-release) e no
[guia detalhado da GUI](gui/README.md).

Para o frontend portátil **planejado**, somente após a publicação oficial e a
verificação da assinatura e dos checksums descrita na
[política de distribuição](#7-política-de-distribuição):

```sh
zupt test zupt-gui-5.2.10-portable.zupt
zupt extract -o gui-verificada zupt-gui-5.2.10-portable.zupt
ZUPT_BIN=/caminho/absoluto/para/zupt \
  bash gui-verificada/zupt-gui-5.2.10-portable/zupt-gui.sh
```

O bundle contém fonte, launchers, ícones e avisos, não Python, Qt ou CLI.
A extração não preserva permissões executáveis; execute o launcher com `bash`
sem alterar permissões recursivamente. No macOS, use `bash zupt-gui.command`;
para abri-lo pelo Finder, aplique `chmod u+x zupt-gui.command` somente nesse
arquivo verificado. Os pacotes 5.2.9 existentes mantêm seus
formatos e ferramentas de extração originais.

## 2. Integrações opcionais

`WITH_SDK=1` habilita `--pq-sdk` e o caminho Argon2id fornecido por uma
instalação de sistema do `libvuptsdk`. `WITH_PQBOX=1` habilita `--pq-box` por
meio de uma instalação de sistema do `libpqvaptvupt`. As opções são
independentes e falham explicitamente se cabeçalhos ou flags de link estiverem
ausentes. A compilação não procura binários opcionais dentro do repositório e
não cria RPATH automático.

O SDK fornece derivação de senha ou encapsulamento para o destinatário. O
payload continua protegido por AES-256-CTR + HMAC-SHA256 no caminho compartilhado
do Zupt; ativar o SDK não muda essa parte do formato.

Os pacotes oficiais previstos para a 5.2.10 mantêm ambas as opções
desativadas. A versão
declarada pela biblioteca não substitui uma verificação dos símbolos da API
easy nem do contrato de memória. Para validar uma compilação opcional, ligue
todos os símbolos exigidos, execute os testes de fronteira e de transparência
do KDF e audite a fonte exata do provedor. O double controlado do libvuptsdk
confirma o despacho, a saída determinística, o piso de custo e as regras de
propriedade do adaptador SDK; ele não comprova Argon2id, a propriedade de uso
intensivo de memória nem a implementação criptográfica externa. O double de
PQBOX cobre somente a análise do envelope de tamanho fixo. O adaptador
libvuptsdk só consome ponteiros e tamanhos retornados quando o provedor informa
sucesso. O PQBOX permanece desativado e não está aprovado para pacotes de
release até que o contrato exato de propriedade e tamanho das saídas de erro
do libpqvaptvupt seja revisado e testado.

## 3. Operação básica

```sh
zupt compress -l 5 backup.zupt pasta/
zupt list backup.zupt
zupt test backup.zupt
zupt extract -o restaurado backup.zupt
```

Use um destino de extração novo ou previamente verificado. Confira o resultado
com comparação de hashes ou arquivos, não apenas pelo código de saída.

Em sistemas POSIX que fornecem `O_SEARCH` ou `O_PATH`, o acesso a arquivos Zupt
adicionados durante a compressão, a arquivos Zupt abertos para leitura, a
criação de arquivos Zupt de saída e a extração aceitam diretórios ancestrais
pesquisáveis, mas não legíveis. Para entradas de compressão, raízes de saída e
raízes de extração, o Zupt prefere um descritor de diretório legível e usa um
descritor somente para busca apenas quando o ancestral permite busca, mas não
leitura. Essas travessias mantêm cada ancestral aberto fixado e verificam,
componente a componente, o tipo de diretório e que links não sejam seguidos.
Arquivos Zupt abertos para leitura usam a travessia POSIX normal e depois
permanecem fixados pelo fluxo aberto. Essa garantia é específica do POSIX;
outras plataformas mantêm suas próprias regras de acesso.

### Senhas e chaves

- Prefira `--password-prompt` para uso interativo.
- Use `--pass-file` apenas com um arquivo privado e controlado pelo usuário.
- Use `--pass-fd` para receber um descritor herdado de um gerenciador de
  segredos.
- Evite `-p SENHA`: argumentos podem aparecer na lista de processos, logs e
  histórico do shell.
- Proteja chaves privadas e mantenha uma cópia recuperável fora do host de
  backup.

Teste a restauração depois de criar o backup e periodicamente durante sua vida
útil. Integridade criptográfica não substitui redundância, retenção nem teste de
recuperação.

## 4. Modos e limites de segurança

O modo de senha usa PBKDF2-SHA256 com 600.000 iterações. `--pq` usa o modo
híbrido nativo ML-KEM-768/X25519, enquanto `--pq-only` usa somente ML-KEM-768
para ambientes que exigem essa postura. Todos os modos criptografados usam
AES-256-CTR com autenticação Encrypt-then-MAC por HMAC-SHA256. Os modos
opcionais do SDK e PQBOX somente existem quando foram compilados contra as
bibliotecas de sistema correspondentes.

O ZUPT aplica contenção de caminho, publicação atômica e verificação de
integridade, mas ainda processa dados potencialmente hostis em código nativo.
Execute arquivos não confiáveis com limites de CPU, memória e armazenamento e,
quando apropriado, dentro de isolamento adicional.

Arquivos anteriores ao trailer de integridade podem exigir
`--allow-legacy-no-ait`. Essa opção é somente para dados antigos cuja origem já
foi verificada. Não a use para ignorar falhas em arquivos novos.

No Windows, o escopo validado cobre caminhos Win32 locais normais. Raízes UNC,
unidades de rede/mapeadas e namespaces de dispositivo ou caminho estendido não
são declarados suportados nesta release. Resultado de compilação cruzada ou
Wine não substitui o teste nativo obrigatório.

## 5. Codec VaptVupt incluído

A fonte 5.2.10 em desenvolvimento inclui VaptVupt 2.65.13; a versão oficial
5.2.9 inclui 2.65.11. O adaptador mantém:

- quadros independentes e janela automática;
- níveis 1–2 em FAST, 3–7 em balanced e 8–9 em extreme;
- filtro BCJ automático somente nos modos balanced/extreme;
- checksum interno desativado porque o ZUPT já registra XXH64 por bloco; nos
  modos criptografados, HMAC-SHA256 também autentica os bytes e metadados;
- descompactação e comparação do bloco recém-criado antes de aceitá-lo.

Uma falha nessa comparação faz o chamador armazenar o bloco sem compressão. A
nova API de contexto FAST sem alocação não é usada pelo aplicativo e não muda o
formato do arquivo ZUPT.

## 6. Testes para uma release

Os wrappers de injeção de falhas dos testes de fuzzing mantêm declarações
explícitas para os símbolos externos usados por `--wrap`. O teste compila as
variantes do codec e do arquivo com `-Wmissing-prototypes`,
`-Wstrict-prototypes` e `-Werror`, mesmo sem flags estritos fornecidos pelo
chamador. Isso valida as declarações do teste, não altera o formato ou a
criptografia e não substitui uma campanha de fuzzing.

Os builds normal, do SDK interno, de sanitizadores e de fuzzing mantêm a exceção de
`-Wcast-align` do Clang limitada a SHA-NI, ANS e SIMD. O build de fuzz identifica
`AFL_CC` separadamente de `CC`; os demais arquivos continuam com os avisos
estritos. O teste existente recompila e executa os dois harnesses reais com
`-Wcast-align -Werror`, além de conferir as regras quando os dois drivers têm
classificações diferentes. A consulta das regras não substitui a execução
instrumentada.

O teste `make test-codec-exact-size` usa o `CC` selecionado e preserva os flags
de compilação e link do chamador. Cada objeto novo e o link mantêm ASan; nesse
conjunto de fontes, a exceção de alinhamento do Clang fica somente em ANS e
SIMD. Erros de compilação e link exibem os diagnósticos completos, e falhas
ou sinais do executável fazem o teste falhar. A regressão de orquestração em
`make check` usa compiladores fictícios para conferir esse contrato; ela não
substitui a execução real com ASan e os round trips BCJ de `make test-all`.
O encoder e o decoder AVX2 passam os endereços em bytes pela interface dos
intrínsecos não alinhados, sem casts para ponteiros de vetor alinhados nem nova supressão de
avisos. A regressão de orquestração confere as nove fontes sem arrays
associativos do Bash; execução real com Bash 3.2 continua sendo um gate nativo.

O watchdog portátil do scanner de código-fonte aguarda o término da sua espera
atual antes de encerrar, sem deixar um processo `sleep` órfão. Isso pode
acrescentar até um intervalo de um segundo à conclusão de cada comando do
arquivo; o status original e o limite de execução são preservados. O teste
executa o scanner real sobre um arquivo seguro e usa um subreaper no Linux para
rejeitar filhos não aguardados. A ausência de Linux, Python 3 ou suporte a
subreaper aparece como `SKIP`, não como validação desse contrato.

O harness do parser (`make test-fuzz-harness` e `make fuzz-format-run`) cria um
diretório privado por execução em `${TMPDIR:-/tmp}`, com permissão 0700, e os
arquivos mutados com criação exclusiva e permissão 0600. Resultados normais
removem o arquivo e o diretório; erro de limpeza faz o teste falhar. No primeiro
sinal, diagnóstico de sanitizador ou erro do supervisor, a mutação para e a
entrada permanece disponível no caminho indicado no log. Escritas incompletas
ou entradas indisponíveis são identificadas separadamente, sem declarar um
reprodutor completo. As regressões conferem permissões, isolamento, bytes
retidos, limpeza e falhas de execução, sem alterar o formato ou a CLI.

Use apenas sementes não sensíveis. Os arquivos retidos podem conter dados da
semente; preserve-os na área privada de evidências antes de encerrar uma VM ou
remover seu diretório temporário. Não publique esses dados automaticamente.
Diagnósticos sintéticos do teste do harness não substituem uma campanha com o
parser real instrumentado.

Antes de criar uma tag, execute em uma árvore limpa e comprometida:

```sh
make WITH_SDK=0 WITH_PQBOX=0 release-check
bash scripts/check-source-only.sh
bash tests/test_source_only.sh
bash tests/test_packaging_syntax.sh
git diff --check
```

O teste instalado exige status 1 e diagnóstico correspondente para comando
inválido, senha incorreta, arquivo truncado e link simbólico no destino.
Verifica a saída combinada de todas as chamadas da CLI e trata sinais, outros
status e diagnósticos de ASan/LSan/UBSan como falhas. Casos negativos e falhas
preservam a saída no log de execução antes da limpeza. `make check` executa
também o harness com a CLI real e injeção de falhas na fronteira do processo.
Os diagnósticos sintéticos validam o supervisor; não comprovam execução dos
sanitizadores. Casos de sinais POSIX são pulados explicitamente no Windows.

Quando a entrega inclui GUI, instale explicitamente PySide6 ou PyQt6 no
ambiente de teste e execute também:

```sh
make WITH_SDK=0 WITH_PQBOX=0 check-gui
```

Esse alvo falha se Qt estiver ausente ou quebrado. Usa arquivos sintéticos e
senhas fictícias temporárias para criar, inspecionar, verificar e extrair
arquivos VaptVupt, testar senha ausente/incorreta/correta, reutilizar widgets
e cancelar trabalhadores antes e durante a execução. Verifica os callbacks
na thread da GUI e exige o término normal dos testes. Não substitui a validação
em uma sessão gráfica e em cada plataforma nativa publicada.

A mesma suíte reexecuta a inicialização real do teste para verificar módulo
sem especificação, loader ausente e macro de versão ausente no cabeçalho.
Exige erros explícitos e rejeição das especificações inválidas antes de criar
o módulo. Esses casos não substituem os fluxos reais da GUI com a CLI.

O trabalhador aplica prazo de execução de 7200 segundos medido por relógio
monotônico antes de criar o filho da CLI, incluindo o tempo de inicialização e
a leitura bloqueada da saída. A thread do watchdog começa antes da criação do
processo e aguarda o retorno ou a exceção da tentativa de inicialização antes de
tratar o prazo excedido. Backups que duram mais de duas horas são encerrados e
reportados como falha. Após EOF, a espera usa somente o tempo restante. A espera
pela inicialização é liberada antes de cancelar o watchdog e aguardar o término
de sua thread, antes da limpeza do filho e da conclusão. Cancelamento, prazo
excedido e erros de leitura tentam encerrar o filho direto, aguardar até cinco
segundos e fechar o pipe. Cada etapa
é tentada mesmo se uma anterior falhar; erro de limpeza torna a operação uma
falha. O diagnóstico informa somente etapa e tipo da exceção, sem argumentos.
A limpeza é uma tentativa: falhas no encerramento ou na espera não garantem a
coleta do filho. O prazo não consegue interromper à força a criação bloqueada do
processo e não cobre descendentes que mantenham o pipe aberto nem operações
ininterruptíveis do sistema operacional.
Os testes cobrem filhos reais silenciosos/com progresso, EOF sem término,
tempo restante de espera, falhas do watchdog, corridas e erros de limpeza.

Depois de criar o filho, o trabalhador valida a existência do pipe de saída e
de um leitor `read1` chamável antes de consumir o progresso. Cada leitura deve
retornar `bytes`, inclusive no EOF (`b''`); outros tipos são rejeitados, não
interpretados como término normal. A ausência ou violação desse contrato
produz erro explícito e mantém a tentativa de coletar o filho, fechar
o pipe disponível e emitir a conclusão uma única vez. As regressões usam
filhos reais com falhas controladas; seus callbacks capturam os valores da
respectiva iteração para evitar dependência de variáveis de loops posteriores.

O log da GUI oculta os valores de `-p` e `--password`, mas a CLI ainda recebe
esses valores nos argumentos do processo. Essa ocultação não protege contra
inspeção local. Fora da GUI, use os mecanismos documentados `--pass-file`,
`--pass-fd` ou `--password-prompt` para evitar essa exposição.

O helper de diagnóstico do SDK interno (`libzuptsdk`) declara seu contrato de argumentos
`printf` para GCC e Clang. A compilação desse arquivo mantém habilitado
`-Wmissing-format-attribute`, além das verificações de formato do compilador,
sem alterar a interface pública nem o texto dos erros.

Também são obrigatórios, conforme disponibilidade:

- compilação e testes completos com GCC e Clang;
- warnings tratados como erro;
- ASan, LSan e UBSan;
- analisador estático do GCC;
- duas gerações byte a byte idênticas do arquivo-fonte;
- instalação, round trip e remoção dos DEB/RPM;
- verificação dos pacotes da GUI em modo off-screen;
- execução nativa do ZIP Windows e do DMG macOS;
- comparação de quadros antigos/novos do codec e arquivos ZUPT normais,
  sólidos e de disco.
- execução do Frama-C (Eva/WP) sobre o código e seus harnesses, sem alarmes
  formais não resolvidos e com provadores disponíveis para os objetivos
  restantes;
- compilação/regeneração com o toolchain Jasmin, além do teste do caminho de
  assembly incluído. `WITH_JASMIN=1` sozinho não comprova a verificação da
  fonte Jasmin.

Registre `PASS`, `FAIL`, `SKIP` ou `BLOCKED` por alvo. Um teste antigo, pulado
ou executado em outra arquitetura não aprova a release atual.

Os testes dos pacotes retirados da 5.2.10 são evidência histórica, não aprovação
do código corrigido. Os testes nativos de Windows/macOS, da GUI e dos pacotes
de distribuição precisam ser repetidos com a fonte e os artefatos finais.
Testes locais de DEB/RPM extraídos não equivalem a instalação Ubuntu/openSUSE.
Falhas, testes não executados e SKIPs não aprovam a nova release.

Os helpers de DEB/RPM da GUI verificam conteúdo e metadados, extraem o pacote
e compilam a fonte Python para verificar a sintaxe. Eles não instalam o pacote
nem executam o Qt. Os jobs nativos de CI fazem a instalação da GUI com a CLI
correspondente, executam os fluxos off-screen e removem os dois pacotes. As
duas etapas precisam passar na distribuição de destino.

## 7. Política de distribuição

Git e o arquivo-fonte devem conter somente código-fonte, documentação, testes,
receitas e dados necessários. Objetos, executáveis, bibliotecas compiladas,
pacotes e artefatos de CI ficam fora do histórico Git.

Os binários pertencem às páginas de release, com procedência da tag de runtime
e do commit efetivo de empacotamento documentadas. Para a futura 5.2.10, estão
previstos cinco bundles `.zupt`
genuínos, sem criptografia, com VaptVupt no nível 9: fonte, CLI Linux x86_64,
CLI Windows x86_64, DMG CLI macOS **arm64, não universal**, e frontend portátil
da GUI. O frontend contém fonte/scripts, não Python, Qt ou CLI empacotados.
DEB/RPM/SRPM da CLI e da GUI mantêm seus formatos nativos. A lista exata está em
[README.pt-BR.md](README.pt-BR.md); o antigo conjunto de 13 arquivos é histórico.

Verifique a chave 6C por um canal independente:
`CF8BA569591B6E7F4D24B0736C95BFAE0646DCCA`. Depois de importar a chave pública
confirmada, valide o inventário e extraia com um desktop Zupt confiável:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
zupt test zupt-5.2.10-source.zupt
zupt extract -o fonte-verificada zupt-5.2.10-source.zupt
```

O formato restaura conteúdo de arquivos regulares, não permissões executáveis.
Antes dos helpers de fonte, entre em
`fonte-verificada/zupt-5.2.10-source` e aplique
`chmod u+x scripts/check-source-only.sh`. Para a CLI Linux verificada:

```sh
zupt test zupt-5.2.10-linux-x86_64.zupt
zupt extract -o linux-verificado zupt-5.2.10-linux-x86_64.zupt
chmod u+x linux-verificado/zupt-5.2.10-linux-x86_64/zupt
linux-verificado/zupt-5.2.10-linux-x86_64/zupt --version
```

No frontend portátil, use `bash zupt-gui.sh` no diretório extraído, com Python,
Qt e uma CLI verificada externos. Não altere permissões recursivamente.

Uma CLI desktop 5.2.9 confiável decodificou os bundles da entrega retirada nos
testes locais. A compatibilidade precisa ser novamente verificada com os
artefatos finais.
Não publique novos `.tar.gz` como downloads manuais. Os arquivos gerados
automaticamente pelo forge e os tarballs internos do SRPM/OBS são entradas de
construção distintas, não esses bundles públicos.

A versão oficial é a 5.2.9. Não use os pins retirados da 5.2.10 como instruções
de instalação da versão final. Antes da publicação, regenere a URL e o checksum
de cada receita a partir da tag final assinada e registre o commit da receita.

O CI anterior à tag não deve tentar baixá-la. Depois de publicar a tag final
assinada e preparar o commit exclusivo dos pins, execute manualmente
`.github/workflows/ci.yml` nesse commit com `verify_recipe_pins=true`. A etapa
pós-tag deve baixar a fonte da tag e confirmar os hashes de AUR, Homebrew e Guix
antes da promoção da release.

`packaging/guix/zupt.scm` seleciona a GUI com a CLI correspondente como
dependência. `guix build -f packaging/guix/zupt.scm` constrói um resultado no
store, mas não o instala no perfil. Verifique a fonte, construa e teste a
receita antes de instalar. Não desative checksums nem presuma instalação
validada de AUR/Homebrew/Nix a partir de testes do Guix.

A receita Guix da CLI executa `make WITH_SDK=0 WITH_PQBOX=0 check` com o
compilador de construção. Python e Git são insumos nativos dos testes, não
dependências de execução da CLI. Conferir essa fase e seus pré-requisitos não
substitui executar a suíte no construtor Guix nem testar a CLI e a GUI instaladas.
A receita também usa o shell da construção nos scripts gerados por quatro
harnesses de teste; o ajuste padrão de shebangs só corrige suas linhas de entrada.

Publique a 5.2.10 somente como release oficial após os gates obrigatórios.
Não publique candidata nem pré-release com problemas conhecidos. Falhas
pendentes ou cobertura crítica ausente bloqueiam a publicação.

AppImage, AppDir, Flatpak, instaladores gráficos nativos e executáveis soltos
continuam fora do conjunto promovido. A presença de um script auxiliar não é
evidência de que o formato foi testado ou liberado.

## 8. Licenças e avisos

O aplicativo, a interface gráfica, as ferramentas criptográficas, a
documentação e a infraestrutura usam AGPL-3.0-or-later. O codec incluído usa
GPL-3.0-or-later. Rotinas derivadas de xxHash mantêm também BSD-2-Clause;
outras origens e licenças estão em
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Distribua os textos `LICENSE*`, `NOTICE` e `THIRD-PARTY-NOTICES.md` junto dos
binários. `LICENSE-COMMERCIAL` apenas informa como consultar termos separados;
ele não concede licença e não altera direitos de terceiros.

## 9. Vulnerabilidades

Siga [SECURITY.md](SECURITY.md) para contato. Inclua versão, sistema,
arquitetura, comando mínimo, impacto e um reproducer sem dados sensíveis. Não
publique detalhes exploráveis antes de uma correção coordenada.
