# Guia de usuário do ZUPT

Este guia descreve os fluxos suportados da linha de comando e da interface
gráfica do ZUPT. Os exemplos usam diretórios descartáveis, deixam a etapa de
verificação explícita e mantêm senhas fora dos argumentos dos processos.

Entre em contato com o projeto somente por
[sac@securityops.co](mailto:sac@securityops.co). Para relatar vulnerabilidades,
siga a [política de segurança](../SECURITY.md).

Leia este guia em [inglês](USER_GUIDE.md).

## Conteúdo

- [Status da versão](#status-da-versão)
- [Instalar ou atualizar no openSUSE Tumbleweed](#instalação-no-opensuse-tumbleweed)
- [Compilar, instalar ou desinstalar a partir do código-fonte](#compilação-a-partir-do-código-fonte)
- [Criar, verificar e restaurar arquivos](#fluxo-da-linha-de-comando)
- [Recuperar arquivos legados confiáveis](#arquivos-legados-confiáveis-sem-ait)
- [Extrair bundles de software](#uso-de-bundles-zupt)
- [Usar a interface gráfica](#interface-gráfica)
- [Executar validações e relatar resultados](#validação-e-relatórios)
- [Reproduzir os testes de auditoria](#reproduzir-os-testes-de-auditoria)
- [Resolver problemas comuns](#solução-de-problemas)

Para consultar a estrutura dos pacotes e os requisitos de publicação, leia o
[guia de distribuição em inglês](../DISTRIBUTION.md). O [guia de auditoria](../AUDIT.md)
registra achados, hipóteses de análise e cobertura pendente.

## Status da versão

Este guia descreve o ZUPT 5.2.10 e o formato de arquivos desktop 1.6. A
[página de releases](https://github.com/cristiancmoises/zupt/releases) reúne tags
assinadas, pacotes, notas e checksums. Escolha a release e o asset da sua
plataforma e siga as [instruções de verificação](../INSTALL.md#5210-bundle-formats-and-verification).

O ZUPT Web está disponível em <https://zupt-web.securityops.co> para exemplos
descartáveis e sem dados sensíveis. É uma implantação separada, com versão,
limites e fronteira de confiança próprios.

## Instalação no openSUSE Tumbleweed

O ZUPT está disponível pelo projeto comunitário OBS
[`home:cabelo:innovators`](https://build.opensuse.org/project/show/home:cabelo:innovators).
Use a [página do pacote openSUSE](https://software.opensuse.org/package/zupt)
para selecionar a distribuição e a arquitetura corretas. No Tumbleweed,
revise o repositório e a chave de assinatura antes de habilitá-lo:

```sh
sudo zypper refresh
sudo zypper install zupt
zupt --version
```

Para atualizar um pacote já instalado:

```sh
sudo zypper refresh
sudo zypper update zupt
zupt --version
```

Revise a transação e mantenha as verificações de assinatura ativas. Esses
comandos atualizam o ZUPT; não fazem uma atualização de distribuição do
Tumbleweed. O pacote é mantido downstream pela comunidade openSUSE; agradeço
ao [Cabelo](https://build.opensuse.org/users/cabelo) por essa manutenção.

## Compilação a partir do código-fonte

O perfil padrão requer compilador C11, GNU Make, bibliotecas C e matemática e
threads POSIX. A compilação não baixa dependências.
Escolha uma tag assinada na [página de releases](https://github.com/cristiancmoises/zupt/releases).
Substitua `PUBLISHED_TAG` pela tag exata e verifique a assinatura com a chave
confirmada por uma fonte independente, conforme [INSTALL.md](../INSTALL.md):

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git fetch origin tag PUBLISHED_TAG
git verify-tag PUBLISHED_TAG
git switch --detach PUBLISHED_TAG
git rev-parse HEAD
```

Compile a revisão selecionada:

```sh
make clean
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
```

O build padrão contém somente fontes e usa a implementação C portátil. As
integrações opcionais SDK e PQBOX devem ser fornecidas pelo sistema; o Makefile
nunca baixa nem carrega uma biblioteca do repositório.

Para instalar em um diretório de staging:

```sh
stage=$(mktemp -d)
make install DESTDIR="$stage" PREFIX=/usr INSTALL_LEGACY_ALIAS=0
find "$stage" -type f -o -type l | sort
```

O prefixo padrão de instalação é `/usr/local`. Para instalação local, use
`sudo make install PREFIX=/usr/local INSTALL_LEGACY_ALIAS=0`. Na remoção,
mantenha as mesmas variáveis de caminhos:

```sh
sudo make uninstall PREFIX=/usr/local INSTALL_LEGACY_ALIAS=0
```

Empacotadores podem definir `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS`,
`AR`, `RANLIB`, `STRIP`, `DESTDIR`, `PREFIX`, `BINDIR`, `LIBDIR`, `INCLUDEDIR`
e `MANDIR`. `INSTALL_LEGACY_ALIAS=1` acrescenta o comando de compatibilidade
`vaptvupt` e sua página de manual; o padrão é 0. Os pacotes devem manter 0
até verificar propriedade e conflitos desse nome.

## Fluxo da linha de comando

Crie, inspecione, verifique e restaure um arquivo em um diretório novo:

```sh
mkdir -p demo/input demo/restored
printf '%s\n' 'dados de exemplo' > demo/input/leia.txt
zupt compress demo/backup.zupt demo/input
zupt list demo/backup.zupt
zupt test demo/backup.zupt
zupt extract -o demo/restored demo/backup.zupt
cmp demo/input/leia.txt demo/restored/demo/input/leia.txt
```

A extração preserva o caminho arquivado `demo/input` dentro do diretório de destino.
Para usar uma única thread na extração, acrescente `-t 1` a `zupt extract`. Execute `zupt test` sem essa opção.

Use `zupt --help` e `man zupt` para consultar todas as opções. Mantenha
senhas fora do histórico e da lista de processos:

```sh
zupt compress --password-prompt demo/criptografado.zupt demo/input
umask 077
printf '%s\n' 'senha-de-exemplo' > demo/password.txt
zupt compress --pass-file demo/password.txt demo/criptografado.zupt demo/input
rm -f demo/password.txt
```

Prefira o terminal interativo ou um arquivo de modo 0600. Nunca coloque
segredos reais em exemplos, logs de CI ou uploads web.

Arquivos criptografados autenticam metadados e blocos com HMAC-SHA256. O modo
`--pq` combina ML-KEM-768 e X25519; `--pq-only` usa somente ML-KEM-768.
Arquivos sem criptografia oferecem detecção de corrupção, não sigilo nem
autenticação.

## Arquivos legados confiáveis sem AIT

`extract`, `list`, `test` e `disk restore` exigem um trailer de integridade
válido por padrão, sem confiar nos flags do cabeçalho para decidir se é
necessário autenticar. Isso impede remover o trailer e limpar um flag de
criptografia não autenticado para reduzir silenciosamente os checks dos
metadados. `--allow-legacy-no-ait` é aceito somente nesses quatro comandos,
apenas para recuperar um arquivo antigo, conhecido e confiável, criado antes
da introdução do AIT. Não use a opção com entrada não confiável ou gravável
por um atacante. Verifique os dados recuperados e migre-os para um arquivo
criado com uma versão oficial atual. Compressão e backup de disco nunca
criam um arquivo sem AIT.

`info` mostra metadados de framing não autenticados, sem validar AIT nem
conteúdo. Seu status de sucesso não é um resultado de integridade.

Essa exceção é separada da compatibilidade do índice de disco da v5.2.1.
Arquivos de disco publicados dessa versão normalmente têm AIT. O escopo
restrito testado inclui o fixture de 718 bytes, criptografado por senha e
deduplicado, com sequência DATA/DATA/REF/DATA. Ele está registrado como texto
hexadecimal auditável, com procedência e SHA-256, e usa índice legado de
largura fixa e AAD linear. O leitor lista, testa, extrai e restaura seus bytes
exatamente. O gate Linux completo histórico passou em `ff99770`. Isso não
cobre todas as combinações históricas nem estabelece que um leitor antigo
suporte novas codificações controladas por flags.

## Uso de bundles `.zupt`

Os bundles de release usam o contêiner próprio `.zupt`. Eles não são tarballs
e devem ser verificados antes da extração:

```sh
zupt test zupt-5.2.10-linux-x86_64.zupt
mkdir -p linux-check
zupt extract -o linux-check zupt-5.2.10-linux-x86_64.zupt
chmod u+x linux-check/zupt-5.2.10-linux-x86_64/zupt
linux-check/zupt-5.2.10-linux-x86_64/zupt --version
```

A extração restaura conteúdos, não modos executáveis. Aplique `chmod u+x`
somente a executáveis já verificados. Para um bundle de fonte, inspecione a
árvore antes de compilar:

```sh
zupt test zupt-5.2.10-source.zupt
zupt extract -o source-check zupt-5.2.10-source.zupt
find source-check -maxdepth 2 -type f -print | sort
```

Antes de compilar e executar os testes dessa fonte extraída, entre na árvore
verificada e restaure somente as permissões exigidas pelo checker e pelos três
wrappers que executam a si mesmos por links simbólicos temporários:

```sh
cd source-check/zupt-5.2.10-source
chmod u+x scripts/check-source-only.sh \
  tests/test_frama_aes_nist_wrapper.sh \
  tests/test_frama_ans_decode_bounds_wrapper.sh \
  tests/test_jasmin_source_wrapper.sh
```

Depois siga as [instruções de compilação](#compilação-a-partir-do-código-fonte).
Não torne toda a árvore extraída executável. Um checkout Git preserva os modos
executáveis registrados.

Não renomeie um tar arbitrário para `.zupt` e não trate um protótipo local como
release oficial. Checksums e assinaturas pertencem ao artefato publicado exato.

Para conferir um bundle local de fonte, prepare primeiro um diretório revisado
`staged-source` contendo somente os arquivos regulares pretendidos. Mantenha
metadados Git, credenciais, saídas de build e o arquivo de saída fora desse
diretório. Use um novo destino de extração:

```sh
zupt compress --vv -l 9 -t 1 source-validation.zupt staged-source
zupt info source-validation.zupt
zupt test source-validation.zupt
zupt extract -t 1 -o source-restored source-validation.zupt
diff -r staged-source source-restored/staged-source
```

Confirme que `info` informa `Encrypted: no`; `test` não aceita `-t`.
A comparação verifica conteúdos, não permissões executáveis. Restaure somente
modos conhecidos e verificados da fonte antes de executar helpers de build.
## Interface gráfica

A GUI é uma interface Python/Qt para o executável local `zupt`. Instale a CLI
primeiro e depois PyQt6 ou PySide6 pelo sistema operacional. No checkout:

```sh
export ZUPT_BIN="$(command -v zupt)"
python3 gui/src/zupt_gui.py
```

A GUI não ignora as verificações da CLI. Use um diretório novo para cada
restauração, revise o arquivo e o destino e confirme o resultado com `zupt test`
ou comparação byte a byte.

Os logs das operações mostram a saída da CLI e os nomes de arquivos como
texto simples. Tags como `<b>` e entidades como `&amp;` permanecem literais;
não devem alterar a aparência ou o significado de um diagnóstico. Novas
entradas não devem interromper a seleção ou a leitura de mensagens anteriores.

Caracteres UTF-8 podem atravessar leituras do pipe da CLI. O worker mantém o
estado de decodificação dentro de cada operação e o finaliza no EOF normal.
Sequências inválidas ou incompletas usam caracteres de substituição sem
reprovar o trabalho; isso altera somente a exibição, não nomes ou bytes
armazenados no arquivo.

Para testar o checkout atual em vez de uma CLI antiga instalada, compile-o e
execute a suíte real de fluxos da GUI com o interpretador selecionado:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0
env ZUPT_BIN="$PWD/zupt" QT_QPA_PLATFORM=offscreen make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check-gui
```

Para o instalador da GUI a partir das fontes, prepare um staging temporário
em vez de alterar o host. No Bash, use `stage=$(mktemp -d)`; no fish, use
`set -l stage (mktemp -d)`. Depois execute:

```sh
bash gui/install.sh --destdir "$stage" --prefix /usr
cmp docs/USER_GUIDE.md "$stage/usr/share/doc/zupt-gui/docs/USER_GUIDE.md"
cmp docs/GUIA_USUARIO.pt-BR.md "$stage/usr/share/doc/zupt-gui/docs/GUIA_USUARIO.pt-BR.md"
bash tests/test_packaging_syntax.sh
```

O instalador inclui os dois guias e as páginas SECURITY, DISTRIBUTION, AUDIT,
INSTALL e THREAT_MODEL referenciadas por eles. A regressão exige bytes
instalados, modo 0644, diretório de dados personalizado e rejeição de guias
ausentes antes de criar a saída da instalação. O build DEB da GUI usa esse
instalador, mas esses checks de staging não compilam nem validam o DEB. Outros
helpers nativos têm gates separados de conteúdo e execução. Referências a
headers e scripts de teste precisam do checkout.

Os bundles Windows e os dois locais de documentação do DMG macOS incluem os
dois guias e SECURITY, DISTRIBUTION, AUDIT, INSTALL e THREAT_MODEL. Depois de
extrair o bundle Windows ou montar o DMG somente de leitura, compare essa
árvore privada e sem alterações concorrentes com o checkout exato de suas fontes:

```sh
make -j1 test-installed-docs
python3 -B scripts/check-installed-docs.py . /path/to/windows-extraction windows
python3 -B scripts/check-installed-docs.py . /path/to/read-only-dmg macos
```

O checker apenas lê arquivos; não extrai nem monta pacotes. Ele confere a versão
do diretório Windows e as duas versões do `Info.plist` macOS com o header das
fontes. Documentos POSIX precisam do modo 0644. Arquivos nativos do Windows NT
normalmente informam 0666; esse perfil não comprova a correção das ACLs. A suíte
Linux anterior de `7fe4eb5` coleta 30 casos: 29 passam e um caso de junction
nativa do NT é pulado. A suíte ampliada da árvore de trabalho define 32 casos,
incluindo duas regressões de staging do instalador da GUI. Antes desta
atualização da documentação, sua execução Linux local passa em 31 casos e pula o
caso de junction nativa do NT. Os seis controles anteriores das receitas
Windows/macOS passam sem executar a CLI de exemplo. Execute o CI nativo
Windows/macOS dos pacotes para cada revisão alterada; os pacotes anteriores de
`b25a486` não cobrem essas mudanças.

O CI nativo Windows de `3e50a65` registra 12 subfalhas do fixture de permissões:
o checker aceita arquivos após o fixture solicitar o modo 0600, embora o
perfil exija 0644. Isso sugere uma diferença na capacidade de alterar permissões;
o log bruto não informa o modo observado. Os controles somente de leitura com
0444 são rejeitados como esperado. A execução falha não qualifica os pacotes
nem estabelece falha do codec ou da criptografia; repita os checks nativos
após corrigir o fixture. A correção local testa a rejeição de arquivos somente
de leitura separadamente. O teste de permissões exclusivas ao proprietário é
pulado explicitamente se o sistema não materializar 0600; os critérios do
checker continuam iguais.

A interface portátil tem um alvo separado de regressão do empacotamento;
ele usa arquivos `.zupt` reais e não precisa de Qt:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-portable-gui
```

Para ensaiar o pacote local, use um diretório de saída novo. No Bash, execute
`release_dir=$(mktemp -d)`; no fish, use `set -l release_dir (mktemp -d)`.
Em seguida, execute esta linha inteira em qualquer um dos dois shells:

```sh
env ZUPT_BIN="$PWD/zupt" DIST_DIR="$release_dir" bash packaging/build-portable-gui.sh
```

O helper confere a CLI correspondente, solicita VaptVupt nível 9 sem
criptografia, testa o contêiner e verifica o inventário exato de 20 arquivos. Os
dois guias ficam sob `docs/`; SECURITY, DISTRIBUTION, AUDIT, INSTALL e
THREAT_MODEL ficam na raiz do pacote. Ele examina as duas árvores de fontes e
compara todos os bytes extraídos. Ele grava o `.zupt`, seu arquivo SHA-256 e um
diretório `.extracted`. Recusa destinos já existentes. Uma falha na publicação
local pode deixar saídas parciais verificadas para inspeção; o helper não apaga
caminhos finais que outro processo possa ter substituído. Esse ensaio não é uma
release assinada nem aprovação de pacote nativo. Python, Qt e a CLI testada
separadamente continuam sendo dependências externas. Execute o launcher extraído
por `bash`, sem presumir que a extração restaurou permissões executáveis. Links
para headers e scripts de teste ainda exigem o checkout; esse pacote não é uma
cópia offline completa da documentação do repositório.

Os testes do pacote portátil verificam conteúdo, checksums, bytes extraídos e
tratamento de falhas. Usam operações reais da CLI, mas não executam o Qt:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-portable-gui
make audit-licenses
```

Execute `check-gui` separadamente com uma biblioteca Qt compatível e valide os
pacotes instalados em sua plataforma de destino.

<!-- Stable fragment links from earlier editions. -->
<a id="manuseio-de-arquivos-nos-fixtures-de-teste"></a>
<a id="supervisão-portátil-dos-checks-e-cobertura-de-ferramentas"></a>
<a id="reprodução-dos-checks-do-analisador-estático"></a>
<a id="evidência-formal-atual-conferida-em-2026-11-12"></a>
<a id="checks-locais-anteriores-ao-commit-2026-10-28"></a>
<a id="limites-ans-com-saída-de-tamanho-exato"></a>
<a id="validação-anterior-com-gcc-e-gui-2026-10-23"></a>
<a id="repetição-formal-mantida-anterior-2026-10-21"></a>
<a id="validação-das-frequências-ans"></a>
<a id="prova-limitada-do-logaritmo-ans"></a>
<a id="limites-das-entradas-da-tabela-ans"></a>
<a id="regressão-do-gate-de-credenciais-do-ci"></a>
<a id="verificação-da-documentação-dos-pacotes-nativos"></a>
<a id="metadados-do-spec-rpm"></a>
<a id="regressões-de-falhas-nas-ferramentas-de-empacotamento"></a>
<a id="testes-da-abi-de-capacidade-de-disco-no-linux"></a>
<a id="testes-de-capacidade-para-saída-de-arquivos"></a>
<a id="testes-do-fixture-de-disco-legado"></a>
<a id="supervisão-do-teste-de-folga-do-decoder"></a>
<a id="supervisão-da-verificação-de-símbolos-sdk"></a>
<a id="supervisão-dos-testes-de-tamanho-exato-e-bcj"></a>
<a id="falhas-de-alocação-nos-workers-e-preservação-do-arquivo"></a>
<a id="controles-do-gate-de-análise-estática"></a>
<a id="testes-de-callbacks-do-sdk"></a>
<a id="testes-de-leitura-de-chaves-nativas"></a>
<a id="controles-de-senha-e-integridade-da-suíte-multithread"></a>
<a id="verificações-do-executável-instalado"></a>
<a id="verificações-da-gui-durante-o-build-guix"></a>
<a id="fallback-pyqt6-e-ciclo-de-vida-dos-objetos-nativos"></a>
<a id="falhas-nas-consultas-da-gui"></a>
<a id="build-dos-harnesses-de-fuzzing-e-validação-da-semente"></a>
<a id="verificações-do-codec-e-da-criptografia"></a>
<a id="limites-diretos-da-recarga"></a>
<a id="consumo-do-leitor-ans-e-check-wp-condicional"></a>
<a id="reproduzir-os-testes-focados-ans-com-sanitizadores"></a>
<a id="limites-do-logaritmo-ans"></a>
<a id="aes-vetores-conhecidos-e-gate-eva"></a>
<a id="reproduzir-os-smoke-tests-da-cli-com-sanitizadores"></a>
<a id="perfis-opcionais-de-integração-e-assembly"></a>
<a id="runtime-com-jasmin-e-suíte-da-fonte-atual"></a>
<a id="análise-wp-focada-no-escalonamento-de-chaves-aes"></a>
<a id="checks-wp-dos-laços-de-bloco-aes-portátil"></a>
<a id="falha-anterior-de-recursos-na-cobertura-contínua"></a>


## Validação e relatórios

Consulte [AUDIT.md](../AUDIT.md) para a matriz de testes mantida, os requisitos,
as evidências registradas e os limites de garantia. Execute os testes na revisão
exata em análise e registre comandos, versões das ferramentas, status de saída
e diagnósticos. Um `SKIP` opcional ou de plataforma indica cobertura não testada.

### Reproduzir os testes de auditoria

Verifique fontes e licenças antes de compilar; depois execute a suíte normal:

```sh
bash scripts/check-source-only.sh --tree .
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-asan-run
```

Em um checkout Git, execute também `make source-audit` para verificar o índice
e o arquivo da revisão. Fontes extraídas usam o modo independente `--tree .`
mostrado acima.

`test-asan-run` executa o smoke test com sanitizadores; `test-asan` apenas o
compila. Use uma cópia limpa para cada compilador ou configuração de
sanitizadores. O scanner de fontes rejeita binários gerados: repita a análise
em outra cópia limpa, sem tratar os resultados do build como código-fonte.

O [perfil de medição de tempo](../AUDIT.md#timing-measurement-profile)
atualizado coleta 400.000 observações por classe para todos os comparadores,
em cinco rodadas, mantendo os critérios de aceitação. O bundle imutável
`v5.2.10` mantém o teste original de 200.000 observações; use um checkout com
o teste ampliado para reproduzir o novo perfil. Um resultado inconclusivo
continua sendo falha do gate, e a medição não prova tempo constante.

A validação de release também exige seis análises Frama-C mantidas e a
verificação das cinco fontes Jasmin. Seus [modelos e requisitos](../AUDIT.md#formal-verification)
têm escopo menor que uma prova do programa inteiro. Os alvos `check` e
`test-all` não substituem essas análises nem a validação dos pacotes nativos.

### Verificações opcionais do varint Rust

A crate experimental `rust/varint` implementa separadamente os inteiros
canônicos sem sinal em base 128, com `no_std`. Ela não é ligada à CLI C11 de
produção nem verifica arquivos completos. Com Rust/Cargo 1.93 ou posterior,
rustfmt, Clippy e o toolchain C necessário instalados, execute:

```sh
make test-rust-varint
make audit-rust-varint
```

O alvo prepara o oráculo C real e compara os perfis debug e release com resolução
offline e locked. Consulte o [escopo e os comandos Rust](../AUDIT.md#experimental-rust-varint)
para os requisitos e as verificações que ficam fora desse perfil.

## Solução de problemas

- `zupt: command not found`: confira o `PATH` ou use o caminho do staging
  produzido por `make install DESTDIR=...`.
- Erro de senha: repita no terminal ou use arquivo 0600; não acrescente a senha
  aos argumentos.
- `zupt test` falhou: preserve o arquivo e o log originais e restaure de uma
  cópia conhecida. Não desative a integridade para um novo backup.
- Erro ao iniciar a GUI: confirme `python3`, um binding Qt suportado e
  `ZUPT_BIN`; execute a CLI diretamente para separar problema da GUI de
  problema do arquivo.
- Erro de dependência ou assinatura no openSUSE: atualize os metadados e revise
  o fornecedor habilitado. Não desative assinaturas nem force a troca.

Para reportar vulnerabilidades, siga [SECURITY.md](../SECURITY.md) e não inclua
conteúdo de backups, chaves, senhas ou dados privados de workloads.
