# Guia de usuário do ZUPT

Este guia descreve os fluxos suportados da linha de comando e da interface
gráfica do ZUPT. Os exemplos usam diretórios descartáveis, deixam a etapa de
verificação explícita e mantêm senhas fora dos argumentos dos processos.

## Status da versão

A versão pública oficial é o [ZUPT 5.2.9](https://github.com/cristiancmoises/zupt/releases/tag/v5.2.9).
A versão 5.2.10 continua não publicada até que toda a matriz de validação,
incluindo análise formal e os gates de assembly, seja concluída. Um checkout
cuja string de versão diz 5.2.10 não é um download oficial.

O ZUPT Web está disponível em <https://zupt-web.securityops.co> para exemplos
descartáveis e sem dados sensíveis. O serviço web é uma implantação separada;
limites, versão e fronteira de confiança podem ser diferentes da instalação
local.

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

```sh
git clone https://github.com/cristiancmoises/zupt.git
cd zupt
git checkout v5.2.9       # use v5.2.10 somente após a publicação oficial
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

## Fluxo da linha de comando

Crie, inspecione, verifique e restaure um arquivo em um diretório novo:

```sh
mkdir -p demo/input demo/restored
printf '%s\n' 'dados de exemplo' > demo/input/leia.txt
zupt compress demo/backup.zupt demo/input
zupt list demo/backup.zupt
zupt test demo/backup.zupt
zupt extract -o demo/restored demo/backup.zupt
cmp demo/input/leia.txt demo/restored/leia.txt
```

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
somente a um binário já verificado. Para um bundle de fonte, inspecione a
árvore antes de compilar:

```sh
zupt test zupt-5.2.10-source.zupt
zupt extract -o source-check zupt-5.2.10-source.zupt
find source-check -maxdepth 2 -type f -print | sort
```

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
O round trip local registrado com 281 arquivos passou em 2026-10-16, seguido
por `make check` estrito com Clang 22.1.8 e a suíte funcional da CLI a partir da
árvore extraída, com skips explícitos. Esse snapshot antecede esta atualização
da documentação; não equivale a release assinada nem à qualificação nativa.

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

O instalador inclui os dois guias e as políticas SECURITY/DISTRIBUTION
referenciadas por eles. A regressão confere os bytes instalados, modo 0644,
diretório de dados personalizado e rejeição de guias ausentes antes de criar
a saída da instalação. O build DEB da GUI usa esse instalador, mas esses
checks de staging não compilam nem validam o DEB. Outros helpers nativos
têm gates separados de conteúdo e execução. Referências a headers e scripts
de teste precisam do checkout.

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
criptografia, testa o contêiner, verifica os 17 arquivos exatos, incluindo os
dois guias sob `docs/` e as políticas SECURITY/DISTRIBUTION referenciadas na
raiz do pacote, examina as duas árvores de fontes e compara todos os
bytes extraídos. Ele grava o `.zupt`, seu
arquivo SHA-256 e um diretório `.extracted`. Recusa destinos já existentes.
Uma falha na publicação local pode deixar saídas parciais verificadas para
inspeção; o helper não apaga caminhos finais que outro processo possa ter
substituído. Esse ensaio não é uma release assinada nem aprovação de pacote
nativo. Python, Qt e a CLI testada separadamente continuam sendo dependências
externas. Execute o launcher extraído por `bash`, sem presumir que a extração
restaurou permissões executáveis.
Links para headers e scripts de teste ainda exigem o checkout; esse pacote
não é uma cópia offline completa da documentação do repositório.

Em 2026-10-18, uma CLI nova com GCC 14.3.0 estrito passa no script funcional
e nos 12 métodos de `test-portable-gui`. Os testes usam operações reais de
arquivo e conferem o conteúdo atual de 17 arquivos, checksum, bytes extraídos,
opções de criptografia/codec, rejeição de falhas da CLI, membros alterados,
symlinks e corridas de publicação das saídas. Os arquivos são dados temporários
de teste, não artefatos assinados de release; a suíte não executa Qt.
`make audit-licenses` também passa nos checks de marcadores SPDX das fontes
cobertas, não em auditoria completa de proveniência, REUSE, patentes ou
direitos de redistribuição. Reproduza esses gates separados com a CLI
correspondente testada e as ferramentas de build instaladas:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-portable-gui
make audit-licenses
```

A execução de 2026-10-07 em VM Linux x86_64 passou nos 39/39 testes com
GCC 14.3.0, Python 3.12.12, PyQt6 6.9.1 e Qt 6.9.2. Também criou um `.zupt`
nível 9 com exatamente 13 arquivos da interface, verificou o arquivo e comparou
todos os bytes extraídos com as fontes montadas. A CLI compatível recém-compilada
ficou fora desse pacote da interface; Python e Qt são dependências externas.
Sete checks estáticos/de empacotamento indisponíveis foram registrados à parte.
Esses resultados valem para o snapshot fixo de 248 arquivos, não para alterações
posteriores da documentação, instalação de pacotes nativos, integração com o
desktop ou aprovação da release.

## Validação e relatórios

Antes de publicar uma versão, o projeto executa builds estritos GCC e Clang,
testes unitários e de integração, sanitizadores, fuzzing limitado, scanners de
conteúdo, verificações de pacotes e workflows em VM descartável. `release-check`
depende de `test-jasmin-source`, `test-jasmin-wipe-checker`,
`test-frama-ans-decode-bounds`, `test-frama-ans-reader`,
`test-frama-ans-frequencies`, `test-frama-ans-logarithm`,
`test-frama-ans-log-bounds` e `test-frama-aes-nist` em um host
Linux x86_64 de manutenção com as ferramentas exigidas e AES-NI/AVX habilitado
pelo sistema. Essas análises não são dependências dos alvos `check` ou
`test-all` usados na distribuição. A revisão formal mais ampla continua
obrigatória antes da publicação; ferramentas ausentes ou evidência incompleta
são bloqueios, não passes. O verificador isolado de limpeza confere somente a
sequência fixada da assembly emitida; ele não substitui as ferramentas Jasmin
de segurança e tempo constante.
Consulte [SECURITY.md](../SECURITY.md), [DISTRIBUTION.md](../DISTRIBUTION.md)
e os scripts de testes para a matriz vigente.

### Evidência formal atual, conferida em 2026-10-30

Na repetição de 2026-10-30 UTC, os seis alvos Frama-C mantidos passam na
fonte congelada de 294 arquivos após as cinco correções dos guards ANS:
limites do decodificador, leitor, frequências, logaritmo, limites do
logaritmo e AES com vetores fixos. As ferramentas são Frama-C 29.0, GCC
14.3.0, Why3 1.7.2 e Z3 4.12.2 reconhecido. Cada alvo mantém seu modelo,
suas hipóteses sobre os chamadores e seus checks exatos de resultado; esses
resultados condicionais não comprovam o aplicativo completo.

A repetição comum do Jasmin 2026.09.0 em 2026-10-30 UTC, na mesma fonte,
passa em compilação, safety, CT, DOIT, lowering e comparação de instruções
geradas/mantidas para as cinco fontes selecionadas. Sete
ferramentas/bibliotecas correspondem aos membros dos pacotes fixados. Passam
duas rejeições de ambiente, quatro controles de avisos, dezessete controles
de limpeza, 1.026 blocos AES/OpenSSL e 1.539 casos CTR4. É uma qualificação
das fontes selecionadas sob as pré-condições documentadas, não uma
verificação do programa inteiro, aceitação dos pacotes finais ou o check
separado da integração do aplicativo com `WITH_JASMIN=1`. Os logs brutos e
checks de integridade das fontes/ferramentas foram preservados. Alterações
posteriores da documentação ficam fora do snapshot medido.

Com as versões exatas das ferramentas, modelos de máquina e pré-requisitos
descritos nas seções de auditoria abaixo, execute os alvos em sequência:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-frama-ans-decode-bounds test-frama-ans-reader \
  test-frama-ans-frequencies test-frama-ans-logarithm \
  test-frama-ans-log-bounds test-frama-aes-nist \
  test-jasmin-source-wrapper test-jasmin-wipe-checker test-jasmin-source
~~~

### Checks locais anteriores ao commit, 2026-10-28

O script real de análise estática passa em nove checks com GCC 14.3.0 no
snapshot posterior de 294 arquivos. Seus três scans opcionais do cppcheck
ficam como `NOT RUN`, pois a ferramenta está ausente. Passam 17 casos dos
controles de estado da distribuição, 21 testes de publicação e 20/55 dos
helpers DEB/RPM. A varredura real da política de fontes passa em 294 arquivos
e zero arquivos de distribuição. A integridade da fonte, ferramentas e
supervisor passa antes e depois das execuções limitadas.

Em uma cópia nova da fonte, dentro de um builder isolado, execute:

~~~sh
CC=gcc bash tests/test_static_analysis.sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-dist-source-state test-packaging-failures
bash scripts/check-source-only.sh --tree .
~~~

Os controles de empacotamento usam ferramentas simuladas e fixtures
temporários, não instalações DEB/RPM nativas. O scan da árvore não aprova uma
tag nem um arquivo final. Alterações posteriores da documentação e das
instruções da chave de assinatura ficam fora desse snapshot; os gates finais
da fonte assinada e dos pacotes continuam separados.

### Limites ANS com saída de tamanho exato

O decodificador de sequências confere o tamanho restante do destino antes de
formar ponteiros para cópias largas. Isso corrige cinco guards sem mudar APIs,
a gramática do frame ou a escolha do caminho de cópia em buffers válidos.

Use uma cópia nova das fontes para cada compilador ou configuração de
sanitizadores. Execute:

~~~sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-decode-bounds
make test-frama-ans-decode-bounds
make test-frama-ans-decode-bounds-wrapper
~~~

Dentro de uma VM descartável, use outra cópia nova das fontes para validar
ASan/LSan/UBSan em modo escalar. As execuções locais dos fixtures registram o
conjunto qualificado de ferramentas e as fontes congeladas; este comando usa
os runtimes de sanitizadores instalados para seu compilador:

~~~sh
env \
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    make -j1 V=1 CC=clang WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
    CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror -DVV_DISABLE_SIMD=1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' \
    LDFLAGS=-fsanitize=address,undefined test-ans-decode-bounds
~~~

Um diagnóstico de sanitizador ou status de saída diferente de zero é falha.
Repita com `CC=gcc` em outra cópia nova para qualificar GCC separadamente.
Se a VM oferecer AVX2, repita em uma cópia nova, substituindo somente
`-DVV_DISABLE_SIMD=1` por `-mavx2`. Mantenha os demais flags e opções.
Caso contrário, registre essa configuração AVX2 como `NOT RUN`.

O teste nativo exige decodificação bem-sucedida em destinos de tamanho exato:
quatro literais e caudas de matches v1/v2 nas distâncias 16 e 8. Mantém os três
fixtures de rejeição de metadados ANS4 malformados. O script Frama-C 29.0
analisa o caminho escalar real de cópia de matches de produção, com avisos de
ponteiro inválido habilitados, `gcc_x86_64`, `slevel=5000` e `plevel=4096`.
O resultado observado é de 558/983 instruções alcançadas em 16/95 funções,
zero alarmes e 63 pré-condições válidas, sem desconhecidas ou inválidas.

Seis testemunhos exatos `Frama_C_show_each_*` aparecem após os asserts dos
fixtures. Impedem que retornos por falha de alocação ou caminhos de sucesso
podados aprovem a análise. A falha de alocação continua modelada; builds
nativos exigem sucesso na alocação e na decodificação. Os modelos da libc
Frama-C expressam os asserts C como pré-condições; por isso a contagem separada
de Assertions ACSL é zero. Os 82 controles sintéticos conferem o tratamento de
resultados e as opções exigidas; não executam o decodificador nem o Frama-C.

O perfil cobre sequências de literais brutos com tabelas de sequência de um
único símbolo e os três casos de metadados. Não estabelece a segurança geral
do decodificador, Huffman ou SIMD.

Em 2026-10-27 UTC, o snapshot corrigido de 294 arquivos passou nos alvos reais
`test-all`, `audit-licenses`, `sdk-test` e `sdk-verify-symbols`, com GCC 14.3.0
e Clang 22.1.8 estritos, em VMs descartáveis de 2 CPUs/2 GiB. Os dois
compiladores também passaram nos testes ANS focados nativos e scalar/AVX2,
com saída de tamanho exato e ASan, LSan e UBSan. As compilações completas da
CLI são comuns; esses resultados focados não instrumentam todo o aplicativo.

Uma compilação GCC separada com `WITH_JASMIN=1` passou nos mesmos alvos da
suíte completa, SDK, licenças e símbolos. O teste de vetores exigiu o dispatch
real `Jasmin AES-NI`, com estado AVX habilitado pelo sistema, sem fallback
portátil. As análises das fontes Jasmin e comparações de instruções anteriores
continuam sendo verificações separadas.

Cada perfil completo registra 15 skips explícitos. O guest Clang selecionado
não contém OpenSSL; o GCC pula, em seu lugar, o caso modelado do header bionic
que exige Clang. Windows nativo, dispositivos loop privilegiados, ferramentas
de shell/manual ausentes e provedores opcionais do sistema ficam fora desses
resultados. Cada perfil passou em 16 controles de isolamento, três controles
negativos reais dos sanitizadores e verificações de ordem e diagnóstico.
As etapas do produto não registraram OOM, limite de processos atingido nem
descendente sobrevivente, no envelope mantido de 768 MiB e 16 tarefas.

As falhas anteriores no limite da imagem comprimida e no tempo da etapa GCC
combinada permanecem registradas. Os perfis aprovados preservam todas as
entradas selecionadas e limites globais; as repetições focadas GCC agora têm
etapas supervisionadas separadas, mantendo 300 segundos para o `test-all`
real. As alterações posteriores da documentação ficam fora desses snapshots.
Continuam pendentes o `release-check` completo, a aceitação nativa de
plataformas, GUI e pacotes, os arquivos finais e as assinaturas.

Em uma cópia nova da fonte, reproduza os alvos comuns com GCC:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror' \
  test-all audit-licenses sdk-test sdk-verify-symbols
~~~

Repita com `CC=clang` em outra cópia nova. Para um build Jasmin separado
em x86_64 suportado, use outra cópia nova e `WITH_JASMIN=1`; confira
na saída dos vetores o caminho AES selecionado. Mantenha os provedores
opcionais desativados até qualificar suas dependências do sistema.

Os resultados anteriores da suíte completa abaixo precedem esses cinco
ajustes. O `release-check` completo e a aceitação dos pacotes finais continuam
como requisitos separados.

### Validação anterior com GCC e GUI, 2026-10-23

Em 2026-10-23 UTC, o `test-all` real com GCC 14.3.0 estrito passa sobre
294 arquivos congelados na VM descartável de 2 CPUs/2 GiB, com 15 skips
explícitos. Inclui 81 casos de tamanho exato com ASan, 1.024 bijeções BCJ,
round trips BCJ L5/L9 com comparação exata, regressão de temporização e três
comparações ML-KEM/OpenSSL. A CLI comum não é inteiramente instrumentada
pelo teste ASan de tamanho exato.

Outra VM com PySide6/Shiboken6/Qt 6.9.2 passa em 64 testes atuais da GUI,
33 testes da referência histórica e seis controles de inicialização. Sua CLI
tem os mesmos bytes do executável aprovado na suíte GCC completa. A CLI e
os controles são compilados sem execução em um build isolado no host;
os controles de sanitizador e os workflows da GUI executam no guest. É uma
validação Qt offscreen, sem cobrir desktop nativo ou instalação dos pacotes finais.

Estes alvos do projeto usam os flags padrão do compilador. A
[matriz de auditoria](#reproduzir-os-testes-de-auditoria) descreve os flags
estritos, versões das ferramentas e configuração dos sanitizadores. Execute
em uma VM descartável qualificada, com compilador, runtimes, Python e binding Qt:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
QT_QPA_PLATFORM=offscreen make -j1 CC=gcc \
    WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check-gui
~~~

As duas execuções registradas exigem negativos reais de sanitizador,
supervisão ordenada completa e hashes das fontes preservados. Permanecem
registradas as falhas dos inputs Qt antigos e do tamanho da imagem completa;
o perfil de runtime aprovado mantém todos os limites de isolamento e recursos.
Skips continuam sem cobertura. Documentação final, nova suíte Clang completa,
revisão formal mais ampla, `release-check` completo e pacotes finais ainda
precisam de aceitação própria.

### Repetição formal mantida anterior, 2026-10-21

Em 2026-10-21 UTC, os quatro alvos Frama-C mantidos passam uma vez cada na
fonte fixa de 294 arquivos com Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 e Z3
4.12.2 reconhecido. Controles reais unsat/sat e de endianness do alvo precedem
cada execução. Metadados alcançam 138/358 instruções com 20 pré-condições
válidas; init/take do leitor têm 30 metas JSON exatas válidas (console 34/34);
os intervalos do logaritmo têm duas assertions e duas pré-condições válidas;
quatro blocos AES fixos alcançam 162/162 instruções com 21 assertions válidas,
sete pré-condições e 64 checks de bytes. Essas execuções Eva têm zero alarmes.
SHA-256 do JSON bruto exato do leitor:
`c166b4a85791e86a3884828ad9651699a9a9da37054dfed13eaacb3d98bd0cd0`.

Execuções Jasmin 2026.09.0 comum e UBSan qualificada separadas passam no gate
das cinco fontes, na comparação de instruções geradas/runtime e nos checks
de stores de wipe. Cada uma passa em 1.026 blocos AES e 1.539 casos AES4.
Negativos do ambiente scratch reprovam antes de cada execução; um controle
real de overflow com sinal reprova antes do UBSan. UBSan instrumenta fixtures
C, não assembly nem executáveis dos provedores. Passam todos os status
externos/de processo/coletor das seis execuções e os pós-checks da fonte.
O namespace mantém afinidade com duas CPUs, espaço de endereçamento de 1 GiB
e CPU de 120 segundos por processo, prazo de 125+5 segundos, scratch de
128 MiB e limite de 1 MiB no coletor de saída emitida; não são quotas de
cgroup agregadas. Os hashes nomeados das ferramentas não cobrem todos os
helpers do host nem a closure completa de dependências.

Com as versões exatas das ferramentas e os pré-requisitos descritos nas
seções formais abaixo, reproduza os alvos mantidos sequencialmente:

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-frama-ans-decode-bounds test-frama-ans-reader \
  test-frama-ans-log-bounds test-frama-aes-nist test-jasmin-source
```

A atualização final dos documentos fica fora desses snapshots medidos.
Diagnósticos anteriores mantêm seu escopo original. Esses checks não provam
o leitor/refill completo ou seus chamadores C, AES com chaves arbitrárias,
limpeza de registradores ou resistência a canais laterais físicos. Tratamento
dos alarmes/unknowns exigidos, runtime real `WITH_JASMIN=1` e qualificação
final de fontes/pacotes/plataformas continuam sendo condições separadas;
a repetição não aprova produção ou publicação.

### Validação das frequências ANS

O perfil de frequências verifica a implementação real de
`validated_symbol_count`, não um decodificador substituto. Use Frama-C
**29.0**, GCC **14.3.0**, Why3 **1.7.2** e Z3 **4.12.2** reconhecido no alvo
little-endian `gcc_x86_64` testado:

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-frequencies
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-ans-allocation test-frama-ans-reader-wrapper
```

O perfil WP habilita somente anotações ACSL condicionais e checks explícitos
de overflow sem sinal. Exige 256 frequências legíveis/inicializadas e um
inteiro de saída gravável/separado. Suas 23 metas JSON exatas, sem smoke,
provam o intervalo do retorno e que um retorno positivo implica frequências
de no máximo 4096; a maior soma possível é 16.776.960. O console inclui
dois resultados adicionais de término/inalcançabilidade (25/25). Essas
hipóteses não são automaticamente provadas para os chamadores ou para o
decodificador geral. A contagem anterior de 14 unknowns pertence a um perfil
Eva histórico de fluxos válidos; não é um inventário atualizado da árvore
atual. Os outros perfis mantidos não habilitam esse
contrato nem o assumem em lugar da análise do corpo da função.

Em 2026-10-22 UTC, passam esse gate e os gates anteriores do leitor/metadados.
Uma mutação privada da condição de aceitação deixa apenas o pós-contrato
das frequências sem prova e é rejeitada. Os perfis de resultados do leitor
e frequências passam em 40 controles sintéticos cada; resultados rejeitados
agora preservam o JSON bruto. Esses controles verificam o relatório, não a
semântica C. Execuções escalares estritas GCC/Clang também passam nos oito
vetores diretos de frequências. Uma mutação privada de redução do acumulador
passa nos testes antigos e falha na nova regressão `65535 + 4097`.
O pré-processamento GCC coincide com o C anterior, com ou sem a macro das
anotações; não há mudança de runtime, API ou formato.

O snapshot de 294 arquivos de 2026-10-22 também passa no teste ANS direto de 79.560
estados, duas recargas por estado, e nos oito vetores de frequências sob
ASan/LSan/UBSan na VM descartável de duas CPUs/2 GiB. Negativos reais dos
sanitizadores precedem o teste; são conferidos o objeto Huffman instrumentado
correspondente, hashes exatos das fontes, 25 registros ordenados de conclusão
e pós-checks de processo/coletor/fonte. Passam também o smoke da CLI
instrumentada e checks comuns separados de SDK/interoperabilidade ML-KEM.
A documentação final fica fora desse snapshot. Não é um novo `test-all`
completo, qualificação Jasmin/Qt/pacotes finais, prova do programa inteiro
ou aprovação para publicar/instalar a release. O novo alvo integra
`release-check`, não o `check` comum destinado às distribuições.

### Prova limitada do logaritmo ANS

Analise o `ilog2` escalar original com shift usando Frama-C **29.0**, GCC
**14.3.0**, Why3 **1.7.2** e Z3 **4.12.2** reconhecido em `gcc_x86_64`:

```sh
make -j1 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-logarithm
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-reader-wrapper
```

A prova habilita as anotações `VV_ANS_LOG_WP` somente nesse perfil explícito.
Para `0 <= v < 4096`, prova retorno 0 para zero, resultado entre 0 e 11 e,
para valores positivos, `2^resultado <= v < 2^(resultado+1)`. Os doze
intervalos explícitos mantêm a recorrência linear. Uma invariante redundante
de limite OR permite ao WP relacionar a condição de saída com máscara zero
à adição; ambas as obrigações são provadas pela tática nativa de intervalo
de bits. Não há novo axioma nem substituição do C executável. Isso não
restringe o auxiliar de userspace a esse domínio nem prova que todos os
chamadores o respeitam.

O gate exige **50 metas JSON exatas e válidas, sem smoke**, e o resumo
**52/52**, que inclui dois resultados implícitos. Preserva scripts de prova
e JSON bruto. Cada registro precisa ter uma meta provada e, quando presente,
`subgoals` inteiro igual a um. Totais parciais, booleanos ou zero falham,
assim como invariantes desconhecidas mesmo com pós-contratos válidos.
Passam os 132 casos sintéticos do supervisor; retirar os dois checks de
submetas produz nove falhas. Essas fixtures verificam o relatório, não a
semântica C. Um pós-contrato falso separado confirma a rejeição real.

A fonte integrada passa em `check` estrito e no smoke funcional da CLI com
GCC/Clang, mantendo 11/10 skips explícitos. Negativos UBSan fatais reais
precedem cada execução; rodam os testes UBSan existentes do fuzz-build,
não uma campanha ASan/LSan. O pré-processamento GCC coincide com a base nos
perfis padrão/frequências/logaritmo. Objetos escalares completos `-O2 -g0`
coincidem com a base usando tanto GCC quanto Clang. É um teorema
limitado do auxiliar e uma regressão focada, não aprovação da tabela,
chamadores, codec completo, pacotes ou produção. O novo alvo formal integra
`release-check`, não o `check` comum das distribuições. A documentação final
fica fora do snapshot de runtime medido.

### Limites das entradas da tabela ANS

O alvo existente `test-ans-allocation` também testa `build_dec_direct` em
todas as divisões de frequência entre os símbolos 0 e 255, incluindo os
extremos de um único símbolo, e em uma tabela uniforme com 256 símbolos.
Verifica **16.785.408 entradas**: campos inicializados após preencher o destino
com um padrão inválido, larguras de no máximo 12,
`baseline + (2^nbits - 1) < 4096`, símbolos ativos e multiplicidades exatas.
A largura é conferida antes do shift; a subtração é feita sem underflow.

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
```

Em 2026-10-22 UTC, passam GCC 14.3.0 e Clang 22.1.8 escalares estritos.
O mesmo teste ampliado passa com ASan/LSan/UBSan na VM descartável de duas
CPUs/2 GiB, junto com o teste do leitor de 79.560 estados, oito vetores de
frequências e o smoke da CLI instrumentada. O wrapper exige os três
marcadores, hashes exatos das fontes e o protocolo completo de 25 registros.
SDK/licenças/exports e três comparações ML-KEM/OpenSSL passam em builds
comuns separados, não sob cobertura dos sanitizadores no SDK/provedor.
A documentação final fica fora desse snapshot. Uma mutação privada de largura
é rejeitada somente pelo teste ampliado. Essas fixtures limitadas não cobrem
todas as tabelas arbitrárias com três ou mais símbolos, round trips do
decodificador para cada divisão, equivalência de formato ou prova geral.

Uma tentativa WP privada separada com Frama-C 29.0/Z3 4.12.2 segue incompleta:
109 metas JSON válidas, 17 timeouts e três avisos sobre a especificação de
`memset`/casts de ponteiros no modelo Typed (console 111/128). Suas anotações
não integram o codec. Um pós-contrato indicado como válido enquanto suas
invariantes de laço continuam sem prova não é um teorema estabelecido.
Obrigações gerais de largura/contagem, intervalo de origem, construção da
tabela e chamadores ainda precisam de tratamento rastreável; contagens
históricas e esses testes não as encerram automaticamente. Este trabalho
não aprova publicação para produção.

### Regressão do gate de credenciais do CI

Execute o teste distribuído com Bash, Git e Python 3 em ambiente descartável:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ci-credentials
```

Esse alvo também integra `check` e o CI de política de fontes. Ele extrai e
executa o bloco Bash literal real de `.github/workflows/ci.yml`, sem biblioteca
YAML. Os seis métodos cobrem um fixture rastreado sem ocorrências, nove padrões
sintéticos de credenciais, cinco resultados Git de erro/inconsistência,
layouts inválidos do bloco e variáveis Git herdadas. Um repositório/índice
sintético externo deve permanecer inalterado. Os fixtures usam repositórios
temporários privados, sem commits nem credenciais reais; o conteúdo encontrado
não pode aparecer na saída.

O fixture de chave privada criptografada falhou com o workflow anterior: ele
retornava sucesso para o rótulo PKCS#8 `ENCRYPTED PRIVATE KEY`, definido na
[RFC 7468, seção 11](https://www.rfc-editor.org/rfc/rfc7468.html#section-11).
A expressão corrigida rejeita esse cabeçalho e os formatos de chave privada
anteriores. O fixture sem ocorrências também contém cabeçalhos de chave
pública, chave pública RSA e certificado, que devem continuar aceitos. São
cabeçalhos sintéticos, não chaves utilizáveis nem um teste de parser PEM. Os
seis métodos e o gate real em um índice privado do snapshot selecionado de
283 arquivos passam após a correção.

O gate aceita somente status 1 de `git grep` com resultados vazios.
Ocorrências, erros operacionais e resultados inconsistentes falham sem anunciar
uma verificação limpa. O stderr do Git permanece visível. O código original
aprovava indevidamente três resultados injetados; essas falhas e a falha de
isolamento do ambiente herdado permanecem nas evidências locais.

Antes da extensão para chave criptografada, os seis métodos passaram em
2026-10-17 com Python 3.12.12, Git 2.54.0 e os oito padrões originais.
`check` estrito novo com GCC 14.3.0 e os testes funcionais da CLI passaram no
snapshot registrado de 283 arquivos, antes da atualização documental, mantendo
11 skips normais explícitos. Ruff 0.16.10/formatação e os perfis basic/padrão do
Pyright 1.1.403 passaram para o novo teste; cada perfil de tipagem analisou
exatamente um arquivo com alvo Python 3.8. Isso não valida execução com Python
3.8 nem representa lint limpo da GUI existente. As execuções registradas usaram
namespace sem rede, fontes somente leitura e scratch privado em RAM, duas
CPUs, limite de espaço de endereçamento de 1 GiB e até 64 processos. Essa
política limitada de padrões não aprova o scanner completo de credenciais
separado, o CI remoto, pacotes nativos ou a release.

Uma verificação separada de inicialização do Gitleaks 8.30.1 fixado permanece
bloqueada: texto não vazio sem credenciais encerra com status 2 e erro do
detector sob o limite inalterado de 1 GiB de espaço de endereçamento. O
diagnóstico registra uma reserva virtual de 4 GiB; isso não comprova uso de
4 GiB de RAM residente. Os controles de versão e entradas inválidas não
iniciam o detector e não o qualificam. O inventário de 283 arquivos anterior
à correção classificou 279 textos UTF-8 e quatro imagens binárias, mas nenhum
arquivo do projeto foi varrido. Varreduras de texto por arquivo também precisam
registrar que stdin não fornece o nome original, portanto regras dependentes
do nome não estão qualificadas; imagens binárias e conteúdo decodificado ou
arquivado exigem cobertura separada. Mantenha essa falha distinta da política
limitada de padrões do CI que passou.

O gate de distribuição exige uma árvore de fonte limpa e commitada. `make dist`
rejeita alterações preparadas ou locais, arquivos rastreados removidos e fontes
ou testes ainda não rastreados antes de substituir o arquivo de saída.
Somente `dist` usa Bash com `pipefail`: `git archive` e gzip precisam terminar
com sucesso antes da execução do verificador de conteúdo e da entrega da
saída. Os demais alvos mantêm o shell existente.

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-dist-source-state
```

O alvo executa 17 controles: os oito checks existentes de fonte limpa/alterada,
um controle de sucesso dos adaptadores com comparação de bytes e oito falhas
de produtores, cobrindo Git/gzip, saída vazia/completa e destinos ausentes ou
existentes. Um produtor com erro não pode alcançar o verificador; saídas
existentes preservam bytes e identidade de inode. Os adaptadores encaminham
a saída real de Git/gzip quando solicitado, mas o verificador é um fixture
da ordem das etapas. Esses testes não aprovam sua política de conteúdo, um
commit final de fonte ou pacotes nativos.

Durante o desenvolvimento, registre os checks de execução separadamente da
validação de pacotes; esta precisa identificar o snapshot realmente arquivado.
O tarball reproduzível continua sendo entrada interna do build de distribuição,
não um artefato de release público. Os pacotes públicos usam `.zupt` genuíno.

Execute `make test-quick-harness` para conferir que a suíte rápida rejeita
falhas dos processos e arquivos extraídos ausentes ou danificados. A suíte real
compara os fixtures de texto, aleatório e vazio e exige sucesso nos processos
de compressão, extração e verificação de integridade.

Ao relatar uma falha, informe comando, versão do compilador, digest do source,
status de saída e localização do log bruto. Um round trip bem-sucedido prova
somente aquele fixture; não prova segurança nem compatibilidade com todo
arquivo histórico.

### Verificação da documentação dos pacotes nativos

Os helpers DEB/RPM da CLI/GUI executam `scripts/check-installed-docs.py` sobre
o pacote realmente extraído, antes de entregá-lo. Exigem os dois guias sob
`docs/` e SECURITY/DISTRIBUTION no diretório pai. A documentação deve ter os
mesmos bytes da fonte, modo 0644 e nenhum componente symlink. O verificador
aceita os layouts Debian, Fedora e openSUSE, inclusive o sufixo exato da versão
atual quando usado. Diretórios ausentes ou duplicados são rejeitados; uma
versão antiga não substitui a atual. A rota debhelper preserva nomes `.md`,
sem quebrar links relativos pela compressão automática.

Execute os testes focados sem compilar a CLI:

```sh
make test-installed-docs
```

Para conferir uma árvore privada já extraída de um build local verificado:

```sh
python3 scripts/check-installed-docs.py . /caminho/absoluto/privado/extraido zupt
```

Use `zupt-gui` no último argumento para o pacote GUI. O comando é somente
leitura e confere apenas documentação; não extrai arquivos, autentica pacotes,
aprova dependências nativas nem substitui testes de execução. A fonte e a
árvore extraída devem ser privadas e não podem mudar durante a verificação.
Os testes usam dados sintéticos e o verificador real; a suíte de empacotamento
também verifica um staging real do instalador GUI. Esses resultados não são
resultados de build ou instalação nativa de DEB/RPM.
Esses fixtures exigem host POSIX de empacotamento; Windows, MSYS e Cygwin
registram skips explícitos em vez de validar modos Unix nesses ambientes.
Use a variável Make existente `PYTHON` para selecionar o interpretador instalado.

### Metadados do spec RPM

Com as ferramentas RPM reais da distribuição, inspecione um spec revisado
em ambiente isolado de empacotamento. A expansão de macros pode iniciar helpers:

```sh
rpm --version
rpm --eval '%{_prefix} %{_bindir} %{_buildshell}'
rpmspec -P packaging/opensuse/zupt.spec
rpmspec -q --buildrequires packaging/opensuse/zupt.spec
```

Ambientes de build Fedora precisam de `libubsan`: a suíte mantida compila e
executa regressões do harness com UBSan. É uma dependência de build, não um
requisito adicional da CLI instalada. O spec openSUSE usa `%{?ext_man}` para
o sufixo de compressão das páginas de manual da distribuição. Execute
`bash tests/test_packaging_syntax.sh` para conferir a expansão RPM real com
`.gz`, `.xz` e sufixo indefinido; ferramentas ausentes continuam como skips
explícitos. O parse local não substitui os gates nativos de `spec-cleaner`,
build e instalação.

O check de 2026-10-18 usa RPM 4.20.1 instalado, arquivos Guix `rpmrc` e macros
x86_64-linux selecionados explicitamente, alvo `x86_64-unknown-linux` e
`_topdir`/`_tmppath` privados. Versão, inspeção das macros, parse do spec e
listagem dos 14 requisitos de build declarados retornam zero. O `_prefix`
real é o diretório do RPM no GNU store; comandos de build/instalação expandidos
também referenciam ferramentas `/usr/bin` ausentes nesse namespace. Nenhuma
seção `%prep`, build, check ou install é executada. Não substitua essas
diferenças nem use `--nodeps` para afirmar aceitação nativa openSUSE. Listar
requisitos não comprova sua instalação; esses resultados não mudam a contagem
anterior da suíte completa de metadados sem uma execução separada dessa suíte.

### Regressões de falhas nas ferramentas de empacotamento

Execute os testes de fronteira DEB/RPM sem compilar ou instalar pacotes:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-packaging-failures
```

Esse alvo é obrigatório em `release-check`, não no `check` usado pelas
distribuições. Exige host Linux com Bash, utilitários GNU, `timeout`, `tar`,
`gzip` e Python 3. Executa cópias privadas dos helpers reais da CLI/GUI com
substitutos controlados para as ferramentas externas. A suíte DEB também
executa o instalador real da GUI e o verificador de documentação em staging
temporário. Não chama um gerenciador nativo, compila o Zupt ou altera o host.

Os testes exigem que falhas de `rpm`, `find`, `sort` e `readelf` interrompam
o helper mesmo após imprimirem uma saída plausível. Preservam o diagnóstico
e o status do produtor, conferem a limpeza e rejeitam o avanço além dos
checkpoints de validação identificados. A inspeção ELF bem-sucedida ainda
deve rejeitar RPATH/RUNPATH e provedores opcionais incorporados. Os helpers
DEB precisam recusar arquivos regulares e symlinks de saída existentes,
inclusive links pendentes, sem modificar seus destinos.

O alvo executa 21 testes unitários do publicador, 20 casos DEB e 55 RPM.
Os controles de metadados/ELF param em checkpoints identificados; controles
positivos separados percorrem os dois helpers RPM completos até a publicação.
Eles substituem ferramentas externas e não afirmam sucesso em build nativo.
Execute cada script diretamente para preservar
logs, rastros e status por caso em um diretório privado novo:

```sh
env ZUPT_TEST_EVIDENCE_DIR=/caminho/absoluto/novo/privado/deb-logs bash tests/test_deb_packaging_failures.sh
env ZUPT_TEST_EVIDENCE_DIR=/caminho/absoluto/novo/privado/rpm-logs bash tests/test_rpm_packaging_failures.sh
```

Essas regressões não aprovam dependências nativas, instalação, assinaturas ou
release.

Os quatro helpers nativos exigem um diretório de saída pertencente ao usuário
do build, sem escrita para grupo/outros. Mantêm um descritor somente leitura
desde antes do build e usam `scripts/publish-package.py` na publicação final.
O descritor também é herdado pelos subprocessos do build; não é uma barreira
contra uma ferramenta maliciosa ou outro processo com o mesmo UID. A verificação
de caminhos usa `O_PATH`, `O_DIRECTORY` e `O_NOFOLLOW` do Linux; os ancestrais
exigem permissão de travessia, não de listagem, e symlinks são rejeitados. As fontes,
seus ancestrais e os vínculos do staging privado precisam permanecer confiáveis.
Use um diretório privado novo para cada tentativa.

O publicador prepara até dois pacotes regulares, de no máximo 1 GiB cada, em
staging privado de modo 0700 no mesmo sistema de arquivos da saída. Confere
comprimentos copiados, metadados da fonte, escritas e sincronização dos arquivos
antes de tornar os artefatos de modo 0644 visíveis. Todos os nomes são
conferidos antes do primeiro hard link; cada link falha atomicamente se já
existir qualquer entrada final, inclusive symlink pendente ou diretório.
Os checksums descrevem os bytes preparados e só são impressos após sucesso
da chamada inteira, com escape de nomes GNU. Esses helpers não criam arquivos
laterais de checksum.

A garantia é não sobrescrever cada arquivo, não uma transação para o par RPM
inteiro nem durabilidade após queda de energia. Uma falha tardia pode deixar
arquivos publicados; ficam para inspeção e nunca são apagados pelo nome final.
Vínculos de staging alterados também são preservados. As verificações do
namespace são snapshots, não travas contra renomeações concorrentes arbitrárias
dos ancestrais ou processos privilegiados. Inspecione saídas parciais e repita
em um diretório novo, sem sobrescrevê-las. A aprovação nativa dos pacotes e da
release continua separada.

### Testes da ABI de capacidade de disco no Linux

Estes testes focados também são dependências de `make check`:

```sh
make CC=gcc test-disk-ioctl-abi test-disk-ioctl-abi-wrapper
make CC=clang test-disk-ioctl-abi test-disk-ioctl-abi-wrapper
```

Os fixtures C exercitam os helpers reais de capacidade com os dois tipos de
requisição ioctl usados pela libc, capacidades acima de 4 GiB, capacidade zero
e consultas malsucedidas. Somente `fstat` e `ioctl` são substituídos; os testes
usam um arquivo regular temporário e não abrem dispositivos de disco. Os flags
do compilador e linker selecionados são preservados, os asserts ficam ativos e
diagnósticos de sanitizadores ou falhas dos processos fazem o teste falhar.
Os 16 controles sintéticos verificam o supervisor, não o código C do produto.

Quando Clang é o compilador selecionado, o script também verifica a fonte real
de disco contra um modelo pequeno da sobrecarga de signedness e da opção
documentada de desativação da bionic. Outros compiladores pulam explicitamente
esse modelo, sem selecionar outro compilador pelo `PATH`. O modelo não equivale
a um build com Android NDK nem a um teste de execução no Android.

### Testes de capacidade para saída de arquivos

Execute `make test-atomic-output-probe` para os 16 controles do supervisor de
capacidade de diretório, também exigidos por `make check`. Eles exercitam flags
do chamador, falhas de compilação e execução, diagnósticos de sanitizadores e
validação dos marcadores, sem substituir ou executar a CLI. O teste real de
saída de arquivo executa separadamente o `zupt` selecionado e verifica a
preservação dos arquivos e a limpeza das saídas temporárias.
Os controles incluem flags vazios do chamador e foram executados com Bash
5.2.37; a validação de execução em Bash antigo continua separada.

### Testes do fixture de disco legado

Execute `make test-legacy-disk-compiler` para os quatro controles da fronteira
do compilador, também exigidos por `make check`. Eles verificam flags do
chamador, `CC` com vários argumentos, flags vazios/ausentes, avisos estritos e
falhas de compilação visíveis. Uma falha controlada interrompe a execução antes
da CLI; esses controles não decodificam arquivos. O teste real permanece
separado:

```sh
bash tests/test_legacy_disk_5_2_1.sh ./zupt
```

Ele decodifica o fixture 5.2.1 criptografado/com deduplicação do repositório e
verifica `list`, `test`, extração genérica e restauração de disco em arquivos
regulares temporários, comparando os bytes restaurados. Não acessa disco físico
nem estabelece compatibilidade com todos os arquivos históricos. Os flags
devem corresponder à toolchain selecionada; musl estático requer a configuração
normal `LDFLAGS=-static`.

### Reproduzir os testes de auditoria

Usuários técnicos podem executar os testes do produto a partir de um checkout
novo que contenha somente fontes. Execute as verificações de licença e fonte
antes da compilação: o scanner examina toda a árvore de trabalho, incluindo
artefatos de build ignorados pelo Git. Guarde toda a saída e não trate uma
dependência opcional ausente como um passe:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 source-audit
bash tests/test_source_only.sh
```

A regressão de fontes executa 54 casos. Seis injetam falhas na enumeração da
árvore, dos arquivos extraídos e do índice Git após a ferramenta real concluir
com sucesso, emitindo nada ou um registro seguro completo. O scanner precisa
falhar com diagnóstico da etapa, sem resumo de aprovação. Três controles de
repasse e um fixture ELF rejeitado verificam o preparo. A enumeração usa listas
novas delimitadas por NUL em temporários privados; a saída parcial de um
produtor com falha nunca é consumida. A execução focada e o `check` estrito com
GCC 14.3.0 passaram em 2026-10-20; o segundo mantém 11 skips de plataforma,
provedor ou ferramenta. Isso verifica o tratamento de falhas da auditoria,
não mutações concorrentes da árvore, segurança completa do codec ou pacotes
nativos.

Outros quatro casos verificam a contagem dos bytes extraídos com um fixture de
fonte de 32 bytes. O `wc` real conclui primeiro; os controles então retornam
erro com saída vazia, zero ou contagem numérica completa, ou repassam uma
contagem bem-sucedida. Zero e saída completa reproduziram aprovações falsas
antes da propagação explícita do erro da pipeline; a rejeição de erro com saída
vazia já existia. Passam os quatro casos, preservando os 50 anteriores. O
`check` estrito com GCC e a suíte funcional da CLI real passaram novamente em
2026-10-20 com os mesmos 11 skips. Os limites não mudaram; isso não cobre toda
falha de contagem/ferramenta nem aprova pacotes finais.

Após as verificações de fonte passarem, compile e execute os testes:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-asan-run
```

`test-asan-run` compila um binário com AddressSanitizer/UndefinedBehaviorSanitizer
e executa um teste básico de round trip com detecção de vazamentos. Compilar
com `test-asan` sozinho não executa esse teste. Para repetir o scanner de fonte
após os testes de execução, use outro checkout novo contendo somente fontes;
os binários gerados são achados esperados na árvore compilada.

#### Supervisão do teste de folga do decoder

Após compilar a CLI, execute os controles do supervisor e os round trips reais:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-vv-decode-slack-harness
bash tests/test_vv_decode_slack.sh ./zupt
```

O primeiro comando executa dez casos sintéticos na fronteira com a CLI,
incluindo caminho com espaços, saída completa seguida de status de erro,
compressor posterior com falha que mantém o arquivo anterior utilizável e
dados extraídos corrompidos ou ausentes. Seis casos reproduziram aprovações
falsas antes da correção. O teste real agora verifica o status de cada
compressão/extração antes de comparar bytes, separa os arquivos por nível e
fluxo, mostra os diagnósticos dos comandos com falha e limpa os fixtures
privados ao sair. O segundo comando preserva a entrada repetitiva de 10 MiB
em L1/5/9 explicitamente seriais (`-t 1`) e L1/9 com quatro threads (`-t 4`),
tanto na compressão quanto na extração. A CLI sintética rejeita seleções de
threads ausentes ou incorretas; seis casos falham antes da correção do fluxo
serial. Ambos os comandos fazem parte de `check`.

Outros três controles cobrem diretório vazio, arquivo oculto preservado e
falha da ferramenta de limpeza com stdout vazio e status 73. O predicado
antigo, baseado apenas na saída de `find`, retornava sucesso indevidamente.
O `rmdir` não recursivo verificado agora propaga o erro e o diagnóstico;
remove somente diretórios próprios de fixtures já encerrados, nunca seu
conteúdo.

Um `check` completo intermediário falhou na compressão L5 com seleção
automática de 24 threads sob o limite inalterado de 1 GiB de espaço de
endereçamento. Os casos supostamente seriais omitiam `-t 1`; corrigir essa
cobertura não identifica a alocação que falhou nem corrige o comportamento
de memória das threads automáticas. Em 2026-10-21 UTC, passam os dez casos do
supervisor, três controles de limpeza e os round trips reais em um novo
`check` estrito com GCC 14.3.0 limitado, seguido da suíte funcional da CLI real.
Permanecem 11 skips explícitos de plataforma/provedor/ferramenta; passam os
54 casos do auditor de fontes. A varredura separada cobre 292 arquivos.
Os controles sintéticos testam supervisão shell, não compressão ou
criptografia. Esse build comum não é uma nova execução global de sanitizadores,
prova formal, validação de pacotes nativos ou aprovação para produção.

#### Supervisão da verificação de símbolos SDK

Use uma toolchain GNU/Linux nativa configurada. Execute os controles de
supervisão separadamente do build e dos testes reais do SDK:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-sdk-build-flags
make CC=clang WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 sdk-test sdk-verify-symbols
```

O primeiro alvo mantém 25 controles de compilador/receita e acrescenta 11
execuções da receita real `sdk-verify-symbols` com fixture pré-compilado
sintético. Usa dois exports literais esperados, `nm` sintético e repasse real
por `awk`, `sed`, `sort`, `grep` e `tr`. Cada erro injetado ocorre após saída
completa e o status esperado da ferramenta real. Marcadores e rastros exatos
impedem que falhas alheias de preparação satisfaçam um caso negativo. Cobrem
operação normal, funções ausentes/extras, oito falhas de ferramentas e limpeza
verificada do diretório temporário. Seis casos reproduziram aprovações
indevidas antes da correção; as duas falhas dos sorts finais e as funções
ausentes/extras já reprovavam. Os 36 controles passam após alterar a receita.
Esses controles não compilam nem executam o SDK e não comprovam compatibilidade
de ABI em runtime.

A receita agora verifica cada produtor separadamente, em vez de depender do
último status da pipeline. A varredura de rejeição aceita apenas o status 1
legítimo de ausência de correspondência do grep, nunca erros da ferramenta.
Mantém a política existente de símbolos de texto exportado (`T`), mapa de
versão e shell portátil; não amplia a auditoria para todas as classes de
símbolos. O segundo comando compila e exercita o SDK interno real e verifica
suas funções exportadas. `WITH_SDK=0` desativa o adaptador libvuptsdk externo,
não os alvos do SDK interno.

Em 2026-10-21 UTC, o snapshot corrigido de 294 arquivos passa em `test-all`
estrito com Clang 22.1.8, seguido de `audit-licenses sdk-test sdk-verify-symbols`,
na VM descartável qualificada. Use os flags completos em
[suíte da fonte atual](#runtime-com-jasmin-e-suíte-da-fonte-atual), selecionando
o Clang configurado para `CC`. Passam os 24 registros ordenados e os status
de VM/coletor/integridade/protocolo. Inclui 81 casos ASan de tamanho exato,
1.024 bijeções BCJ, round trips BCJ da CLI idênticos byte a byte em L5/L9,
três comparações reais ML-KEM/OpenSSL e 15 casos do SDK interno. O gate de
tempo passa em cinco execuções com 200.000 amostras por classe e limiares
inalterados; é evidência de regressão, não prova de tempo constante ou
benchmark do codec.

Os limites continuam em 2 CPUs/2 GiB, etapas de 768 MiB/16 tarefas, scratch
de 512 MiB, arquivos de 64 MiB, saída de 4 MiB por etapa e prazos de 300
segundos nas etapas do produto. Picos de cgroup da suíte/SDK de
233.459.712/33.243.136 bytes, sem eventos OOM/limite de processos nem
descendentes restantes nessas etapas. Permanecem 14 skips explícitos:
Windows nativo, cinco casos SDK externo, dispositivo loop privilegiado,
zsh/fish/ferramentas de manual, pacote de desenvolvimento SDK externo ausente
e três integrações de provedores desativados. SDK, PQBOX e Jasmin ficam
desativados nesse perfil completo; o fixture bionic com Clang selecionado
executa. Um `check` GCC 14.3.0 estrito comum separado e a suíte da CLI real
passam com 11 skips. Não é build globalmente instrumentado nem nova
qualificação Frama-C/Jasmin. A atualização final dos documentos fica fora do
snapshot da VM. SHA-256 do log bruto completo:
`c3bc4b4264539b771eaa1a549efae830a9b57b26c36d367fbc17d87f73b2ca50`.

Na contabilidade da release, diferencie os seis alvos Frama-C mantidos
(limites do decodificador, inicialização/extração do leitor, validação das
frequências, logaritmo com domínio limitado, intervalos do logaritmo e AES
de vetores fixos), os checks Jasmin de fonte/segurança/tempo constante/
wipe e os testes reais de runtime `WITH_JASMIN=1`. Resultados anteriores mantêm
suas próprias identidades de fonte e ferramentas. Totais históricos de metas
de pesquisa não são uma lista atual de aprovação/reprovação. Isso não dispensa
revisão e resolução ou justificativa dos alarmes/unknowns exigidos pela
política de distribuição, escopo formal mais amplo, cobertura dos provedores
opcionais ou gates dos pacotes finais. Nenhuma contagem isolada de alvos
comprova prontidão para produção.

#### Supervisão dos testes de tamanho exato e BCJ

Após compilar a CLI, execute separadamente os controles do supervisor e o
teste real do codec:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-codec-exact-size-wrapper
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-codec-exact-size
```

O primeiro alvo usa processos sintéticos de compilador/CLI e enumeração real
de arquivos. Mantém dez controles de compilação/status/sinal e acrescenta
nove casos BCJ: operação normal; compressão/extração com saída completa
seguida de status 73 em cada nível L5/L9; enumeração que emite um nome válido
e depois falha; e saída extra, ausente ou corrompida. Cinco casos reproduziram
aprovações indevidas antes da correção. Os outros três negativos já reprovavam
o script antigo. Etapas com falha precisam preservar todos os diagnósticos,
impedir operações dependentes e nunca informar aprovação; o outro nível
continua sendo testado.

O supervisor real agora verifica o status de cada etapa antes de aceitar sua
saída, lê um manifesto completo delimitado por NUL e exige exatamente um
arquivo extraído idêntico byte a byte. O caminho existente de compilação e
execução ASan permanece igual. Controles sintéticos não executam codec ou
sanitizador. O segundo alvo precisa de runtime ASan disponível e executa o
codec real e os checks BCJ da CLI; nenhum dos alvos sozinho aprova produção.

Em 2026-10-21 UTC, o snapshot corrigido de 294 arquivos passa em `test-all`
estrito com GCC 14.3.0, seguido de `audit-licenses sdk-test sdk-verify-symbols`,
na VM descartável qualificada. Os flags e comandos completos estão em
[suíte da fonte atual](#runtime-com-jasmin-e-suíte-da-fonte-atual).
Passam os 24 registros ordenados e os status de VM/coletor/integridade/protocolo.
O teste real informa 81 casos de tamanho exato, 1.024 bijeções BCJ determinísticas
e round trips da CLI idênticos byte a byte em L5/L9. Também passam o gate de
tempo, 14 checks multithread, dez PQ, 14 dedup, três comparações reais
ML-KEM/OpenSSL e 15 casos do SDK interno. A medição de tempo mantém cinco
execuções, 200.000 amostras por classe e limiares originais; é evidência de
regressão, não prova de tempo constante. Tempos multithread não são benchmarks
do codec.

A VM mantém 2 CPUs/2 GiB, etapas de 768 MiB/16 tarefas, scratch de 512 MiB,
arquivos de 64 MiB, saída de 4 MiB por etapa e prazos de 300 segundos nas
etapas do produto. Não há eventos OOM/limite de processos nem descendentes
restantes nessas etapas. Os picos de cgroup da suíte e SDK são 236.765.184 e
95.404.032 bytes. Permanecem 15 skips explícitos: Windows nativo, fixture bionic
com Clang selecionado, cinco checks de SDK externo, dispositivo loop
privilegiado, zsh/fish/ferramentas de manual, pacote de desenvolvimento SDK
externo e três integrações de provedores desativados. SDK, PQBOX e Jasmin
ficam desativados nesse perfil completo. Um `check` GCC comum separado e a
suíte da CLI passam com 11 skips. Não é nova qualificação Clang, de sanitizador
do programa inteiro, Frama-C/Jasmin ou dos pacotes finais. A atualização final
dos documentos está fora do snapshot da VM; produção continua sem aprovação.
SHA-256 do log bruto completo da VM:
`d88e75ad5903048f498f43043d780ce9f56aedd067bebed6cb7d458e3cff89b0`.

#### Falhas de alocação nos workers e preservação do arquivo

Execute o alvo mantido com compilador Linux nativo e linker compatível com
GNU que suporte `--wrap`. Também são necessários GNU Make, Python 3 e `timeout`:

```sh
make CC=gcc CFLAGS='-O2 -g -Werror' \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-worker-allocation

make CC=gcc CFLAGS='-O2 -g -Werror -fsanitize=undefined -fno-sanitize-recover=all' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=all' \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-worker-allocation
```

O alvo compila uma CLI privada a partir do core real com wrappers de link
exclusivos do teste; binários normais nunca incluem o injetor. Os flags do
chamador são preservados, acrescentando `-fno-lto` para manter a interceptação
visível. SDK, PQBOX e Jasmin ficam desativados nessa compilação privada.
Alvos não Linux ou cross são pulados; linker sem suporte em um alvo nativo
elegível é falha, não cobertura.

Uma entrada fixa de 65.536 bytes usa STORE, dois workers e blocos de 65.536
bytes. Cinco casos cobrem operação normal e falhas deliberadas no buffer
inicial de compressão (76.288 bytes) e no payload final (65.536 bytes) do
worker 0, cada falha com destino ausente ou existente. O teste verifica a
sequência exata de alocações, início real das duas threads, retorno dos workers,
uma injeção, status normal 1 e diagnóstico de falta de memória do bloco.
Timeouts, sinais, erros do fixture e diagnósticos de sanitizadores reprovam
o teste. Os bytes do destino anterior devem permanecer iguais; destinos
ausentes continuam ausentes. `rmdir` verificado rejeita temporários ocultos
restantes. O arquivo normal deve verificar e extrair byte a byte. A saída
completa e os status dos comandos são mostrados.

Em 2026-10-21 UTC, os cinco casos passam com GCC 14.3.0 estrito comum e com
UBSan sem recuperação sob o perfil limitado inalterado. O `check` comum
ampliado e a suíte da CLI real também passam, mantendo 11 skips explícitos.
É cobertura de regressão de um tratamento de falhas existente, não um novo
bug corrigido no runtime. Clang estava indisponível nos locais verificados.
Esses casos apenas STORE não identificam o OOM anterior com 24 threads
automáticas, não comprovam ausência de vazamentos, não cobrem falhas de alocação
criptografadas e não aprovam pacotes nativos ou produção. Não implicam nova
prova Frama-C/Jasmin ou execução global de sanitizadores em VM.

#### Controles do gate de análise estática

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-static-analysis-harness
env CC=gcc bash tests/test_static_analysis.sh
```

O primeiro comando executa 53 cenários do supervisor. Eles cobrem descoberta
de fontes, falhas silenciosas do compilador, erros de `grep` antes ou depois
de saída completa, contagens inválidas ou inconsistentes, contagens muito
grandes, avisos e padrões proibidos nas fontes. A ausência do SHA-NI deve
interromper o fluxo antes da compilação; sua remoção posterior não pode omitir
os checks silenciosamente. Esses controles alteram somente fixtures privados,
e as asserções usam o `grep` real.

Os controles usam substitutos de compilador/analisador; não analisam C.
O segundo comando executa as políticas reais de avisos do GCC e as passagens
disponíveis do cppcheck. A ausência de cppcheck continua como skip, não uma
análise limpa. Preserve os logs completos e os códigos de saída. Um status
válido sem ocorrências é diferente de falha da ferramenta ou leitura, mesmo
quando esta já imprimiu zero.

`source-audit` confere a política de conteúdo somente-fonte, não credenciais
expostas. Um detector de segredos que não inicializa não comprova scan limpo.

#### Testes de callbacks do SDK

O SDK e a CLI compartilham a seleção explícita `WITH_JASMIN`. Nos builds
x86_64 compatíveis, `WITH_JASMIN=1` seleciona a assembly versionada nos
chamadores C do SDK, além de vincular seus objetos. O padrão portátil continua
`WITH_JASMIN=0`; isso não habilita provedores externos da CLI no SDK.

Verifique as receitas sem compilar:

```sh
make WITH_SDK=0 WITH_PQBOX=0 test-sdk-build-flags
```

As 25 asserções verificam seis regras de compilação C com assembly desativada
e ativada, os `CPPFLAGS` do chamador e a exclusão dos flags/bibliotecas dos
provedores externos da CLI. O teste também integra `check` e `sdk-test`.
Receitas não substituem testes de execução. Para builds reais com assembly,
comece em um checkout descartável limpo para cada compilador:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 \
  SDK_BUILD_DIR=build/sdk-gcc sdk-test sdk-verify-symbols
```

Repita com `CC=clang` em outro checkout novo. Diretórios separados do SDK
não isolam objetos compartilhados da CLI ou do Jasmin. Atualmente, o SDK
mantém a detecção de recursos da CPU no estado padrão: vincular a assembly
AES não comprova dispatch AES por hardware no SDK. Esta correção de build
não fundamenta uma alegação de ganho de throughput.

A biblioteca de compatibilidade interna `libzuptsdk` tem testes próprios.
Execute a suíte completa do SDK ou somente os 13 casos de callbacks:

```sh
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test sdk-verify-symbols
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-stream-errors
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-staging
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-file-reads sdk-test-key-ownership
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-read-stop sdk-test-temp-paths
make CC=gcc SDK_BUILD_DIR=build/sdk-gcc CFLAGS='-O2 -g -Werror' sdk-test-key-write-errors
make CC=clang SDK_BUILD_DIR=build/sdk-ubsan \
  CFLAGS='-O1 -g -Werror -fsanitize=undefined -fno-sanitize-recover=all' \
  sdk-test sdk-verify-symbols
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:hard_rss_limit_mb=512 \
  UBSAN_OPTIONS=halt_on_error=1 \
  make CC=clang SDK_BUILD_DIR=build/sdk-asan \
  CFLAGS='-O1 -g -Werror -fsanitize=address,undefined -fno-sanitize-recover=all' \
  sdk-test sdk-verify-symbols
```

Os testes usam o código real de arquivos com falhas injetadas nas operações de
I/O. Verificam roundtrip byte a byte, erro de leitura após entregar 17 bytes,
callbacks com retorno negativo/curto, contagens `max_bytes + 1` e `INT64_MAX`,
falhas de fechamento e preservação do primeiro erro. Os streams são realmente
fechados mesmo quando o teste injeta erro no fechamento. O fixture requer
`fopencookie` e um linker com suporte a `--wrap`. O callback de saída pode
receber um prefixo antes de uma falha; descarte essa saída se a operação
falhar. A interface usa arquivos temporários e não é um decodificador
incremental.

Nas operações do SDK em POSIX, escolha por `TMPDIR` um diretório temporário
privado da sua conta, com modo `0700` e diretórios ancestrais confiáveis. A
limpeza e as reaberturas posteriores pressupõem que outros usuários não possam
substituir suas entradas. A criação exclusiva não garante essa condição se o
diretório pai estiver sob controle de um atacante.

Os 26 checks originais de caminhos temporários incluem truncamento em uma hierarquia
real longa, falhas de formatação nas 15 chamadas do helper, validação dos
fixtures e limpeza final de alocações. Os nove chamadores públicos rejeitam um
nome inválido ou truncado com `ZUPTSDK_ERR_IO` antes de usá-lo. Os testes
preservam bytes e identidade de inode dos arquivos alheios, ponteiros de saída
e contagens de descritores; a compressão por stream não deve consumir entrada
antes de preparar os dois nomes. Falhas aninhadas removem somente arquivos de
staging já pertencentes à operação. As verificações da consulta ao diretório
temporário no Windows ainda exigem validação nativa nessa plataforma.

Na glibc, dois controles adicionais verificam a saída válida da formatação
verificada e a rejeição real de um limite declarado de destino inconsistente.
A rejeição usa um buffer fisicamente suficiente e exige o sinal de aborto e
o diagnóstico esperados da libc; falhas de sanitizador ou sinais diferentes
não contam como sucesso. Os interceptores cobrem as entradas comuns e
fortificadas sem descartar flags de formato nem limites. A primeira execução
hospedada da 5.2.10 revelou essa lacuna do teste, não uma falha observada da
formatação de produção.

Em 2026-10-29, as suítes completas estritas do SDK passam localmente com GCC
14.3.0 e Clang 22.1.8 nos perfis comum, `_FORTIFY_SOURCE=2` e
`_FORTIFY_SOURCE=3`, incluindo os 28 casos de caminhos temporários em cada
perfil. Uma mutação de controle que descarta o limite encaminhado falha no
novo caso de rejeição, enquanto os 26 originais ainda passam. A validação no
Ubuntu hospedado e a dos pacotes nativos finais continuam separadas.
Use uma cópia nova da fonte para cada compilador e perfil:

~~~sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  SDK_BUILD_DIR=build/sdk-fortify3 CPPFLAGS='-D_FORTIFY_SOURCE=3' \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror' \
  sdk-test
~~~

Repita com `CC=clang`, com nível de fortificação `2` e com `CPPFLAGS` vazio
para o perfil comum. Mantenha a otimização habilitada para a fortificação da
glibc e use diretórios de build separados para flags diferentes.

Os 18 casos de interrupção de leitura exercitam cópias de chaves e entrega de
arquivos pelo callback de saída. Verificam que um `fread` parcial positivo com
erro não é seguido por outra leitura e que os bytes exatos do prefixo são
entregues uma única vez. A falha de leitura prevalece sobre callbacks curtos
ou com erro e sobre falhas de fechamento. Uma chamada do SDK que falha dentro
do callback não deve substituir o diagnóstico da leitura externa. Cópias de
chaves com falha preservam bytes e inode do destino; descarte a saída parcial
dos callbacks quando a operação falhar.

`sdk-test` também inclui 40 casos de staging privado nas operações de
compressão por stream/buffer, extração para diretório, verificação e
descompressão por stream. Verificam modo `0600` e close-on-exec sob `umask 000`,
preservam bytes e identidade de dispositivo/inode dos arquivos e links em
colisão, e injetam falhas de permissão, conversão para stdio, escrita e
fechamento. O SDK mantém o handle criado exclusivamente e, na falha, remove
somente arquivos que criou. Após integração, esses casos passaram em GCC comum
e builds separados de Clang/UBSan e Clang/ASan/UBSan. A CLI recompilada também
passou nos 52 checks de arquivos de chave e nos oito checks funcionais.
A compilação COFF para Windows e seis casos de modelo da ponte são evidências
separadas; não validam linkedição, execução ou aplicação da DACL no Windows.

O alvo de leitura acrescenta 58 casos para falhas de tamanho, seek, leitura,
fechamento e alocação na compressão por arquivo/buffer, extração para buffer e
nas duas leituras da descompressão por stream. Verifica saídas inalteradas na
falha, ausência de callback prematuro, limpeza dos buffers incompletos,
fechamento dos handles e preservação do primeiro erro quando o fechamento
também falha. A extração de arquivo vazio funciona mesmo se o alocador retorna
`NULL` para pedidos de zero bytes.

O alvo de posse de chaves acrescenta 19 casos para limpeza dos arquivos gerados
após falha de alocação, ciclos de exportação/destruição de chave pública e
preservação de arquivos privados/públicos carregados pelo usuário. Colisões com
arquivos regulares, symlinks e hardlinks mantêm bytes e identidade. Chaves
salvas e caminhos carregados continuam pertencendo ao chamador. Esses testes
não validam todo erro do escritor de chaves do núcleo; arquivos parciais após
falha no SDK são cobertos pela regressão separada de escrita de chaves.

Os 74 checks de escrita de chaves injetam falhas de criação, permissão,
escrita negativa/nula/parcial, sincronização e fechamento. Flags internos de
criação permitem ao SDK remover somente suas próprias chaves temporárias
privadas/públicas; arquivos regulares, symlinks e hardlinks em colisão mantêm
bytes e identidade. A limpeza e os callbacks do alocador não devem substituir
o primeiro erro. O escritor de chaves da CLI mantém intencionalmente arquivos
com falha para inspeção; esse contrato tem controles separados e não mudou.
Esses checks não qualificam a limpeza de caminhos não ASCII, handles com
falha ou o comportamento nativo de DACLs no Windows.

Em 2026-10-15, um build comum novo com GCC 14.3.0 e builds separados com
Clang 22.1.8 usando UBSan e ASan/UBSan passaram nos 15 checks do SDK, nos 13
casos de stream e no check de símbolos
exportados. Esses testes no host não substituem os gates de VM, instalação de
pacotes ou análise formal do programa completo. Uma compilação exploratória
de todo o núcleo com `-Wconversion -Werror` falhou nas conversões assinadas de
índices já existentes em `src/zupt_lz.c`; essa falha continua registrada. O
fixture novo de stream passa com esses flags de conversão/protótipos.

#### Testes de leitura de chaves nativas

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-native-key-read-errors
```

Esse alvo também faz parte de `make check`. Seus 66 casos usam geração,
exportação, criptografia e descriptografia reais de ZKEY e ZPQK, com falhas de
stream injetadas. Verificam leitura parcial positiva com erro, EOF de chave
pública, sondagem final obrigatória de chave privada completa, dados/erros
após a chave, falhas de fechamento e cabeçalhos/checksums inválidos. A rejeição
preserva `EINVAL` e as saídas do chamador; cada stream fecha uma vez. A limpeza
interna do buffer foi revisada no código, não observada diretamente pelo teste.

A injeção depende dos cookie streams de GNU/Linux e de wrapping no linker.
Windows, Darwin, BSD e Android registram skip explícito; alvo do compilador
vazio ou desconhecido é erro. As execuções nativas registradas usam glibc,
não musl ou Windows. Os testes comuns de arquivos de chave continuam
necessários em cada sistema suportado.

#### Controles de senha e integridade da suíte multithread

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-threaded-harness
```

Esse alvo também faz parte de `make check`. Executa o script multithread real
com uma CLI sintética. Os 14 controles anteriores permanecem: um positivo
e 13 negativos de T9 cobrem status
0/2/127, status 1 não relacionado, encerramento do filho, quatro marcadores
de diagnóstico, saída após NUL e falhas operacionais nas duas varreduras do
log. Cada negativo precisa reprovar especificamente T9 enquanto os outros
13 casos passam; uma falha arbitrária do script não é evidência suficiente.
A validação anterior aprova indevidamente 12 controles. A correção exige
status 1 da CLI, varredura completa sem marcadores e o diagnóstico
`Error: Authentication failed`; erro de leitura nunca significa log limpo.

Outros 20 negativos exercitam T10: status não zero, encerramento do filho,
texto de sanitizadores (também após NUL), saída não relacionada contendo
`0 failed`, `10 failed`, contagem errada, resumo ausente, duplicado ou
contraditório, resumo contraditório após NUL e falhas nas três varreduras.
Cada um deve reprovar somente T10, mantendo os outros 13 casos aprovados,
com recibo da injeção; falhas de varredura também exigem recibo da ferramenta.
O T10 original aceita indevidamente 18 dos primeiros 33 controles. O controle
seguinte, com contradição após NUL, expõe a primeira correção, que contava
somente resumos iniciados por espaços em branco.

A validação final exige status 0 da CLI, ausência de marcadores de
sanitizadores e exatamente uma linha igual a
`  Test: 9 passed, 0 failed (9 files)` (com dois espaços iniciais). Contam os
nove arquivos regulares, inclusive vazio e em subdiretório; diretórios não
contam. Toda linha contendo `Test:` entra na contagem, independentemente do
prefixo. Status e contagem devem ser válidos: imprimir `1` antes de falhar
não permite aprovar T10. Este grupo mantém 34 controles, tanto em `make check`
quanto nos testes existentes de interpretadores e autocópia do Guix.

Sete controles de ciclo de vida elevam o subtotal a 41. Executam a
suíte real com um pai temporário privado e exclusivo contendo espaços,
restauram `umask 000` do chamador e conferem um diretório real com modo 0700
e um arquivo gerado pela suíte com modo 0600. Um symlink no nome antigo
aponta somente para um sentinela fictício privado, que deve permanecer
inalterado. Outros controles exigem limpeza e status 129/130/143 para
HUP/INT/TERM, ou status 1 antes de chamar a CLI quando o pai é inválido ou
`mktemp` falha. Os sete reprovam a inicialização antiga; nela, o controle INT
sai com zero e o arquivo gerado tem modo 0666. A correção passa nos sete.

`TMPDIR` deve apontar para um pai confiável que outro usuário não possa
substituir. A suíte usa `mktemp -d`, encerra se a criação falhar e limpa pelo
trap de saída. SIGKILL e interrupção do próprio supervisor podem deixar
fixtures temporários, inclusive o symlink de teste no nome antigo; nesses
casos não há garantia de limpeza. Não use dados importantes como fixtures.

Nove controles do fixture JSON elevam o subtotal a 50. A suíte mantém
o gerador original com semente 42, mas exige término sem erro e uma validação
separada de exatamente 5.000 registros, IDs inteiros sequenciais, nomes
`user_ID` correspondentes e scores de ponto flutuante finitos. Saída vazia,
curta, malformada, excessiva ou com esquema inválido, scores não finitos,
gerador que produz os dados completos antes de falhar e validador que imprime
sucesso antes de falhar devem encerrar com status 1 antes da primeira
compressão. Os controles exigem recibo da injeção, diagnóstico, limpeza do
diretório e ausência de chamadas de compressão, extração ou integridade;
também verificam um registro inválido no meio do arquivo. Os oito negativos
reprovam o gerador anterior sem validação. O fixture normal é conferido
independentemente, sem regenerar scores. Seu SHA-256 observado coincide com
a saída anterior à correção no Python fixado; isso não demonstra determinismo
entre versões nem valida produtores JSON arbitrários.

Dez controles dos fixtures binários elevam o subtotal a 60. Antes de T1,
os dois produtores `dd` devem terminar sem erro e um validador separado deve
aceitar exatamente 512.000 bytes aleatórios e 204.800 bytes zerados. O
controle normal confere independentemente os tamanhos e o conteúdo zerado
na primeira compressão. Para cada produtor, os controles injetam saída
completa seguida de erro ou saída vazia, curta e excessiva com status zero.
Os oito expõem aprovações indevidas no script antigo. Um nono negativo faz
o novo validador de tamanhos imprimir sucesso antes de falhar. Cada negativo
exige status 1, recibo da injeção, diagnóstico, limpeza e ausência de T1,
resumo ou chamadas de compressão/extração/integridade. Os diagnósticos dos
produtores são preservados. Naquele marco restrito aos fixtures, os 50
controles anteriores e os corpos de T1–T14 permaneceram inalterados. Os bytes
aleatórios não são determinísticos; esses controles não validam produtores arbitrários.

Onze controles de T14 elevam o subtotal a 71. Os compressores com N=1 e
N=4 precisam terminar com status zero e deixar uma saída regular e não vazia
antes de qualquer indicação de sucesso da medição. O controle normal confere
as duas chamadas em ordem; dez negativos cobrem cada fase falhando antes da
saída, falhando após a saída sintética completa ou retornando zero com saída
ausente, vazia ou em forma de diretório. Os dez expõem aprovações indevidas no
script antigo. Após a correção, exigem status 1, exatamente uma falha T14 e
totais de 13 aprovados/1 falha, marcadores de diagnóstico de stdout/stderr,
recibos das chamadas e limpeza, sem tempos, speedup ou sucesso com medição
indisponível. Os corpos e chamadas dos 60 controles anteriores permanecem
inalterados. T14 agora guarda um log combinado de stdout/stderr por compressor
e mostra ambos em caso de falha. Essa proteção de tipo/tamanho não demonstra
integridade dos arquivos; não verifica falhas do relógio/`awk` nem diagnósticos
de sanitizadores em um processo que termina com zero. Os tempos continuam
informativos, não são evidência de benchmark reproduzível.

Oito controles de T6 elevam o total atual a 79. T6 exige status zero tanto na
compressão quanto na extração, exatamente 1.000 arquivos regulares de saída
e comparação recursiva dos caminhos e conteúdos de toda a árvore. A raiz
esperada mantém o prefixo absoluto de entrada sem a barra inicial, conforme
uma listagem/extração real de referência; a simulação de T6 agora reproduz
esse layout. Cinco controles expõem aprovações indevidas no gate antigo:
saída completa seguida de erro do compressor ou extrator, além de corrupção
de mesmo tamanho, renomeação ou mudança de diretório de `file_2.txt`, que não
era amostrado. Os controles de arquivo ausente/extra cobrem rejeições já
existentes pela contagem cujo stderr era descartado. Cada negativo exige
status 1, uma falha T6, totais 13/1, ambos os marcadores de diagnóstico e
limpeza; o controle normal exige 14/0. Os corpos e chamadas dos 71 controles
anteriores permanecem inalterados. Antes de corromper a saída, o controle
remove seu hardlink e verifica que os bytes do `file_2.txt` original não
mudaram. Isso não verifica metadados/permissões, nem constitui auditoria
completa do parser ou medição de desempenho.
Passam os 79 controles; uma execução separada da CLI real passa nos 14 checks
multithread.

Os fixtures usam hardlinks somente nos dados privados gerados para limitar
o espaço temporário. Não executam o codec nem a criptografia; a saída
sintética de tempo não mede throughput. Execute a CLI real separadamente:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' \
  CARGO=false WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
bash scripts/test-installed-zupt.sh ./zupt
sh tests/test_threaded.sh ./zupt
```

O `check` e a suíte funcional registrados com GCC 14.3.0 passam com Cargo
desativado; 11 checks indisponíveis permanecem explícitos (Windows, um caso
modelado de cabeçalho bionic, cinco casos do SDK externo, dispositivo de loop
privilegiado, zsh, fish e renderizadores da página de manual). A execução
multithread real separada passa nos 14 checks, incluindo round trips com
1/2/4/8 threads, criptografia, rejeição de senha incorreta e integridade.
Seus tempos não são evidência de desempenho reproduzível. Outras lacunas de
status e geração dos fixtures permanecem. Esse resultado e os controles
sintéticos não substituem validação de runtime com sanitizadores, dos pacotes
finais ou de produção.

#### Verificações do executável instalado

Confira separadamente o executável realmente instalado ou preparado:

```sh
bash scripts/test-installed-zupt.sh /caminho/do/pacote/bin/zupt
```

A receita da CLI no Guix agora executa esse script com o caminho exato
`$out/bin/zupt`, após stripping e validação de RUNPATH. Respeita `#:tests? #f`;
a compilação cruzada pula o novo check por padrão, como a fase GNU padrão.
Um check pulado não valida o runtime instalado. Confira a ligação da fase
com Guile e os módulos Guix disponíveis:

```sh
guile --no-auto-compile -q -s tests/test_guix_gui_install_plan.scm
```

Os controles Scheme executam a fase real com um script gravador para conferir
ordem, caminhos com espaços e propagação de falhas; não executam o codec.
Separadamente, o perfil privado registrado compila a CLI atual com GCC
estrito, instala pelo Make, executa o pós-processamento real do Guix e passa
no script funcional sem o executável da árvore de build. Remover o binário
instalado faz a fase falhar. Isso não cria uma derivação, resolve sua closure
nativa de dependências, instala no perfil do usuário ou qualifica a origem
retirada ainda selecionada pela receita.

A etapa dos manifestos SHA-256 verifica os geradores de hash, a enumeração e a
ordenação. Qualquer falha rejeita o gate, inclusive quando o produtor imprime
saída plausível ou deixa ambos os manifestos vazios. As comparações de bytes
e os checks de status/sanitizadores da CLI continuam sendo requisitos separados.

Teste o próprio validador com a CLI real:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-installed-smoke-harness
# Ou use um executável já compilado:
bash tests/test_installed_smoke_harness.sh /caminho/do/pacote/bin/zupt
```

Em hosts POSIX são 65 casos: os 53 controles existentes de processos e 12
controles das ferramentas de checksum. As duas interfaces têm controle de
sucesso, saída vazia/plausível com erro de hash e falhas de enumeração/ordenação.
Adaptadores privados encaminham ao gerador SHA-256 real disponível; o caminho
`shasum` não exige Perl para esses controles. Eles validam o tratamento de
falhas do script, não Perl nativo, pacotes macOS/BSD/Windows, cobertura de
sanitizadores ou prontidão para produção. No Windows, os fixtures de sinais
POSIX registram skip explícito.

Esse teste exercita round trips de arquivos sintéticos e tratamento de
falhas; não instala nada no perfil do usuário nem substitui os gates formais.
No experimento registrado da CLI GNU Guix em 2026-10-09, o build real da
derivação, o `check` habilitado e as fases de instalação passaram em uma VM
descartável. A execução volátil completa anterior dessa mesma fonte e
derivação registra dez skips explícitos.
A exportação da saída para retenção durável falhou depois no limite do
arquivo comprimido. Em um experimento posterior com transferência binária
limitada, a saída exata foi capturada, restaurada em armazenamento temporário
privado e reserializada byte a byte. O comando acima passou nos oito checks
contra a candidata CLI real. O classificador completo da VM ainda rejeitou
essa execução: os recibos finais do console foram truncados no desligamento,
e o cliente silencioso omitiu logs das fases/testes.
Isso não anula o gate de aceitação que falhou nem estabelece cobertura de
sanitizadores, validação da GUI ou aprovação para produção.
Outra execução da mesma fonte fixa e derivação restaurou os logs completos
das fases e usou uma espera limitada do console antes do desligamento.
Os classificadores completos nativo e volátil passaram, com os dez skips
explícitos e tamanho/hash idênticos da saída. Essa execução não transferiu
pacote; não transforma a execução anterior com transferência binária em pacote aprovado.
Uma execução separada em 2026-10-10 passou nos classificadores completos
nativo e volátil e comparou seu fluxo UART novo byte a byte com a candidata
preservada até EOF. Os códigos de saída do produtor, coletor, compressor e
comparador foram zero; dez skips explícitos permanecem. Isso verifica a
transferência nessa execução, sem criar outro artefato durável.
Uma verificação posterior de retenção privada armazenou uma cópia XZ de
277.792 bytes da saída exata. Ela passou na validação de fluxo único CRC32,
decodificação e comparação completa até EOF, sincronização conferida do
arquivo/diretório e releitura integral. A restauração dessa cópia comprimida,
a reserialização NAR e os oito checks reais da CLI passaram contra a
referência bruta preservada. Treze controles sintéticos de retenção passaram
separadamente; eles não auditam o produto nem provam durabilidade física.
Isso conclui apenas o gate da cópia privada retida, não durabilidade após
perda de energia ou aprovação da release. Pacotes públicos continuam
exigindo `.zupt`; o XZ usado aqui é evidência privada.
As execuções anteriores reprovadas continuam reprovadas. As mudanças
posteriores de documentação não fizeram parte do build fixado.
A fase de instalação ocorreu dentro da VM, não no host: empacotamento
nativo da GUI, fonte imutável revisada, conclusão formal/tempo constante,
assinaturas e validação final da release continuam pendentes.
Não substitua o pin da receita por uma fonte anterior
nem pule testes para aprovar a 5.2.10.

Para verificar metadados e fases da CLI/GUI no Guix, execute na raiz das fontes
com Guile, módulos Scheme do Guix, `sh`, `bash`, `python3` e `make` no `PATH`.
Mantenha prazo externo para falhas dos subprocessos:

```sh
timeout --kill-after=2s 30s guile --no-auto-compile -q -s tests/test_guix_gui_install_plan.scm
NIX_REMOTE=dummy:// timeout --kill-after=2s 30s bash tests/test_packaging_syntax.sh
```

O teste focado avalia a receita real e executa a fase de instalação por cópia
do Guix em armazenamento temporário. Compara byte a byte com o source o manual
instalado da GUI, os arquivos de licença do projeto e da GUI e a proveniência
dos assets, além do ícone relativo ao módulo, dois guias de usuário e políticas
de segurança/distribuição: dez arquivos da GUI conferidos no total. Também
executa a fase real de documentação da CLI e compara os dois guias,
`SECURITY.md` e `DISTRIBUTION.md`, totalizando quatro arquivos da CLI.
Em 2026-10-17, a regressão ampliada falha primeiro em `DISTRIBUTION.md` ausente
na CLI; após corrigir essa entrada, detecta `SECURITY.md` ausente na GUI.
A receita corrigida passa nas duas comparações reais de arquivos instalados.
Uma execução nova e estrita com GCC também passa nas 17 etapas, testes
funcionais da CLI e 56 testes reais da GUI offscreen, com 11 skips normais,
no snapshot corrigido de 282 arquivos antes desta atualização apenas documental.
A origem da fonte permanece intencionalmente inalterada; essas fases não
comprovam derivação Guix nativa, closure completa, instalação pelo gerenciador
de pacotes ou aprovação da release. A regressão de intérpretes executa a fase
padrão real `patch-source-shebangs` antes da fase da
receita que ajusta fixtures gerados, seguida por nove grupos de controles em
shell. Os wrappers do leitor, logaritmo e tamanho exato começam como
fontes não executáveis e copiam a si mesmos para ferramentas executáveis;
isso detecta a ausência da preparação dos shebangs sem exigir compilador
ou Frama-C reais. Não compila nem executa o codec. Os grupos DEB/RPM também
executam os helpers reais com ferramentas substitutas: os 20 casos DEB e
55 RPM devem passar. A receita ajusta seus intérpretes gerados; corrigir
apenas o shebang de entrada não basta. A regressão detecta essas omissões
em ambiente semelhante ao Guix sem `/usr/bin/env`; um host convencional
pode ocultar essa dependência. Uma execução
registrada sem rede omite `/bin/sh` e `/usr/bin/env`, verificando que os fixtures
gerados usam os intérpretes selecionados do store. O pin da fonte retirada,
o build nativo e a closure real do Qt continuam como gates separados.
Uma execução separada no host aplica essas fases reais ao snapshot completo
de 281 arquivos e passa no `make check` estrito com GCC 14.3.0 e na suíte
funcional da CLI real. Foram executados 29.413 checks de limites do codec;
SDK/PQBOX/Jasmin estão desativados nesse build. Os 11 skips explícitos abrangem
Windows nativo, o modelo de cabeçalho bionic exclusivo do Clang, cinco sweeps
do SDK, dispositivos de loop privilegiados, zsh, fish e renderizadores de
manuais. Hashes e modos das fontes são conferidos antes e depois dos testes.
Isso valida a execução no host, não uma derivação Guix nem a GUI.
A cópia do ícone para o tema continua instalada separadamente; a cópia relativa
permite ao módulo Python encontrar sua imagem.
O teste também executa as fases reais `make-launcher` e `install-desktop-file`
com caminhos controlados para a saída padrão dos pacotes. Um executável Guile
que registra a chamada substitui o Python: confere limites exatos dos argumentos,
incluindo strings vazias, espaços, aspas, glob com arquivo correspondente e
quebra de linha; variáveis de caminhos ausentes, vazias e herdadas; CLI fixada,
prefixo completo de 48 bibliotecas auxiliares, status 37 e modo executável.
Os campos obrigatórios do desktop incluem `Exec` com o caminho gerado e `%F`,
além de `Icon=zupt-gui`. Esse teste não executa Qt. O ambiente do processo pai
é restaurado e o pipe é fechado com coleta do filho, inclusive em erros de
leitura. Oito mutações deliberadas em cópias privadas da receita foram rejeitadas
pelos checks correspondentes; esses controles não são bugs do produto.
A execução isolada de metadados em 2026-10-10 registrou 55 passes,
nenhuma falha e dois skips (Make e `dpkg-parsechangelog` indisponíveis); o parser
Nix usou o store `dummy://`, sem armazenamento persistente. Esses checks não
compilam dependências, resolvem todos os Gexps/caminhos do store, verificam o
arquivo remoto fixado ou validam um pacote nativo completo da GUI ou abertura
real pelo desktop. Guile ausente é um skip na suíte de metadados, não um passe
do teste focado.

Um teste isolado separado usou essas mesmas fases com dependências já instaladas
e a CLI restaurada privadamente. Sem caminhos herdados de Python/plugins/bibliotecas
e com um `ZUPT_BIN` conflitante, o launcher gerado retornou `zupt-gui 5.2.10`
e passou no selftest offscreen real com seis abas, selecionando
`/tmp/package/bin/zupt`. Usou Python 3.12.12 e PySide6 6.9.2/Qt 6.9.2 sob os
limites abaixo. Algumas versões auxiliares instaladas são anteriores ao snapshot
atual da receita; isso evidencia o runtime desses inputs específicos, não a
validação da closure Guix desejada ou um build nativo da GUI.

Para testar diretamente pelo Python uma GUI preparada, use um ambiente com
PySide6 e suas dependências Qt. Selecione a CLI e o módulo correspondentes:

```sh
env ZUPT_BIN=/caminho/do/pacote/bin/zupt \
    ZUPT_GUI_MODULE=/caminho/do/pacote/lib/zupt-gui/zupt_gui.py \
    QT_QPA_PLATFORM=offscreen python3 -B tests/test_gui_workflows.py \
    BootstrapGuardTests CapabilityLabelTests WorkerLogTests SupervisorTests \
    GuiWorkflowTests.test_plain_vaptvupt_archive_actions \
    GuiWorkflowTests.test_password_vaptvupt_archive_actions \
    GuiWorkflowTests.test_cancel_before_worker_start
```

Isso seleciona 38 testes, não a suíte completa. Em 2026-10-10 eles passaram com
Python 3.12.12, PySide6 6.9.2/Qt 6.9.2 e a CLI nativa Guix 5.2.10 restaurada
privadamente. Um teste separado conferiu caminho/versão exatos da CLI,
encontrou o ícone relativo instalado e executou o selftest offscreen com seis
abas. O checkout e o store das ferramentas instaladas foram montados somente
leitura em sandbox sem privilégios ou rede: CPUs 0/1, espaço de endereçamento
de 1 GiB por processo, armazenamento
temporário de 32 MiB, limite de 1 MiB por arquivo e prazo externo de 30 segundos.
O teste completo de fechar/cancelar cria um arquivo de 32 MiB e não foi executado
nesse perfil; seu fixture e critérios continuam iguais. Execute o `check-gui`
completo acima em ambiente descartável com recursos adequados. A seleção de
fluxos usou execução direta pelo Python, não o launcher gerado. O teste separado
do launcher acima não estabelece cobertura completa dos fluxos, abertura pelo
desktop X11/Wayland real ou derivação nativa completa da GUI. O build da CLI
continua vinculado à sua fonte fixa anterior.

Um perfil posterior, separado e somente em RAM, executou os 39 testes
inalterados em 2026-10-10: nenhuma falha ou skip, incluindo fechar a janela
com a CLI ativa, cancelar o filho e aguardar o trabalhador. Para a suíte
completa, omita a seleção de casos e transmita a desativação de bytecode ao
processo filho:

```sh
env PYTHONDONTWRITEBYTECODE=1 \
    ZUPT_BIN=/caminho/do/pacote/bin/zupt \
    ZUPT_GUI_MODULE=/caminho/do/pacote/lib/zupt-gui/zupt_gui.py \
    QT_QPA_PLATFORM=offscreen \
    timeout --kill-after=2s 135s python3 -B tests/test_gui_workflows.py
```

Use um ambiente descartável com PySide6 e suas dependências Qt configuradas.
Seu encerramento deve terminar e coletar todos os descendentes, inclusive
sessões separadas; o timeout do exemplo sozinho não garante esse isolamento.
A execução completa usou armazenamento temporário de 128 MiB, limite de
32 MiB por arquivo e prazo externo de 135 segundos; o supervisor inalterado
da suíte tem prazo de 120 segundos. O fixture existente de fechar/cancelar
grava exatamente 33.554.432 bytes, portanto não cabe no limite anterior de
1 MiB por arquivo nem no perfil de 32 MiB de armazenamento temporário.
O novo perfil manteve CPUs 0/1, limite de CPU de 25 segundos por processo,
espaço de endereçamento de 1 GiB por processo, 64 descritores, core dumps
desabilitados, UID/GID sintéticos 65534, source/ferramentas somente leitura
e ausência de rede, home, daemon Guix ou display do host. Não são limites
de RAM agregada nem um teste em VM. O perfil anterior e seu resultado
parcial registrado não foram alterados.

Os fluxos completos usaram execução direta pelo Python do módulo atual
instalado da GUI e da CLI restaurada privadamente da fonte fixa anterior,
com Python 3.12.12 e PySide6/Qt 6.9.2 existentes. Antes dessa execução,
o launcher gerado pela receita real passou novamente nos checks de versão
e selftest offscreen com seis abas. Isso não comprova abertura pelo desktop
real nem valida a closure de dependências da receita atual.
Naquele snapshot, o `copy-build-system` do Guix removia a fase padrão
`check`, e a receita da GUI não a reincluía: aqueles resultados externos
não devem ser atribuídos a um build nativo da GUI. A derivação nativa completa
da GUI e os demais gates da release continuam pendentes.

O resultado de 39 testes acima é anterior à correção do ciclo de vida das
operações concluídas. Um teste separado com a CLI real reproduziu um, dois e
três objetos finalizados ainda ligados à aba aberta. A regressão acrescentada
falhou antes da correção e passou depois: três operações, nenhum job restante
como filho da aba e uma notificação de destruição por job, thread e worker,
mantendo a janela aberta. O worker é destruído ao terminar sua thread; o
controlador agenda a própria destruição somente após o join nativo existente
e a remoção da lista ativa. Os testes de arquivos e cancelamento agora observam
a destruição da thread em vez de chamar métodos de objetos Qt destruídos,
preservando as verificações reais de status do filho, estado dos widgets e
callbacks na thread da GUI.

Os 40 testes passaram depois, sem falhas ou skips, no mesmo perfil separado
da suíte completa e com os inputs preparados. O comando completo acima agora
inclui a nova regressão; para selecionar apenas ela, acrescente
`GuiWorkflowTests.test_completed_jobs_release_qobjects_before_window_close`.
Isso verifica o ciclo de vida observado dos objetos Qt, não vazamentos de
RSS agregado, concorrência arbitrária, compatibilidade PyQt6 ou o pacote
nativo da GUI ainda pendente.

O diálogo de confirmação de fechamento executa um loop de eventos modal:
um job da lista inicial pode terminar e ser destruído antes da confirmação
do cancelamento. A nova regressão reproduziu um erro de QThread destruída
com uma operação real da CLI. O tratamento de fechamento agora consulta
novamente os jobs ativos após a confirmação, sem guardar uma thread destruída
através desse loop. A regressão focada e depois os 41 testes passaram; a
suíte completa passou novamente após a correção final do código do teste,
sem falhas ou skips. Para selecionar apenas o novo caso, acrescente
`GuiWorkflowTests.test_job_finishing_during_close_confirmation_does_not_use_deleted_thread`
ao comando acima. Os limites de isolamento e os inputs preparados descritos
acima continuam aplicáveis; essas execuções não aprovam um pacote nativo da
GUI nem a publicação para produção.

As verificações de sintaxe Python passaram nos dois arquivos Python alterados.
O Ruff 0.16.10 registrou os mesmos 29 diagnósticos e dois arquivos fora da
formatação antes e depois dessas mudanças; não restaram diagnósticos novos,
mas esses checks de lint e formatação não passaram. O Pyright não iniciou
a análise: o V8 não conseguiu reservar sua região de código sob o limite
inalterado de 1 GiB de espaço de endereçamento por processo. Esse check de
tipos permanece bloqueado, não aprovado.

### Verificações da GUI durante o build Guix

A receita atualizada da GUI acrescenta `check` após `install-desktop-file`;
os testes ficam habilitados por padrão. Executa `zupt-gui --version` e
`zupt-gui --selftest` pelo launcher instalado e depois chama Python com `-B`
para executar `tests/test_gui_workflows.py` sem selecionar casos.
`ZUPT_BIN` seleciona a CLI correspondente dos inputs e `ZUPT_GUI_MODULE`
seleciona o módulo instalado. O Qt usa offscreen, e os filhos herdam a
desativação de bytecode. Definir `#:tests? #f` desativa esse gate
deliberadamente; esse build não comprova cobertura dos testes da GUI.

A geração do launcher e o check dos fluxos compartilham o cálculo dos
caminhos Python, de plugins Qt e de bibliotecas. O check remove valores
herdados antes de executar o launcher e depois define os caminhos exatos do
pacote para a execução direta pelo Python. Restaura todo o ambiente do pai
no sucesso ou na falha de um filho. Falhas na versão, no selftest ou nos
fluxos interrompem a fase, sem aceitar saídas anteriores bem-sucedidas.

O comando Scheme focado acima também verifica a ordem das fases, testes
habilitados por padrão e explicitamente, desativação sem executar filhos,
as três chamadas exatas, caminhos limpos e restauração do ambiente.
Cada posição de filho é testada com status 37 e o erro real de invocação do
Guix. Seu executável de registro verifica a ligação das chamadas, não o Qt.

Separadamente, a nova fase real da receita executou o launcher instalado,
o selftest com seis abas e todos os 41 fluxos duas vezes em 2026-10-10,
inclusive após o ajuste final da formatação da receita: nenhuma falha ou
skip, marcador de conclusão exato e ambiente restaurado. Usou o perfil
separado somente em RAM descrito acima, Python 3.12.12 e PySide6/Qt 6.9.2
existentes, a GUI atual instalada e a CLI restaurada da fonte fixa anterior.
Não executou a derivação nativa da GUI nem validou a closure atual da receita.
Metadados puros de pacotes e diretórios com nomes semelhantes no store não
são saídas autenticadas de derivações nem comprovam a disponibilidade da
closure necessária.

Em 2026-10-16, uma execução separada usou uma CLI correspondente recém-compilada
e a GUI atual do snapshot registrado de 281 arquivos. As fases reais de
instalação, launcher, desktop e check passaram com Python 3.12.12 e PySide6/Qt
6.9.2 existentes: 13 comparações de bytes dos arquivos instalados, selftest de
seis abas e todos os 41 fluxos. As 17 etapas registradas passaram, incluindo
os checks estritos com GCC e os testes funcionais da CLI real; seus 11 checks
indisponíveis de plataforma/provider/ferramentas permanecem explícitos.
Foi uma execução offscreen no host sem rede, não uma derivação nativa Guix
ou teste da closure. As saídas das bibliotecas existentes foram mapeadas
manualmente como dados. O teste de cancelamento inalterado exige um fixture
de 32 MiB: somente a GUI e seus filhos CLI receberam esse limite por arquivo;
as etapas normais mantiveram 16 MiB no mesmo filesystem temporário de 128 MiB
em RAM. O erro anterior do driver e a falha de capacidade de 16 MiB continuam
reprovados; nenhum teste ou critério foi enfraquecido. Alterações posteriores
de documentação e supervisão dos testes não pertencem àquele snapshot.
O fallback de locale C do Qt e o aviso de binding importado do Guile continuam
preservados no log bruto.

A origem da receita ainda seleciona o arquivo da tag de release anterior,
não essas fontes editadas. A aceitação nativa precisa usar a fonte final
revisada e fixada, os inputs reais desejados e um perfil descartável de build
admitido separadamente. Os limites atuais de retenção não admitem o
experimento nativo existente da GUI. O resultado da fase preparada não
autoriza instalação de pacote nem aprovação da release.

Em 2026-10-17, três novas regressões de renderização literal falharam no log
com texto formatado ainda inalterado. O log de texto simples passou depois
nos 50 testes pela fase real da receita da GUI instalada: os 41 anteriores,
oito controles do widget e um round trip com caminho real de arquivo POSIX.
Cobrem marcação, entidades/Unicode, entradas repetidas, vazias e multilinha,
altura e somente leitura, estilo efetivo, seleção e rolagem. Use o
`make check-gui` mostrado acima para incluí-los; o caso de nome POSIX recebe
skip explícito nas plataformas que não representam esse fixture.

A execução registrada no host usou a CLI recém-compilada com GCC 14.3.0 e
Python 3.12.12/PySide6/Qt 6.9.2 existentes, mantendo o filesystem de 128 MiB
em RAM sem rede, limites de 2 CPUs/1 GiB por processo e o limite separado de
32 MiB para o fixture da GUI descritos acima. Passaram as 17 etapas, incluindo
checks estritos e testes funcionais da CLI; seus 11 skips normais permanecem
explícitos. A fonte selecionada tinha 282 arquivos antes desta atualização
documental. Não foram testados PyQt6, closure Guix nativa ou desktop real.
Isso não aprova a release.

Os checks separados de qualidade Python continuam não limpos: Ruff informa
os mesmos 29 diagnósticos na base preservada e nas fontes modificadas, e
ambas falham na formatação. Tentativas anteriores do Pyright encerraram com
133 na reserva da região de código e 134 na alocação do heap sob o limite de
1 GiB de espaço de endereçamento; essas falhas continuam registradas. A
correção de exibição não muda formato, criptografia ou argumentos da CLI.

Uma execução posterior em 2026-10-17 reproduz 22 asserções de fluxo reprovadas
antes de corrigir a decodificação UTF-8 por bloco. Cinco métodos adicionais
exercitam 31 cenários do worker real: cada divisão de caracteres de 2/3/4
bytes, leitura byte a byte, LF/EOF, progresso intercalado, sequências malformadas
ou truncadas, EOF vazio e reutilização. Limites determinísticos de `read1`
envolvem um processo filho real; a conclusão exige reap e fechamento do pipe.
Os 55 testes passam depois na fase da GUI instalada, junto de checks estritos
novos com GCC, testes funcionais da CLI e 17 etapas registradas; os 11 skips
normais continuam explícitos. Vale o mesmo provider e perfil de recursos acima.
Somente esse snapshot posterior de 282 arquivos contém a correção UTF-8, antes
da atualização documental seguinte. Não aprova pacotes nativos, PyQt6,
sanitização da suíte completa ou produção. A retenção total de saída continua
como revisão de recursos separada; esta correção não acrescenta um limite.

Na análise de tipos Python, um experimento Linux pareado e isolado manteve
2 CPUs, limite de 1 GiB de espaço de endereçamento e as mesmas opções do
interpretador/heap V8. As arenas glibc padrão abortaram com 134; usar
`MALLOC_ARENA_MAX=1` permitiu concluir a mesma análise da base. O `VmPeak`
registrado caiu de 1.048.480 para 819.064 KiB; são observações do processo,
não benchmarks do codec. Outra execução, com entradas relativas corretamente
delimitadas, analisou exatamente a GUI daquele snapshot e seu arquivo de testes usando
declarações reais PySide6/Qt 6.9.2 e Python 3.12.12. Pyright 1.1.403/Node
24.18.0 concluíram a análise basic configurada com status 1: três imports
PyQt6 opcionais não resolvidos e doze classes-base Qt inválidas. O comando
em modo padrão abaixo também informa `obj` possivelmente não definido no
fixture de lifetime existente, totalizando 16 erros. Alternativas de import em
runtime não selecionam estaticamente um provider. Não houve supressão de
diagnósticos; aquele snapshot não passa na tipagem nem qualifica ambos os providers.

O perfil posterior do provider preferido usa as declarações reais do PySide6.
`TYPE_CHECKING` impede a mistura estática com o provider opcional; seu valor em
runtime é falso, mantendo os imports existentes com preferência por PySide6 e
fallback para PyQt6. Os tipos concretos revelaram dez diagnósticos causados pelo
armazenamento `thread` do controlador ocultar o método herdado `QObject.thread()`.
Uma regressão com Qt real reproduziu o `TypeError` antes da correção com `_thread`
privado. O teste confere a afinidade do controlador, worker e objeto QThread
antes de iniciar a CLI real, aguardando a limpeza normal mesmo se uma asserção
falhar. O fixture de lifetime também inicializa sua referência de laço sem
reter um QObject.

Passaram então os 56 testes reais da GUI, incluindo conclusão, cancelamento,
corrida de fechamento e destruição de objetos. Checks estritos novos com GCC,
testes funcionais da CLI e todas as 17 etapas no host passaram com os mesmos
11 skips normais, provider e limites acima. O Pyright basic e o comando padrão
abaixo retornaram zero erros exatamente para GUI e arquivo de testes de fluxo,
sob os limites de tipagem inalterados. Uma execução Python isolada e sem site
packages preservou o diagnóstico de Qt ausente e status 1. Não houve declarações
falsas, diagnósticos ignorados ou aumento de limites. Os 29 diagnósticos do Ruff
e as falhas de formatação continuam. Esse snapshot posterior de 282 arquivos
antecede a atualização apenas documental dos resultados; ainda não qualifica
runtime PyQt6, pacotes nativos, desktop real, sanitização da suíte completa
ou a release de produção.

A alteração posterior da política de subprocessos acrescenta `check=False`
explícito a cinco helpers da GUI e ao filho que falha deliberadamente no
supervisor. Isso corresponde ao padrão existente do Python: códigos de saída
não zero continuam disponíveis para inspeção. Com as mesmas configurações
efetivas do Ruff e diretório de trabalho, a regra focada passa de seis
diagnósticos para zero; o lint completo cai de 29 para 23, com os demais
diagnósticos inalterados. Os dois arquivos ainda falham na formatação.
Checks estritos novos com GCC, testes funcionais da CLI, todos os 56 testes Qt
e 17 etapas no host passam com 11 skips normais; os dois perfis de tipagem do
provider preferido continuam com zero erros. Reproduza os checks separados:

```sh
ruff check --no-cache --select PLW1510 gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff check --no-cache --select F401,RUF059 gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff check --no-cache --select I gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff check --no-cache gui/src/zupt_gui.py tests/test_gui_workflows.py
ruff format --check --no-cache gui/src/zupt_gui.py tests/test_gui_workflows.py
```

O primeiro comando verifica somente a regra de política de saída explícita,
não todo o lint. Registre as regras efetivas com
`ruff check --no-cache --show-settings gui/src/zupt_gui.py`;
o lint completo depende da configuração
selecionada. As falhas anteriores de lint completo e formatação permanecem
registradas; os resultados atuais após organizar imports e formatar estão abaixo.

Em GNU/Linux, com Pyright instalado e declarações PySide6 genuínas visíveis ao
Python selecionado, o comando de tipagem com limites é:

```sh
env MALLOC_ARENA_MAX=1 NODE_OPTIONS='--jitless --max-old-space-size=256 --max-semi-space-size=8' \
  timeout --kill-after=5 120 prlimit --as=1073741824 --cpu=120 \
  --nofile=128 --fsize=1048576 --core=0 taskset -c 0,1 \
  pyright --pythonpath "$(command -v python3)" --pythonversion 3.12 \
  gui/src/zupt_gui.py tests/test_gui_workflows.py
```

Exige GNU `timeout`, `prlimit` e um conjunto permitido de CPUs contendo 0 e 1;
falha da ferramenta não é sucesso. A execução registrada também usou namespace
sem rede, fontes/ferramentas somente leitura e 64 MiB privados em RAM; o
comando acima sozinho não fornece esse isolamento de filesystem/rede.

A execução posterior dos contratos de sondagem acrescenta seis métodos sem
alterar a GUI de produção: a suíte passa a ter 62 métodos, sendo os 56
anteriores e seis testes POSIX que iniciam executáveis Python privados. Cobrem
caminhos ausentes/não executáveis, diagnósticos de saída, banners de versão
somente após sucesso, help nos dois streams após sucesso ou falha, capacidades
em cache sem iniciar outro filho, streams de info e resultados dos comandos.
Os caminhos dos executáveis e os argumentos incluem espaços; os resultados
esperados são literais, não calculados pela GUI testada.

Passam checks novos e estritos com GCC/CLI e todos os 62 métodos na execução
registrada de 18 etapas no host, com 11 skips normais. Um controle positivo
separado passa nos seis testes; cinco mutações privadas da GUI falham nos
métodos esperados. Quatro mudam o tratamento de saída dos subprocessos e uma
aceita indevidamente um comando de versão que falhou. São controles de
sensibilidade, não cinco defeitos descobertos no produto nem prova de segurança.
Os dois perfis reais de tipagem do provider preferido retornam zero erros após
explicitar os argumentos de streams no fixture. A falha inicial de tipagem, os
23 diagnósticos restantes do Ruff e as duas falhas de formatação permanecem
registrados.

A limpeza posterior de nomes sem uso remove `Qt` e `QPixmap` dos imports dos
dois providers e nomeia o status ignorado de Info como `_code`. A seleção do
provider, as chamadas de subprocesso, a exibição de stdout com fallback para
stderr e os bytes dos testes permanecem iguais. O check focado F401/RUF059
passa de três diagnósticos para zero; naquele snapshot o Ruff completo tem 20,
mantendo os demais diagnósticos e configurações. Os dois arquivos ainda falhavam na
formatação. Passam novamente checks estritos novos com GCC/CLI, os mesmos
62 métodos, 18 etapas no host, controle positivo das sondagens e cinco
mutações rejeitadas, com 11 skips normais. Os dois perfis reais de tipagem do
provider preferido retornam zero erros; hashes registrados do conteúdo do
pacote Pyright instalado coincidem antes e depois da análise. Não aprova lint
limpo, auditoria completa do toolchain/dependências ou runtime PyQt6.

A limpeza mecânica seguinte organiza imports e formata os dois arquivos Python
com Ruff 0.16.10. Os checks de imports e formatação passam; o lint completo cai
de 20 para 16 achados, com os demais diagnósticos e configurações efetivas
inalterados. Restam 12 BLE001, dois S110 e dois EXE001; nenhuma política de
exceção, supressão, regra ou permissão de arquivo foi alterada. Uma comparação
restrita da AST preserva todos os campos fora dos imports, registros e
multiplicidade dos imports em cada grupo consecutivo, texto/ordem dos comentários,
cabeçalhos de licença e os 62 métodos de teste ordenados. Esse check não
estabelece efeitos da inicialização dos imports nem a associação dos comentários
às instruções. Passam checks estritos novos com GCC/CLI, 18 etapas no host,
os 62 métodos, o controle positivo de seis sondagens e cinco mutações privadas
rejeitadas, com 11 skips normais da CLI. Os dois perfis de tipagem PySide6
genuínos retornam zero erros, com hashes do pacote Pyright instalado iguais
antes e depois da análise. O lint completo e os demais gates de produção
continuam sem aprovação.

### Fallback PyQt6 e ciclo de vida dos objetos nativos

A execução posterior do fallback reproduziu a ausência de um callback anônimo
de destruição no PyQt6. Medições nativas confirmaram a exclusão do job, thread
e worker. A regressão existente agora usa receptores QObject independentes na
thread da GUI, com slots decorados sem argumentos, e mantém o wrapper do worker
até concluir as asserções. Isso impede que a coleta de lixo mascare a falta da
limpeza nativa; o código de ciclo de vida de produção não mudou.

Os 62 métodos passam com PySide6 6.9.2 e PyQt6 6.9.1/Qt 6.9.2 reais. Os dois
providers passam nos controles positivos e rejeitam cinco mutações de sondagens
e a remoção de `finished -> worker.deleteLater`. Os perfis finais passam em
`all` estrito com GCC, testes funcionais da CLI e checks da GUI, com 18 etapas
PySide/19 PyQt. O `check` completo e estrito com GCC também passou antes de
explicitar a captura de uma variável no fixture, com entradas C/GUI idênticas
e 11 skips normais da CLI. Os dois perfis finais de tipagem do provider
preferido passam. Imports/formatação passam; o lint completo mantém 16 achados.
São resultados offscreen no host, não aprovação de pacotes nativos, VM ou
sanitizadores.

Para reproduzir a suíte do fallback, use uma CLI correspondente e testada e
um Python com PyQt6 genuíno, sem PySide6/shiboken6. Execute estes comandos
de shell POSIX na raiz das fontes, substituindo os caminhos de exemplo:

```sh
PYQT_PYTHON=/absolute/path/to/python-with-PyQt6
export ZUPT_BIN=/absolute/path/to/tested/zupt
export ZUPT_GUI_MODULE="$PWD/gui/src/zupt_gui.py"
export QT_QPA_PLATFORM=offscreen
"$PYQT_PYTHON" -B - <<'PY'
import sys
from importlib import metadata, util
assert all(util.find_spec(name) is None for name in ("PySide6", "shiboken6"))
from PyQt6 import QtCore, QtGui, QtWidgets, sip
print("Python:", sys.executable)
print("PyQt6:", QtCore.PYQT_VERSION_STR, "Qt:", QtCore.qVersion())
print("PyQt6-sip:", metadata.version("PyQt6-sip"), "SIP:", sip.SIP_VERSION_STR)
for module in (QtCore, QtGui, QtWidgets, sip):
    print(module.__name__, module.__file__)
PY
"$PYQT_PYTHON" -B tests/test_gui_workflows.py
"$PYQT_PYTHON" -B tests/test_gui_workflows.py GuiWorkflowTests.test_completed_jobs_release_qobjects_before_window_close
```

Preserve caminhos dos módulos, `GUI binding: PyQt6`, status de saída e marcador
de conclusão normal. A distribuição e o gerador SIP têm versões diferentes;
a execução registrada usou PyQt6-sip 13.10.2 e SIP 6.11.1. Esses comandos não
criam o namespace sem rede/limites do perfil registrado nem executam seus
controles privados de mutação. Falhas, conclusão ausente e skips não aprovam.

Na raiz das fontes, após configurar o runtime PySide6/Qt real do Python
selecionado e compilar ou preparar CLI e GUI de versões correspondentes,
execute somente essas sondagens:

```sh
env PYTHONDONTWRITEBYTECODE=1 \
  ZUPT_BIN=/path/to/staged/bin/zupt \
  ZUPT_GUI_MODULE=/path/to/staged/lib/zupt-gui/zupt_gui.py \
  QT_QPA_PLATFORM=offscreen \
  python3 -B tests/test_gui_workflows.py CliProbeTests
```

Troque os caminhos de exemplo pelos arquivos preparados. O import/bootstrap
ainda exige a CLI executável de versão correspondente. Os seis fixtures
exigem POSIX e um caminho do interpretador utilizável em shebang portátil;
sistemas não suportados informam skips explícitos, não cobertura. O seletor
não executa os demais métodos; a receita executa a suíte completa sem
seletores. Nem os fixtures nem a execução da receita no host aprovam pacotes
nativos, sanitização da suíte completa, runtime PyQt6 ou a release de produção.

### Falhas nas consultas da GUI

Em 2026-10-18, as três consultas síncronas de versão, capacidades e informações
do arquivo mantêm os fallbacks existentes para `OSError`,
`subprocess.SubprocessError` e `UnicodeError`. Erros inesperados de programação
agora se propagam, em vez de virarem silenciosamente metadados ausentes. Os
caminhos de falha esperada não imprimem o conteúdo das exceções. Saídas de
help/info com código não zero, capacidades em cache e limpeza do Worker
mantêm seus contratos anteriores.

Dois métodos de regressão cobrem 18 falhas esperadas e nove erros inesperados.
Os nove casos de erro inesperado primeiro falham na GUI antiga. Com a
correção, a suíte completa tem 64 métodos; os registros anteriores de 62
métodos acima descrevem os snapshots precedentes. Os 64 passam com PySide6
6.9.2 genuíno e, separadamente, PyQt6 6.9.1/Qt 6.9.2, com comparação dos bytes
das fontes instaladas, checks de versão/selftest e os controles existentes de
mutação das sondagens. Um `check` novo e estrito com GCC 14.3.0 e a execução
funcional da CLI passam com 11 skips normais.

Com o ambiente Qt/Python real e os caminhos preparados correspondentes
descritos acima, selecione somente os dois métodos novos com:

```sh
env PYTHONDONTWRITEBYTECODE=1 \
  ZUPT_BIN=/path/to/staged/bin/zupt \
  ZUPT_GUI_MODULE=/path/to/staged/lib/zupt-gui/zupt_gui.py \
  QT_QPA_PLATFORM=offscreen \
  python3 -B tests/test_gui_workflows.py CliQueryFailureTests
```

O seletor não substitui a execução completa de `check-gui`. Os registros
preservam um erro inicial no teste de regressão e uma colisão anterior de
diretórios no supervisor privado; nenhum é contado como teste aprovado.
Formatação e os dois perfis reais de tipagem do provider preferido passam.
O Ruff completo ainda retorna 1: seus 16 diagnósticos caem para 11, sendo
nove handlers de fronteira/limpeza do Worker e dois achados de shebang/modo.
Esses handlers e os modos intencionais 0644 das fontes não mudam; nenhuma
regra foi suprimida. Os resultados offscreen no host não qualificam closure
Guix nativa, desktop real, campanha atual de sanitizadores em VM ou release
de produção. As entradas formais C/Jasmin permanecem iguais às análises
selecionadas registradas separadamente; não foram provadas novamente por
estes testes Python.

### Build dos harnesses de fuzzing e validação da semente

Execute a regressão real dos harnesses e os controles do shell em uma cópia
nova das fontes; depois repita com `CC=clang`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O2 -Werror -Wpedantic -Wshadow -Wcast-align -Wformat=2' \
  test-fuzz-build test-fuzz-build-wrapper
```

O alvo Make primeiro compila a CLI correspondente e fornece seu caminho
absoluto por `FUZZ_TEST_CLI`. Essa CLI apenas cria e testa a semente STORE
sem criptografia. Os dois executáveis de fuzzing continuam compilando seu
próprio núcleo UBSan; objetos separados sem LTO preservam os checks reais
de I/O curto/interrompido, falha na preparação, extração/teste/listagem e
limpeza. Um caminho explícito vazio, ausente, sem permissão de execução ou
que seja diretório falha antes de consultar o compilador. Caminhos relativos
usam o diretório atual, não `PATH`; espaços permanecem parte do nome.
Erros no build, na criação ou no teste da semente interrompem o teste.

Sem `FUZZ_TEST_CLI`, a execução direta ainda compila sua CLI privada:

```sh
env -u FUZZ_TEST_CLI CC=gcc \
  CFLAGS='-O2 -Werror -Wpedantic -Wshadow -Wcast-align -Wformat=2' \
  sh tests/test_fuzz_build.sh
```

Os dez controles sintéticos verificam seleção, argumentos, ordem e
propagação de erros, não correção do C ou cobertura de fuzzing. A regressão
do caminho fornecido falhou antes da mudança e passou depois. Um diagnóstico
isolado com GCC 14.3.0 mediu 5,17 segundos no build duplicado da CLI comum;
é uma observação do custo de build, não benchmark de compressão. A execução
Make padrão usa os flags normais da CLI, sem recompilá-la com os flags extras
`-Wcast-align -Werror` do teste; o perfil estrito acima e o CI preservam ambos
para a CLI completa. Os flags do fuzzing e os limites de recursos não mudam.

### Verificações opcionais do varint Rust

A migração gradual começa em `rust/varint`, uma biblioteca `no_std` separada
que preserva os inteiros canônicos sem sinal em base 128 de `src/zupt_format.c`.
Não tem crates externas, build scripts, alocação, FFI ou código unsafe. Não
verifica arquivos completos e não é ligada à CLI C11 nem instalada nos pacotes.
O `make`, `make check`, a instalação e as receitas de distribuição não invocam
Rust; este primeiro módulo não converte o parser de produção.

Este perfil de desenvolvimento precisa de Rust/Cargo **1.93 ou posterior**,
rustfmt, Clippy, Bash e compilador/linker C com descarte de seções de funções
e dados. Os alvos não baixam ferramentas ou dependências:

```sh
make test-rust-varint
make audit-rust-varint
```

`CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS` e `CARGO` são selecionáveis.
O runner usa um filho privado de `TMPDIR`, orçamento Cargo de dois jobs,
resolução offline/locked e artefatos temporários. Mantenha o diretório pai
confiável. Ferramenta ausente, falha do compilador, do oráculo ou de teste é
erro, não skip. O oráculo liga a unidade real `src/zupt_format.c`; o descarte
de seções não usadas evita um parser C substituto copiado e não importa o
resto da aplicação para o núcleo Rust. O perfil foi executado em GNU/Linux
x86_64 com GCC 14.3.0 e Rust/Cargo 1.93.0, não em todas as plataformas.

Nove testes focados cobrem bytes conhecidos, truncamento, representação longa
inválida, décimo byte inválido, entrada extra, fatias com offset, preservação
da saída insuficiente, limites de bits/round trips determinísticos e entrada
grande. Dois testes de integração verificam a rejeição de protocolo inválido
do helper e **114.721** casos C/Rust por perfil debug/release, incluindo todas
as 65.536 entradas de dois bytes. A seed sintética é `0x5a55505452555354`;
isso não é fuzzing guiado por cobertura. Com sucesso, bytes codificados,
valores e comprimentos consumidos das APIs C de buffer/FILE coincidem. Em
erros, compara-se somente aceitação/rejeição: valores parciais e posição do
stream com erro do C não fazem parte da API Rust `Result`. O encoder Rust
verifica capacidade antes de escrever; o C pressupõe armazenamento suficiente.

Os testes focados/diferenciais, a formatação e o Clippy registrados passam.
Miri, verificador formal Rust, consulta RustSec e fuzzing Rust guiado por
cobertura **não** foram executados neste perfil. Miri não é um verificador
genérico de FFI nativa; qualifique os testes Rust aplicáveis separadamente.
Frama-C continua cobrindo recortes C, e Jasmin seus módulos; nenhum deles
prova este código Rust. Estes resultados não substituem os gates de release
e segurança. A 5.2.10 continua não publicada até aceitar toda a qualificação.

Um `make check` novo e estrito com GCC 14.3.0 e a suíte funcional real da CLI
também passam com `CARGO` apontando para um executável que falha, confirmando
que esse caminho não exige Cargo. Restam 11 skips: Windows nativo, caso
modelado de header bionic/Clang, cinco casos de SDK externo, dispositivo loop
privilegiado, zsh, fish e renderizadores de man page. O perfil Linux sem rede
ou home usa somente ferramentas instaladas e mapeamentos `sh`/`env` fixados
e somente leitura; não é build de derivação Guix ou pacote openSUSE. Faltas
anteriores de headers, interpretadores e ferramentas, e uma falha do launcher
privado, continuam registradas, sem contá-las como aprovação. Código C de
produção e testes preexistentes não mudaram.

### Verificações do codec e da criptografia

Execute os scripts ampliados existentes da CLI separadamente do alvo básico
`check`:

```sh
make -j2 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 all
bash tests/regression.sh ./zupt
sh tests/test_pq.sh ./zupt
bash tests/test_dedup_props.sh ./zupt
```

Em 2026-10-18, uma compilação nova com GCC 14.3.0 estrito e o script funcional
da CLI passaram, seguidos de 22 checks de regressão, 10 de PQ interno e
14 de propriedades dedup, sem falhas em cada suíte. A última inclui rejeição
de adulteração de referência criptografada. Os testes usaram dados e chaves
sintéticos em namespace sem rede, fontes/ferramentas somente leitura,
afinidade a duas CPUs, AS de 1 GiB, NPROC 64 e scratch privado de 128 MiB em
RAM. A afinidade não limita o número de trabalhadores: os valores padrão e
explícitos de threads continuam válidos. A suíte multithread completa não foi
executada nesse perfil porque seu pior caso de scratch pode superar o teto.
`test-all` também chama os gates separados de medição de tempo e exact-size
com ASan; eles não foram executados aqui. A saída informativa de tamanho ou
throughput de scripts antigos não é comparação representativa de desempenho.
O teto de scratch pertence ao ambiente de testes, não é limite de tamanho do
arquivo nem qualificação de pacote.

Para interoperabilidade ML-KEM-768, use OpenSSL 3.5 ou posterior com ML-KEM
habilitado:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-crypto-test-wrappers
CC=gcc bash tests/test_mlkem_fips203.sh
CC=clang bash tests/test_mlkem_fips203.sh
```

O primeiro comando executa 27 controles de supervisores shell, não uma
verificação criptográfica. Seus 15 casos ML-KEM incluem fluxos bem-sucedidos,
skips de versões antigas/providers e dez produtores que retornam erro após
gravar saída plausível.
Exercitam o script real de interoperabilidade com fronteiras sintéticas de
compilador/OpenSSL; uma comparação aparentemente válida não pode anular uma
falha do processo. Os dois comandos diretos compilam o harness C portátil real
separadamente com o compilador selecionado. Cada um compara a geração
determinística da chave pública e os segredos compartilhados nas duas
direções de encapsulamento contra o OpenSSL real. Exija
`Conformance: 3 passed, 0 failed` e status zero. Ferramentas ausentes ou OpenSSL
sem ML-KEM, ou outra implementação de referência, geram `SKIP` explícito,
não evidência de interoperabilidade;
falha na consulta de capacidades ou em subprocesso posterior reprova o teste.
Registre as versões reais do compilador/OpenSSL e a saída completa. Esses
checks finitos não são certificação do algoritmo nem prova de tempo constante.
A execução anterior de 2026-10-16 após a correção passa nos 27 controles, em um novo
`make check` estrito com GCC e na suíte funcional da CLI real. GCC 14.3.0 e
Clang 22.1.8 passam separadamente nas três comparações reais de
interoperabilidade contra OpenSSL 3.5.7, sem skips nessas duas etapas.
A suíte normal mantém seus 11 skips não relacionados.

Uma execução nova em 2026-10-18 com GCC 14.3.0 repete as três comparações
genuínas com OpenSSL 3.5.7, sem falhas ou skips. Não implica novo Clang nem
sanitizadores. `CC` seleciona o driver, mas o script usa seu comando próprio
com `-O2`, não `CFLAGS` do Makefile. Coloque o OpenSSL desejado no `PATH`;
um compilador Guix também exige seu ambiente configurado de headers e
bibliotecas. Essa execução usou o perfil fixado existente somente no namespace
privado, sem alterar perfil de usuário nem instalar ferramentas.

O `check` estrito com Clang 22.1.8 e o script funcional da CLI real foram
repetidos nas fontes atuais em 2026-10-18. Ambos passam com SDK/PQBOX/Jasmin
desativados e 10 skips explícitos: Windows, cinco casos do SDK externo,
dispositivo de loop privilegiado, zsh, fish e renderizadores da página de
manual. Diferentemente do GCC, esta execução exercita o caso modelado do
header bionic. Use uma cópia nova das fontes para cada compilador; mudar `CC`
sobre objetos existentes não recompila todos os objetos em cache.
No ambiente de desenvolvimento configurado para o Clang, execute:

```sh
make -j2 CC=clang CFLAGS='-O2 -g -Werror -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2' WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
bash scripts/test-installed-zupt.sh ./zupt
```

A primeira tentativa isolada não encontrou `libgcc_s.so.1` para um helper
UBSan e falhou; o script da CLI corretamente não foi executado em seguida.
Uma nova tentativa disponibilizou o diretório das bibliotecas de suporte GCC
configurado no Clang instalado somente no ambiente filho. Nenhuma fonte,
flag de aviso, critério ou limite mudou. Configure o compilador e seu runtime
em conjunto; não suprima erros do carregador nem mude caminhos globais de
bibliotecas para considerar um teste aprovado. O resultado inclui os checks
UBSan dos helpers existentes, não `test-all` completo, campanha ASan/LSan na
VM ou qualificação dos pacotes nativos.

O alvo existente `test-ans-allocation` agora também verifica sete estados
do leitor calculados manualmente a partir de um fixture de 16 bytes. Ele
confirma que ler zero bits não antecipa dados de entrada e verifica o
acumulador, a contagem de bits, a posição e o intervalo da fonte durante
reabastecimento com máscara, cauda curta e EOF. Essas verificações comuns
de falha permanecem ativas com `NDEBUG`. Todos os testes anteriores são
preservados, incluindo os 2.312 casos de referência de bits e os 520 casos
de contadores esgotados. O alvo já faz parte de `check`; não exige outro
framework de testes.

O alvo ampliado passou com UBSan sem recuperação e `NDEBUG` no GCC 14.3.0
e Clang 22.1.8 em 2026-10-18. Execuções estritas separadas de `check` e da
CLI, em cópias novas, passaram com 11 skips no GCC e 10 no Clang. Uma mutação
privada de reabastecimento antecipado passou na suíte antiga, mas o teste
ampliado a rejeitou na primeira leitura de zero bits após compilar com
sucesso. Esse controle valida o novo oráculo de estados; não comprova uma
vulnerabilidade existente no decodificador. Para uma execução focada em uma
cópia nova e com o runtime do compilador configurado:

```sh
make -j2 CC=clang CFLAGS='-O1 -g -DNDEBUG -Werror -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -fsanitize=undefined -fno-sanitize-recover=undefined' LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
```

Use `CC=gcc` para o GCC. São regressões nativas limitadas, não prova geral
do leitor, qualificação big-endian, campanha ASan/LSan atual na VM nem
aprovação da release. A implementação e os critérios formais existentes
não mudaram; o mutante privado não é distribuído.

#### Limites diretos da recarga

Em 2026-10-22 UTC, `test-ans-allocation` acrescenta 79.560 estados iniciais:
quatro alinhamentos, prefixos 0/1/7, 0..16 bytes restantes, contagens de bits
0..64 e seis padrões de acumulador. Um laço separado byte a byte calcula o
acumulador, a contagem e a posição esperados. As duas recargas verificam os
cinco campos do leitor e os bytes da origem; a segunda não deve alterar nada.
Intervalos não vazios terminam exatamente no fim da alocação. Alocações de
tamanho zero usam um byte; os testes existentes de fonte NULL esgotada
continuam separados. Padrões sintéticos também verificam a preservação dos
bits acima da contagem; nem todo estado é produzido por um encoder.

Em cópias novas da fonte e com o runtime do compilador configurado, execute:

```sh
make -B -j2 CC=gcc CPPFLAGS='-DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE' \
  CFLAGS='-O2 -g -Werror' LDFLAGS= \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
make -B -j2 CC=gcc CPPFLAGS='-DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE' \
  CFLAGS='-O1 -g -Werror -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation
```

Repita com `CC=clang`. GCC 14.3.0 e Clang 22.1.8 passam nos dois perfis
escalares. `-B` recompila o objeto Huffman com seu tratamento local existente
de alinhamento. Duas mutações privadas sem UB passam na suíte antiga, mas a
nova rejeita ignorar a recarga na contagem 56 e apagar o acumulador em uma
recarga sem efeito com dados pendentes na contagem 57 (status reais de
Make/programa 2/1, não crashes). `check` estrito e smoke funcional da CLI
também passam com 11 skips no GCC e 10 no Clang. Os perfis nativos mantêm
duas CPUs, 1 GiB por processo, scratch de 128 MiB e prazo de 600+5 segundos.

Um fixture finito privado separado amplia a caracterização de sete etapas
com um caso literal na contagem 56 e todas as oito contagens 57..64 com dados
pendentes. Eva no Frama-C 29.0/GCC 14.3.0 alcança 159/197 instruções, valida
as 33 pré-condições, informa zero unknowns/invalids/alarmes e retorna
`main == 0`. Contadores confirmam as oito iterações e o limite adjacente.
O fixture antigo aceita a mutação de preservação; o ampliado tem uma
pré-condição de assertion inválida e é reprovado, apesar do status zero do
analisador. O alvo WP mantido do leitor passa separadamente nas 30 metas
JSON exatas com Z3 4.12.2 reconhecido. Os logs brutos preservam o aviso de
bootstrap do Why3 e uma nota informativa de `memcmp` não suportado no modelo
da libc; isso não é prova da libc.

Esses checks finitos não encerram as 14 obrigações mais amplas dos chamadores
nem provam a recarga geral. ASan/LSan novo na VM está bloqueado pelo kernel
fixado indisponível; outro kernel ou resultado histórico não substitui essa
execução. Não implica novo `test-all` completo, análise Jasmin, benchmark ou
qualificação de pacotes. A documentação final fica fora do snapshot de
runtime. Implementação do codec, API pública e formato permanecem iguais.

Uma execução posterior de pré-requisitos, em 2026-10-22 UTC, usa um kernel
instalado fixado separadamente, pois a imagem anterior não foi recuperada nos
artefatos locais examinados. Passam sete controles genéricos e nove nativos
de isolamento/limites/supervisão com o protocolo exato de 17 registros; os
13 casos sintéticos do parser também passam. O guest tem duas CPUs/2 GiB,
sem NIC, discos ou home do host. Os controles do envelope mantêm 768 MiB,
swap zero, 16 tarefas, scratch de 512 MiB e arquivos de 64 MiB, incluindo
negativos reais de limites, limpeza, timeout e saída excessiva. Passam os
checks de estado da fonte e das entradas/ferramentas nomeadas antes/depois.
A imagem privada mínima contém somente um controlador estático confiável e
sentinelas sintéticos, não Zupt, compilador no guest ou payload de sanitizadores.

A falha inicial do namespace é preservada: o mesmo limite de 16 processos deve
ser aplicado dentro do namespace novo, não ao UID do host já ocupado antes da
criação dele. O aviso de GC do wrapper do linker também fica registrado.
Restaurar a precedência anterior do binutils real elimina esse aviso e produz
os mesmos bytes do controlador; nenhum limite, filtro de avisos ou ajuste de
GC muda. Isso qualifica somente o recorte medido de isolamento. Qualifique
novamente a toolchain do guest e os negativos reais ASan-OOB/LSan-leak/UBSan-
overflow antes de executar os testes do software; passes históricos de
sanitizadores não se transferem para o novo conjunto kernel/entradas. Os gates
formais mais amplos e dos pacotes finais continuam abertos.

Uma execução posterior no snapshot fixo de 294 arquivos qualifica a toolchain
GCC 14.3.0 selecionada no guest e executa o perfil real. Os controles de
redzone/execução limpa ASan e os negativos de overflow de heap, vazamento e
overflow com sinal produzem os diagnósticos esperados e saídas 134/134/1.
Somente depois o perfil compila a CLI atual e executa `make test-asan-run`
e `bash scripts/test-installed-zupt.sh ./zupt_asan`, com detecção de vazamentos.
Passam os round trips de arquivo e disco em arquivo comum, senha incorreta,
entrada corrompida e rejeição de symlink no destino, sem achados dos
sanitizadores. Nenhum dispositivo de disco do host é usado. Passam os alvos
comuns separados `audit-licenses`, `sdk-test` e `sdk-verify-symbols`, além das
três comparações ML-KEM com OpenSSL 3.5.7. Esses resultados do SDK e de
interoperabilidade não são cobertura de sanitizadores.

O protocolo completo tem 25 registros ordenados, incluindo os mesmos 16
controles de isolamento; retornam zero os checks dos processos, coletor,
protocolo e fonte/entradas antes/depois. O alvo mantém 768 MiB, 16 tarefas
e scratch de 512 MiB na VM descartável de duas CPUs/2 GiB. Os testes dos
verificadores privados cobrem 12 métodos de inventário de entradas e oito
métodos sintéticos do gate de diagnósticos; não são testes do produto.
Esta execução não inclui novo `test-all` completo, o teste direto dos
79.560 estados de recarga ANS sob ASan, Qt ou pacotes finais. Também não
encerra as 14 obrigações formais mais amplas. A documentação final fica
fora desse snapshot de runtime; implementação/API/formato não mudam.

Os cinco gates formais existentes também foram repetidos nas fontes atuais
selecionadas em 2026-10-18, com Frama-C 29.0, Why3 1.7.2, Z3 4.12.2,
Jasmin 2026.09.0 e GCC 14.3.0. Todos passam: Eva do logaritmo, Eva do AES com
vetores fixos, WP do leitor, Eva do perfil atual de três fixtures de metadados
e o gate Jasmin de cinco fontes. WP do leitor informa 30 metas JSON exatas
válidas, com 16 resultados Qed e 14 Z3 (34/34 obrigações no console).
Eva dos metadados alcança 138/358 instruções, sem alarmes e com 20
pré-condições válidas. Jasmin inclui 1.026 blocos AES e 1.539 casos CTR4.
Os comandos e limites individuais das provas constam abaixo. As falhas
anteriores de resolução de `cmp` e `libcrypto.so.3` permanecem registradas;
somente o ambiente privado das ferramentas foi corrigido. Confira `cmp`,
binutils, `pkg-config`, runtime libcrypto selecionado e runtime do compilador
antes dos fixtures Jasmin. Esses resultados condicionais não estabelecem
segurança do programa completo, cobertura de todos os streams válidos do
decodificador nem aprovação da release para produção.

Para a [regressão ANS atual](#limites-ans-com-saída-de-tamanho-exato),
execute:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-decode-bounds
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds-wrapper
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds
```

A regressão nativa faz parte de `check`. O alvo Frama-C exige Frama-C 29.0
no `PATH`, ou `FRAMA_C` definido com o caminho do executável, e chama
`tests/test_frama_ans_decode_bounds.sh`. Ele é separado do alvo básico
`check` e obrigatório antes de uma release. Ferramentas ausentes, erros de
execução, avisos da análise, alarmes ou pré-condições não comprovadas fazem
o gate falhar; não são skips. O parser exige seis testemunhos exatos dos
fixtures e o resumo registrado de 63 pré-condições e zero alarmes, rejeitando
resultados ausentes, duplicados, conflitantes ou podados.
GNU awk e grep devem estar no `PATH`.

`test-frama-ans-decode-bounds-wrapper` faz parte de `check`; seus 82 controles
atuais estão descritos no
[perfil atual](#limites-ans-com-saída-de-tamanho-exato).
O wrapper anterior tinha 57 controles, preservava os 56 casos anteriores e
rejeitava o relatório antigo de dois fixtures, com 121/343 instruções e
14 pré-condições. Oito fixtures anteriores de aviso,
erro, falha e timeout com perfil completo reproduziram aprovações falsas antes
da correção do scanner sem distinção de caixa. Um controle positivo preserva
a nota informativa de termo ACSL `memset` não suportado. Erros 2/127 do scanner
devem causar falha tanto na detecção de diagnósticos quanto na verificação
do marcador PASS; não equivalem à ausência de correspondência. Os controles
não analisam o codec. A extensão anterior do gate de metadados manteve suas
opções ao acrescentar o terceiro fixture. Registre a versão do pré-processador
junto à do Frama-C; a execução preservada sem avisos usou GCC 14.3.0.
No GNU Guix, um ambiente temporário com versões fixadas permite executar os
alvos atuais:

```sh
guix shell --pure frama-c@29.0 gcc-toolchain@14 make bash-minimal coreutils gawk grep -- \
  bash -c 'make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-decode-bounds-wrapper test-frama-ans-decode-bounds'
```

Use uma revisão conhecida dos canais Guix e guarde seu commit no registro da
auditoria. O comando não instala Frama-C no perfil do usuário. O pré-processador
GCC 16 emite avisos de redefinição de macros com essa versão do Frama-C;
o gate rejeita essa execução, sem transformar seu resumo de zero alarmes em
aprovação completa.

Os números de metadados abaixo descrevem snapshots anteriores. Os comandos
acima executam o [perfil atual](#limites-ans-com-saída-de-tamanho-exato).

A execução Eva anterior com dois fixtures passou com zero alarmes e 14/14
pré-condições em 121/343 instruções alcançadas. A execução histórica com três
fixtures acrescentou um fixture de 33 bytes com pistas `{1,0,0,1}` e somente
um byte de payload.
A quarta pista deve ser rejeitada depois que a primeira consumir esse byte,
preservando o consumo `SIZE_MAX` e quatro bytes de saída inicializados com
`0xa5`. Naquele snapshot, o decodificador inalterado alcançou 138/358
instruções em 5/76 funções, com zero alarmes e 20/20 pré-condições válidas sob
as mesmas opções `slevel=16`, `plevel=512`. O corpo do
decodificador retorna `VVA_ERR_CORRUPT` e `main` retorna 0. A libc do Frama-C
modela os asserts C como pré-condições de `__FC_assert`; a contagem de
Assertions ACSL é zero. O resultado cobre esses fixtures no modelo de máquina
`gcc_x86_64` do script; não verifica a tabela de decodificação alocada, o
caminho de quatro pistas nem todas as entradas. O script converte `_Alignof`
para o operador GCC
equivalente `__alignof__`, pois Frama-C 29.0 não interpreta a grafia C11.
Guarde toda a saída da análise ao reproduzir a verificação.

O teste nativo anterior com três fixtures passou com UBSan escalar em GCC
14.3.0 e Clang 22.1.8 pelas receitas reais do Makefile. A receita histórica
standalone abaixo exclui o caminho de cópia de matches de produção. Para os
fixtures atuais, use a [receita atual](#limites-ans-com-saída-de-tamanho-exato),
com uma cópia nova das fontes por compilador e configuração:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  CPPFLAGS='-DVV_DISABLE_SIMD=1 -DVV_ANS_STANDALONE' \
  CFLAGS='-O1 -g -Werror -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -DNDEBUG -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' test-ans-decode-bounds
```

Repita com `CC=clang` na outra árvore. O alvo reativa os asserts com `-UNDEBUG`.
Clang mantém a exceção de alinhamento de casts já existente, local ao objeto
ANS; nenhuma supressão nova ou global foi acrescentada. Uma tentativa separada
com Clang direto estrito falha com 16 diagnósticos existentes de alinhamento e
não é um perfil aprovado. O runtime UBSan isolado do Clang exigiu a biblioteca
GCC fixada; a falha inicial do loader permanece registrada separadamente.

Controles privados de alocação no linker verificam zero tentativas de alocar
a tabela nos três fixtures. Alterar somente o guard das pistas para comparar
com o orçamento original de payload mantém os dois fixtures anteriores
aprovados, mas o caso novo alcança uma tentativa de alocação e retorna `NOMEM`.
O controle retorna NULL nesse ponto para impedir leituras inválidas das pistas;
não executa uma decodificação insegura nem comprova o decodificador completo.
`check` estrito novo com GCC e os testes funcionais da CLI real passam no
snapshot registrado de 283 arquivos antes da atualização documental, mantendo
11 skips normais. Código C de produção, API e formato permanecem inalterados.

Um experimento
privado separado de fluxo válido alcançou esses caminhos posteriores, mas
manteve 15 alarmes e cinco pré-condições desconhecidas; a execução de maior
precisão não concluiu em 120 segundos. Esse experimento não faz parte do
gate incluído e não aprova o uso em produção.

Em 2026-10-10, outro executável Frama-C 29.0 e o fixture sintético inalterado
produziram novamente o resultado completo de 15 alarmes e cinco pré-condições
desconhecidas com `slevel=16`, `plevel=512`. Uma execução separada variou apenas
`plevel` para 4096, sem a opção anterior de desenrolamento global dos laços.
Sob um perfil diagnóstico menor, somente em RAM (prazo de 25 segundos para
o analisador, 30 segundos externos, espaço de endereçamento de 768 MiB para
o analisador e limite de 1 MiB para o arquivo de log), terminou com status
153 no limite do log, antes do resumo final. Os bytes e hashes exatos dos
logs capturados foram conferidos; o resultado incompleto é uma falha, não
evidência de menos alarmes. Nenhuma execução altera o decodificador, os
asserts ou o modelo de falha de alocação, nem substitui o experimento anterior
em VM.

#### Consumo do leitor ANS e check WP condicional

O leitor compartilhado conta somente bits armazenados após esgotar a pista,
preservando a extensão implícita por zeros do formato. O contador antigo
ficava negativo na primeira leitura positiva após esgotamento. Uma regressão
direta e limitada reproduziu esse estado; não se afirma um exploit de entrada
gigante na CLI. Consumo do fluxo simples e gramática de codificação não mudam.

Selecione o ambiente isolado e qualquer caminho privado de `WHY3CONFIG`
antes de detectar o solver ou executar os comandos Make abaixo.

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-reader-wrapper
why3 config detect
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-reader
```

Use Frama-C 29.0, Python 3, pré-processador GCC 14 e Z3 4.12.2 reconhecido
pelo Why3. Configure o solver em ambiente isolado, sem substituir bibliotecas
do host. Para configuração privada, defina `WHY3CONFIG` com seu caminho antes
de detectar o solver ou executar Make. `FRAMA_C` e `PYTHON` selecionam os executáveis.
O gate existente também aceita Z3 4.13.0. Uma execução real posterior passou
com essa versão, mas Why3 1.7.2 a informou como não reconhecida na detecção.
Preserve o aviso; aceitação pelo gate não qualifica um solver reconhecido.
Se definir `WHY3CONFIG`, crie e confira essa configuração antes de **qualquer**
invocação Frama-C, inclusive somente Eva: a inicialização WP ainda pode lê-la.
A repetição posterior documentada abaixo usa novamente Z3 4.12.2 reconhecido;
o aviso de detecção do 4.13.0 pertence à execução anterior, não ao novo perfil.
O script usa
`gcc_x86_64`, o mesmo pré-processamento standalone/escalar do check de
metadados, `-wp -wp-rte -wp-fct ans_br_init,ans_br_take -wp-prover z3 -wp-par 1
-wp-timeout 2` e relatório WP bruto. Obrigações desconhecidas, avisos,
ferramentas ausentes, timeouts e resultados conflitantes/duplicados causam
falha, mesmo quando o analisador retorna 0.

A execução real comprova 30 obrigações JSON exatas sem smoke: 12 da
inicialização e 18 da extração. O resumo 34/34 inclui também terminação e
inalcançabilidade das duas funções. A inicialização exige contexto gravável,
zera acumulador, contador e posição e guarda o ponteiro/tamanho fornecidos,
sem ler a fonte. A extração confere saturação do contador, escritas restritas
a `a`/`n`, shifts e condições selecionadas de erros de execução, supondo
`a`/`n` válidos e inicializados, contador em 0..64 e largura em 0..32. Isso não
comprova recarga, todos os chamadores, inicialização da tabela, validação do
formato ou o decodificador inteiro. Os 40 controles simulados testam somente o
tratamento do relatório. Frama-C 29 emite tempos zero como `0.`; o parser
adapta apenas essa representação numérica fora de strings, rejeita chaves
duplicadas/valores não finitos e imprime o relatório inalterado com seu hash.
Preserve stdout/stderr completos, hashes das ferramentas e status de saída.

GCC 14.3.0 e Clang 22.1.8 nativos passam em 2.312 configurações do leitor
(quatro alinhamentos, tamanhos 0..16, larguras 0..32 e larguras mistas),
incluindo reinicialização de contexto preenchido com estado antigo inválido,
160 leituras cada, consumos do fluxo simples 10/12 e saídas ANS4 de 1..4096.
Sufixos da saída, retornos e limpeza de alocações são conferidos. UBSan
escalar focado também passa com ambos os compiladores em `-O1
-fsanitize=undefined -fno-sanitize-recover=undefined`. Repetição ASan/vazamentos
em VM descartável na fonte editada agora passa com Clang 22.1.8 nos modos
scalar e AVX2. O complemento focado abaixo não valida CLI ou fuzz completos.

#### Reproduzir os testes focados ANS com sanitizadores

A execução privada de 10/10/2026 fixou 255 arquivos de fonte e compilou
novamente a implementação ANS real incluída por `tests/test_ans_allocation.c`,
além de um objeto Huffman instrumentado. As duas execuções passaram nos
checks de alocação, leitor/reinicialização, contadores esgotados, saídas
1..4096 e logaritmo. Controles negativos ASan, LSan e UBSan precisaram falhar
separadamente com os diagnósticos esperados. Testes C de tamanho exato passaram
81/0 e 1.024 casos de bijeção BCJ; round trips L5/L9 usaram a CLI comum.

Para reprodução focada, use uma VM Linux x86_64 descartável e execute este
bloco Bash na raiz da fonte. No fish, entre primeiro em `bash`. `CC` indica
um único executável de compilador com runtimes dos sanitizadores funcionais;
diretórios de recursos e caminhos de runtime dos compiladores Guix exigem
configuração separada. A passagem AVX2 exige que a VM exponha AVX2 e falha
se não houver suporte; ausência da instrução não conta como cobertura aprovada.
Objetos temporários evitam misturar objetos instrumentados com os do projeto.

```bash
(
set -eu
audit_tmp=$(mktemp -d)
trap 'rm -f -- "$audit_tmp/huffman.o" "$audit_tmp/ans-test"; rmdir -- "$audit_tmp"' EXIT
audit_cc=${CC:-cc}
audit_flags=(-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror '-fsanitize=address,undefined' -fno-sanitize-recover=all -fno-omit-frame-pointer)
audit_cast=()
case "$("$audit_cc" --version)" in *clang*) audit_cast=(-Wno-cast-align) ;; esac
for audit_mode in scalar avx2; do
    audit_simd=(-DVV_DISABLE_SIMD=1)
    if test "$audit_mode" = avx2; then
        grep -qiw avx2 /proc/cpuinfo
        audit_simd=(-mavx2)
    fi
    "$audit_cc" "${audit_flags[@]}" "${audit_simd[@]}" -D_DEFAULT_SOURCE -Iinclude -Isrc -c src/vv_huffman.c -o "$audit_tmp/huffman.o"
    "$audit_cc" "${audit_flags[@]}" "${audit_simd[@]}" "${audit_cast[@]}" -D_DEFAULT_SOURCE -Iinclude -Isrc tests/test_ans_allocation.c "$audit_tmp/huffman.o" -o "$audit_tmp/ans-test"
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$audit_tmp/ans-test"
done
)
```

A VM medida manteve 2 CPUs/2 GiB, cgroup do alvo de 768 MiB/16 tarefas e
512 MiB temporários, sem NIC, home, discos ou sockets do host. O alvo focado
final atingiu pico de 235.048.960 bytes, sem eventos inesperados de recursos
ou descendentes sobreviventes. Os comandos acima não configuram esses
controles da VM nem executam os harnesses separados de controles negativos
ou tamanho exato. Não comprovam correção completa do decoder, ausência de
vulnerabilidades ou prontidão da release; os gates formais de chamadores,
tabela/recarga e pacotes finais continuam pendentes. Alterações posteriores
da documentação ficaram fora do snapshot da VM.

A recarga agora testa `l - p >= 8` sob o invariante existente `p <= l`,
em vez de somar oito a `p`. Outros 520 casos começam com `p == l`, fonte
NULL, oito posições comuns/próximas de `SIZE_MAX` e todos os contadores em
0..64. Conferem que a recarga não acessa a fonte e preserva os campos;
depois verificam extensão por zeros e contagens exatas para larguras 0..32.
São contadores sintéticos, não buffers gigantes alocados. O predicado antigo
falha com diagnóstico UBSan sem recuperação de offset sobre ponteiro NULL;
ambos os compiladores passam com a correção. O prefixo de metadados ANS4 já
limita os tamanhos reais das pistas longe desse overflow; isso não comprova
vulnerabilidade alcançável em arquivos nem altera o formato. O `make check`
nativo completo e estrito também passa após essa mudança com GCC 14.3.0 e
Clang 22.1.8, SDK/PQBOX/Jasmin desativados e skips de plataformas/ferramentas
indisponíveis preservados. As duas tentativas iniciais em paralelo atingiram
o prazo de 125 segundos (124); execuções sequenciais passam sem aumentar
prazos ou limites de CPU/memória. Os logs brutos completos preservam tanto
essas falhas quanto as execuções posteriores aprovadas.

O diagnóstico Eva privado de fluxo válido de 4096 bytes agora usa anotação
local para desenrolar os 256 símbolos e
`-eva-domains-function gauges:vva_decode4_impl`, preservando slevel 16,
plevel 512, oráculo de bytes e modelo de alocação com possível falha.
Após mudar o guard da recarga, alcança 349/496 instruções e registra zero
alarmes de memória, mas 14 das 51 pré-condições continuam desconhecidas
(37 válidas): quatro limites de largura e quatro limites do contador nas
quatro chamadas a `ans_br_take`, uma condição do intervalo de origem do
`memcpy` e cinco assertions do fixture sobre falha de alocação, consumo e
bytes decodificados. O snapshot anterior, somente com anotações, tinha
38 válidas/13 desconhecidas. Esse diagnóstico condicional não é um gate de
release aprovado. Somente as anotações mantêm o C executável pré-processado
igual; o guard é uma mudança executável. Uma tentativa WP mais ampla da recarga expirou e registrou
avisos de ponteiros incompatíveis no modelo de memória; seus contratos
experimentais não foram mantidos como garantias comprovadas.

Uma entrada Eva separada em `check_reader_exhausted_positions` também está
pendente. Com slevel 16/plevel 512 e gauges restrito à recarga, combina estados
distintos dos contadores e registra um alarme de memória certo e uma
pré-condição inválida (nove válidas). Aumentar somente o slevel dessa entrada
para 20000 atinge o prazo de 25 segundos antes do resumo. Nenhuma execução
passa no check; regressões nativas e raciocínio manual dos invariantes não
substituem prova genérica da recarga.

Um diagnóstico WP separado de 2026-10-13 analisou o C executável inalterado
com contrato de estado esgotado (`p == l`), permitindo ponteiro de entrada
nulo ou ilegível, sem limite adicional de comprimento. Qed demonstrou 44/78
metas; selecionar o Z3 4.12.2 já admitido demonstrou as mesmas 78/78 metas.
Persistem três avisos: cláusulas explícitas de término/saída ausentes para
`memcpy` e dois casts de ponteiro incompatíveis no modelo Typed. A admissão
estrita permanece com status 1. Isso registra avanço somente nesse caso;
admissão sem avisos, recarga geral e obrigações dos chamadores continuam abertas.

Em 2026-10-19, um novo contrato privado admitiu leitor somente para leitura,
com todos os campos inicializados, `0 <= n <= 64` e `p == l`, sem validade da
entrada, separação ou teto de comprimento. O invariante de laço `p == l`,
`loop assigns \nothing` e variante constante descrevem o corpo inalcançável.
WP+RTE levou esse novo diagnóstico de 40/54 a 62/62 metas com Z3 4.12.2
reconhecido, preservando os três avisos de `memcpy`/Typed. A admissão estrita
continua falhando. Acrescentar somente a pós-condição falsa `a == 0` deixa
exatamente essa meta adicional sem prova (62/63). Restaurar o guard antigo
`p + 8 <= l` em outro controle privado deixa 25/54 metas sem prova, incluindo
validade da fonte. Relatórios brutos e identidades exatas das metas ficam
preservados localmente; esses números não são o inventário histórico de 78
metas. Nem o contrato nem suas anotações de laço são publicados como garantias.

O alvo nativo mantido agora acrescenta 9.360 estados sintéticos de preservação:
oito posições, 65 contagens de bits, seis padrões de acumulador e três fontes
(NULL, um byte local e alias do próprio leitor). Compara os cinco campos após
a recarga. Duas mutações privadas zeram um acumulador não nulo em `SIZE_MAX`
com fonte NULL ou outro cuja fonte é alias do leitor. Ambas passam no teste
antigo e falham no novo check; esses controles usam GCC sem sanitizadores.
GCC 14.3.0 e Clang 22.1.8 estritos passam com o codec inalterado em `-O2`,
inclusive em execuções separadas de UBSan sem recuperação cujos controles
reais de overflow falham como exigido. É cobertura de preservação de campos,
não prova de todo acesso possível à memória nem novo resultado ASan/LSan em
VM. O C executável do codec, API e formato não mudam. Reproduza o novo perfil
comum em checkout novo contendo somente fonte:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O2 -g -Werror' test-ans-allocation
```

Repita com `CC=clang` em outro checkout novo. Para o perfil UBSan medido,
acrescente `-fsanitize=undefined -fno-sanitize-recover=undefined` a `CFLAGS`
e passe esses mesmos dois flags em `LDFLAGS`. Use ambiente completo de
compilador/runtime, não um caminho de compilador que deixou de existir.

A repetição posterior com sanitizadores GCC 14.3.0, em 2026-10-19, usou fonte
fixa de 291 arquivos em VM descartável. Cópias novas e independentes compilaram
o alvo real `test-ans-allocation` em `-O2`, com ASan/UBSan, diagnósticos fatais
e detecção de vazamentos. O perfil com SIMD do projeto desativado confere os
três macros de recurso em zero; o perfil AVX2 exige AVX2 no guest e confere os
macros AVX2 do compilador e do projeto. Cada um passa nos 9.360 estados de
preservação e testes mantidos. Isso não afirma desativação da vetorização de
libc/compilador nem cobertura de toda instrução SIMD.

Os probes originais de recursos/isolamento e três controles reais de falha dos
sanitizadores passam antes do produto. Passam os 23 registros ordenados e os
status separados de VM/coletor/integridade/protocolo. Os alvos escalar/AVX2
atingem picos de 236.113.920/235.483.136 bytes, sem eventos OOM/limite de PIDs
ou filhos remanescentes. Permanecem 2 CPUs/2 GiB na VM e 768 MiB/16 tarefas/
512 MiB temporários no alvo, sem rede, home, discos ou sockets do host. Os 22
métodos de regressão do novo perfil privado rejeitam etapas ausentes, fora de
ordem, duplicadas e status externos de falha. São testes do supervisor, não do
codec. Esta repetição não executa novamente Clang ASan, suítes completas CLI/
SDK/fuzz, Frama-C/Jasmin ou pacotes finais. Não resolve os três avisos formais
acima nem aprova produção.

Um diagnóstico adicional do Frama-C 29 isolou as cláusulas ausentes da libc.
Uma cópia privada de seu `string.h` original acrescenta apenas
`terminates \true;` e `exits \false;` ao contrato existente de `memcpy`,
preservando validade, separação, efeitos, conteúdo copiado e valor de retorno.
São premissas explícitas da biblioteca externa, não prova da implementação da
libc. O C analisado, alvo, modelo Typed, Z3 4.12.2 reconhecido, limites do
solver e política estrita de avisos permanecem iguais. O aviso de especificação
ausente desaparece; passam as mesmas 62 identidades de metas positivas. Uma
pós-condição falsa correspondente acrescenta exatamente uma meta sem prova
(62/63). Persistem dois avisos de conversão de ponteiros do Typed, portanto a
admissão estrita continua reprovada. O resultado com o header original mantém
três avisos. Nem o header privado nem as anotações diagnósticas são distribuídos
como contrato provado. Não houve modo de cast inseguro, supressão de avisos
ou reescrita do codec.

O experimento privado seguinte substitui somente a carga `memcpy` de oito bytes
por oito leituras escalares e shifts explícitos unsigned de 64 bits. No alvo
little-endian fixado, o Frama-C 29 valida 63 metas JSON exatas, com 65/65
resultados no console e sem avisos da análise, usando tanto o header explícito
quanto o original da libc. As pré-condições do leitor esgotado não mudam:
não há nova premissa de fonte legível, separação ou comprimento. A pós-condição
falsa correspondente deixa somente sua meta adicional sem prova; o guard
sujeito a overflow deixa 18 metas sem prova. Timeouts não são contraexemplos
produzidos pelo solver.

Um contrato separado de recarga em bloco exige leitor inicializado e gravável,
`0 <= n <= 56`, `p <= l`, oito bytes restantes legíveis e inicializados e
separação entre esses bytes e o leitor. Entre os experimentos de estratégia,
o C da candidata privada e seu contrato permanecem inalterados;
o Frama-C 29/Z3 4.12.2 reconhecido valida as 64 obrigações originais. Táticas
existentes de shift e divisão explícita em três casos no zero fecham o limite
restante do deslocamento da máscara; os três filhos são Qed Valid. O negativo
correspondente deixa sem prova apenas sua pós-condição falsa adicional (64/65).
As alternativas anteriores que falharam permanecem registradas; status zero do
processo sozinho não aprova a prova. As pós-condições cobrem avanços e limites
exatos de `p`/`n` e preservação de `s`/`l`, não igualdade funcional do acumulador.
Essas pré-condições excluem o fallback e não comprovam o leitor geral nem seus
chamadores.

Oito execuções reais GCC 14.3.0/Clang 22.1.8 de referência/alternativa, comuns/
UBSan, passam no alvo mantido `test-ans-allocation` anterior, incluindo as 2.312
configurações do leitor, 9.360 estados de preservação e 288 chamadas de lanes
mistas. O Clang emite objetos sem símbolos de depuração idênticos; o GCC mantém
a seção de texto de 30.168 bytes, mas altera instruções e tamanhos de algumas
funções. Um benchmark ANS privado posterior, em processo, usa esses objetos GCC
preservados, sete conjuntos sintéticos aceitos e 31 lotes pareados alternados
por conjunto e API. Cinco entradas recusadas pelo encoder ficam sem medição.
Para entradas com vários símbolos, construção e reset das tabelas entram em
cada decode; codificação da entrada e alocação do workspace reutilizável ficam
fora. Entradas constantes não passam pelas tabelas nem pela recarga.
Há ganhos e perdas, sem benefício consistente; médias dos lotes não são
distribuições de latência por chamada nem comparação com Zstd. Essas entradas,
táticas e benchmarks diagnósticos continuam privados, não são novos alvos de
auditoria distribuídos. Use os comandos mantidos anteriores para testar o
produto; eles não reproduzem esse experimento privado de contrato.
A alternativa não integra o produto: o decoder original e seus dois avisos
Typed permanecem inalterados.
Não é prova da recarga geral, qualificação de outros endiannesses, aceitação
dos pacotes finais ou aprovação para produção.

O próximo teste mantido acrescenta 288 chamadas ANS4 com lanes mistas ao mesmo
alvo `test-ans-allocation`, já incluído em `make check`. A entrada sintética
aceita tem lanes de 0/1/8/9 bytes, não é arquivo produzido pelo encoder.
Uma expectativa literal de 36 bytes, derivada independentemente, verifica
todas as saídas de 1..36 bytes, quatro alinhamentos de fonte/saída e as APIs
comum/workspace. Fonte e destino terminam nos limites reais das alocações;
confere canários de prefixo, consumo de 50 bytes e contagens de alocação do
decoder 1/0. Um workspace alinhado é inicializado uma vez e reutilizado em
144 chamadas. As lanes longas de zeros exercitam transições de EOF, não todos
os padrões de bits da recarga nem reutilização com tabelas de frequência
diferentes. Duas mutações privadas de span/bits parciais passam no alvo antigo
e falham nos checks novos nos bytes previstos.

Use o comando `make ... test-ans-allocation` anterior em checkouts novos GCC/
Clang comuns e UBSan separados. Os quatro perfis nativos estritos passam.
Perfis novos GCC ASan/LSan/UBSan escalar e AVX2 em VM também passam nos casos
novos e 9.360 estados preservados, após rejeitar controles reais de falha dos
sanitizadores. Os limites originais de 2 CPUs/2 GiB da VM e 768 MiB/16 tarefas
do alvo permanecem inalterados.

A mesma fonte fixa passa depois nos alvos reais `test-all` estritos e, em
separado, `audit-licenses sdk-test sdk-verify-symbols` com GCC 14.3.0 e Clang
22.1.8. Cada execução tem 24 registros ordenados e status zero de processo,
coletor, integridade e protocolo; permanecem 15/14 skips explícitos,
respectivamente. Integrações externas de SDK/PQ, Windows nativo, dispositivos
loop privilegiados e shells/renderizadores ausentes ficam sem cobertura.
O check bionic do Clang modela sintaxe de header, não qualifica Android.
As suítes usam `WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0`; os checks do SDK interno
rodam separadamente. Incluem testes focados de sanitizadores, mas não são
globalmente instrumentadas. Os artefatos antigos do Clang estão ausentes;
um novo provedor instalado explicitamente fixado passa em smoke, controles
e suíte completa próprios, sem downloads ou limites maiores. Edições posteriores
da documentação ficam fora do snapshot do produto. Nem os resultados nem a
regressão nova resolvem os dois avisos Typed, as obrigações formais mais amplas
ou os gates dos pacotes finais da release.

Dentro de VM descartável com toolchain completo GCC 14.3.0 e sanitizadores,
use cópia nova da fonte revisada para cada build. Reproduza o alvo escalar:

```sh
env ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CPPFLAGS='-DVV_DISABLE_SIMD=1' \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all' \
  test-ans-allocation
```

Para AVX2, use outra cópia nova da fonte, omita `CPPFLAGS` e acrescente
`-mavx2` a `CFLAGS`; exija guest com AVX2, sem aceitar skip. Reaproveitar a
primeira árvore pode manter objeto compilado com flags diferentes. Esses
comandos executam o alvo, não o envelope privado da VM ou seus controles de
admissão. Não remova limites dos sanitizadores no host nem use swap ativo.

Em checkout novo contendo somente fonte, reproduza o perfil UBSan anterior com
GCC e repita em outro checkout novo com `CC=clang`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O1 -Werror -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined' test-ans-allocation
```

A execução Eva anterior do fluxo válido após saturar o contador registrou três
alarmes (dois de inicialização da tabela, um de limites da saída), 37
pré-condições válidas e 13 desconhecidas, com 349/496 instruções alcançadas.
Os contratos do auxiliar tornam a análise condicional a obrigações pendentes
dos chamadores. O perfil de precisão mais novo descrito acima resolve esses
alarmes, mas não as pré-condições desconhecidas. Uma tentativa separada de
precisão restrita à tabela expirou
em 25 segundos. Ambas preservam fixture, oráculo, modelo malloc e limites;
as análises anteriores que falharam continuam registradas. Não resulta em
prova do decodificador completo nem aprovação da release.

Um diagnóstico privado separado de largura da tabela leu o header real de
dois símbolos com frequências 1/4095, validou-o e chamou `build_dec_direct`.
Com slevel 16, slevel 64 no auxiliar e plevel 512, comprovou duas das quatro
assertions e as oito pré-condições, mas registrou dois alarmes aritméticos
e manteve desconhecidos o sucesso da construção da tabela e sua largura
(139/228 instruções alcançadas em 5/75 funções). A repetição com slevel 8500
somente na tabela atingiu o prazo inalterado de 25 segundos sem resumo
completo. Nenhuma execução passa no gate ou confirma bug em execução;
não foram presumidas especificações da tabela nem limites desejados.
Esses resultados não resolvem as quatro obrigações de largura do chamador.

#### Limites do logaritmo ANS

`tests/test_ans_log_bounds.c` inclui o núcleo escalar real e chama seu
`ilog2` inalterado duas vezes pelo modelo de intervalo unsigned do Frama-C:
todos os valores `uint32_t` e, separadamente, todos os valores em 0..4096.
Um check do pré-processador exige `unsigned int` de 32 bits; os limites
desejados são assertions, não hipóteses ou especificação que substitui o
auxiliar. Com Frama-C 29.0, GCC 14.3.0, GNU awk e `gcc_x86_64`, execute:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-ans-allocation test-frama-ans-log-bounds-wrapper
FRAMA_C=frama-c make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-ans-log-bounds
```

O gate usa pré-processamento escalar/standalone, slevel 16, slevel 64
restrito ao auxiliar e plevel 512, com avisos de overflow signed/unsigned.
Exige os dois corpos alcançados e retornando, domínio completo da entrada,
intervalos de resultado 0..31 e 0..12, 2/2 assertions e 2/2 pré-condições dos
intervalos válidas, zero avisos/alarmes e 15/15 instruções em 2/75 funções.
Perfis inesperados, duplicados ou incompletos e falhas das ferramentas são
erros; preserve saída bruta e status. A análise real passou com limite de
25 segundos/768 MiB, afinidade em duas CPUs e sem rede ou acesso ao home.
Os 60 controles simulados separados testam o gate, não a correção do C.
Rejeitam diagnósticos de aviso/erro em maiúsculas ou caixa mista mesmo quando
o restante do relatório contém o perfil completo esperado.

Uma nova execução em 2026-10-16 com Frama-C 29.0 e GCC 14.3.0 x86_64 fixados
passou neste gate Eva real e no gate separado de metadados malformados:
respectivamente 2/2 assertions mais 2/2 pré-condições em 15/15 instruções,
e 14/14 pré-condições em 121/343 instruções. Ambos informaram zero avisos/alarmes
e mantiveram os checks existentes de resultados exatos. O log dos metadados
também mantém uma nota informativa de termo ACSL `memset` não suportado. Isso não encerra as obrigações
dos chamadores de fluxos válidos, refill, tabela ou decodificador completo.

A regressão nativa de alocação acrescenta 4.195 checks com resultados
esperados: zero, `UINT32_MAX`, as 32 potências de dois e seus vizinhos,
e todos os valores em 0..4096. GCC 14.3.0 e Clang 22.1.8 passam com UBSan
escalar sem recuperação. Uma mutação privada que retorna zero falha no novo
check. Nenhum algoritmo de execução mudou. A análise de limites não prova
a função exata do logaritmo, equivalência da tabela, limites de frequências
dos chamadores ou decodificador completo; as 14 pré-condições desconhecidas
do perfil de fluxo válido continuam pendentes.

#### AES: vetores conhecidos e gate Eva

O fixture nativo usa `src/zupt_aes256.c` diretamente, mesmo quando o build
ao redor habilita `WITH_JASMIN=1`. Ele confere os 64 bytes de ciphertext dos
quatro vetores fixos AES-256 ECB de
[NIST SP 800-38A F.1.5, página impressa 26](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf),
com uma chave fixa e buffers válidos separados. Não exercita o dispatch da
assembly em execução. Os alvos nativo e de controles do supervisor fazem
parte de `check`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-aes-nist test-frama-aes-nist-wrapper
```

Para o perfil UBSan estrito, execute com GCC e repita com `CC=clang`:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC=gcc \
  CFLAGS='-O1 -g -Werror -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -DNDEBUG -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined' test-aes-nist
```

As execuções registradas GCC 14/Clang 22 passaram com `-DNDEBUG` do chamador;
o alvo Make coloca `-UNDEBUG` após os flags do compilador, mantendo todos os
asserts ativos. O fixture também rejeita um build direto que deixe `NDEBUG`
definido. Esse alvo recompila a fonte C portátil, sem reutilizar objetos
existentes. O controle de compilação com asserts desabilitados retornou 0
antes desse guard do fixture e 1 depois; é um controle da qualidade do teste,
não uma correção do produto.

O gate Eva separado é obrigatório em `release-check`, não no `check` básico.
Reproduza seu perfil fixado `gcc_x86_64` com Frama-C **29.0**, GCC **14.3.0**,
GNU awk (`awk` no `PATH`) e um executável de prazo compatível com GNU:

```sh
FRAMA_C=frama-c FRAMA_CPP_CC=gcc FRAMA_TIMEOUT=timeout \
  make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-aes-nist
```

Defina `FRAMA_C` e `FRAMA_CPP_CC` com caminhos alternativos quando necessário;
as versões são verificadas, não deduzidas dos nomes. Use
`FRAMA_TIMEOUT=gtimeout` onde GNU coreutils instala esse nome. A análise real
tem prazo de 120 segundos e cinco segundos de tolerância antes de matar o
processo. Ferramentas ausentes, status de execução diferente de zero, avisos,
alarmes, propriedades desconhecidas/inválidas ou saída incompleta causam
falha, sem skip. Guarde o log bruto completo e o status de saída.

Um ambiente Guix temporário pode fornecer as ferramentas sem instalá-las no
perfil do usuário. Fixe e registre o commit dos canais; `gcc-toolchain@14`
precisa resolver para 14.3.0, não outra versão 14.x:

```sh
guix shell --pure frama-c@29.0 gcc-toolchain@14 make bash-minimal coreutils gawk grep -- \
  bash -c 'FRAMA_C=frama-c FRAMA_CPP_CC=gcc FRAMA_TIMEOUT=timeout make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-aes-nist test-frama-aes-nist-wrapper test-frama-aes-nist'
```

A execução Eva atual passou sem avisos e com zero alarmes, 21 propriedades
válidas, sete pré-condições válidas e retorno de `main`. Alcançou as
162 instruções das cinco funções analisadas de 27, incluindo os corpos reais
do inicializador, cifrador de bloco, `gmul` e `xtime`. A substituição automática
por builtins está desabilitada para essas funções C. O gate exige 64 chamadas
`__FC_assert` alcançadas e sua pré-condição `nonnull_c` válida; as 21
Assertions do resumo Eva são quatro propriedades de laço da inicialização,
duas verificações internas de inicialização, um invariante do laço `gmul`
e quatorze invariantes dos laços de bloco,
**não 64 objetivos de prova quantificados
separadamente**. O snapshot anterior de 248 arquivos tinha quatro propriedades
e 160 instruções, antes das assertions internas. O snapshot intermediário
somente de inicialização tinha seis propriedades e 162 instruções; o snapshot
posterior somente dos auxiliares tinha sete propriedades. Os novos invariantes
de bloco não acrescentam instrução executável. Um byte esperado incorreto produziu
status de processo zero e zero alarmes, mas pré-condição de assert inválida
e `main` sem retorno; o gate rejeitou corretamente esse resultado.

Os 32 controles sintéticos do wrapper testam diagnósticos, ferramentas/status,
corpos executados, contagens de bytes e análise incompleta/sem retorno,
incluindo a rejeição dos resumos antigos de quatro propriedades/160 instruções
e de seis/sete propriedades. Os 28 casos anteriores são preservados; quatro
casos adicionais cobrem os prefixos `warning:`/`error:` em maiúsculas e com
capitalização mista. Uma regressão no gate antigo expôs o aviso em maiúsculas
aceito com status zero. O wrapper para na primeira falha, portanto isso não
representa quatro aprovações indevidas observadas separadamente. O gate agora
usa `tolower` do awk POSIX somente nesse predicado, preservando a saída bruta
e os demais checks do perfil.
Seu supervisor simulado confere os argumentos de prazo, mas não impõe prazo.
Ele não analisa AES nem precisa de Frama-C ou `timeout` GNU real, portanto
essas ferramentas opcionais não são dependências do `check` padrão.

No snapshot fixo de 294 arquivos testado em 2026-10-22 UTC, passam os 32
controles e o perfil Eva real acima: 162/162 instruções, 21 assertions válidas,
sete pré-condições válidas e zero alarmes nesse escopo de vetores fixos.
Também passam novos `check` estritos com GCC 14.3.0 e Clang 22.1.8 e o smoke
funcional da CLI, com 11 e dez skips explícitos, respectivamente. O Clang
executa o fixture de cabeçalho bionic que o GCC pula; Windows, cinco casos do
SDK externo, o check privilegiado de loop device e ferramentas de shell/manuais
ausentes continuam não testados. O executável Clang instalado foi fixado
separadamente do provedor histórico indisponível, sem tratá-los como idênticos
byte a byte. São execuções nativas em namespaces, não uma nova VM, `test-all`
completo, campanha global de sanitizadores ou aceitação de pacotes nativos
finais. A atualização final dos documentos fica fora do snapshot de runtime;
nenhum código C, assembly, criptográfico ou do formato de arquivo mudou.

Execute o supervisor focado sem o toolchain formal opcional:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-frama-aes-nist-wrapper
```

Repita a regressão comum em um checkout descartável novo para cada compilador;
o Make não acompanha todas as mudanças de compilador/flags. Para Clang,
substitua `CC=gcc` pelo executável Clang selecionado. Execute o comando Frama-C
real acima com seu perfil fixado de pré-processamento GCC, independentemente
dessa escolha:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 check
bash scripts/test-installed-zupt.sh ./zupt
```

Os resultados cobrem somente uma chave fixa e quatro vetores válidos no C
portátil. Não provam equivalência AES/FIPS para chaves arbitrárias, resistência
a canais laterais, correção dos chamadores assembly nem o programa completo.
O resultado histórico WP somente com Qed abaixo permanece parcial. O
`test-all` GCC 14 com `WITH_JASMIN=1` passou em VM isolada num snapshot fixo de 247 arquivos, com
14 skips explícitos; mudanças posteriores no wrapper do scanner de avisos,
Makefile e documentação ficaram fora. O Clang 22 passou no snapshot fixo de
248 arquivos com 15 skips explícitos, incluindo interoperabilidade OpenSSL,
pois sua VM não tinha o executável `openssl`. Três checks de interoperabilidade
passaram separadamente no GCC247, não no Clang248. As duas suítes normais usam
`WITH_SDK=0 WITH_PQBOX=0` e não foram recompiladas globalmente com ASan/UBSan.
Alterações posteriores da documentação ainda exigem auditoria final da fonte;
nenhum resultado autoriza a publicação para produção.

Após as alterações na inicialização AES, novas execuções `test-all` com
GCC 14.3.0 e Clang 22.1.8 passaram na fonte fixa de 248 arquivos em VM com
2 CPUs/2 GiB e `WITH_JASMIN=0 WITH_SDK=0 WITH_PQBOX=0` (14 e 15 skips
explícitos, respectivamente). O Clang também passou na suíte completa com
`WITH_JASMIN=1`, exigindo dispatch real dos vetores para Jasmin AES-NI com
AVX habilitado pelo sistema; 15 skips continuam não testados. Separadamente,
`test-asan-run` e smoke tests do GCC passaram com a CLI instrumentada por
ASan/UBSan e detecção de vazamentos ativa. As suítes completas normais não são
instrumentadas globalmente. Esses checks não comprovam instalação nativa de
pacote nem regeneração pelo compilador e não incluem edições posteriores da
documentação. Preserve os logs brutos e todos os skips; a tabela do README
separa os resultados de integração e os requisitos restantes para a release.

#### Reproduzir os smoke tests da CLI com sanitizadores

Use um checkout descartável da fonte e um runtime de sanitizadores GCC ou
Clang configurado. Não reutilize objetos de outro compilador ou perfil de
recursos; o Make não acompanha todas as mudanças de flags. O ambiente Clang
no Guix também precisa dos caminhos de resource-directory e runtime
configurados. Execute em Bash, não diretamente no fish, com usuário comum:
como root, o teste de permissões sem privilégios é pulado. O subshell para
após qualquer comando que falhar:

```sh
(
set -eu
make -j1 WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 CC="${CC:-cc}" \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror' \
  ASAN_CFLAGS='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined' \
  ASAN_LDFLAGS='-fsanitize=address,undefined' \
  test-asan-run
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  bash scripts/test-installed-zupt.sh ./zupt_asan
)
```

O comando fixa os flags padrão dos sanitizadores, sem aceitar substituições
do ambiente. O Makefile acrescenta `ASAN_CFLAGS`, cujo `-O1` prevalece sobre o
`-O2` anterior. Ele instrumenta cada fonte C deste perfil da CLI; `WITH_JASMIN=0`
exclui assembly não instrumentada. As exceções existentes de alinhamento de
casts do Clang ficam restritas às unidades designadas. O primeiro alvo verifica
roundtrips de arquivos, uma imagem de disco fictícia cifrada/com deduplicação
e ajuda/versão. O installed-smoke acrescenta caminhos aninhados, vazios,
aleatórios, com espaços e UTF-8, rejeição de senha incorreta/corrupção e de
escape por symlink. Diagnósticos dos sanitizadores devem reprovar até os
casos em que se espera uma rejeição normal.

Não imponha um limite pequeno de espaço de endereçamento virtual ao ASan:
sua memória de sombra precisa de uma faixa grande. Limite a memória real e
o tempo de execução em uma VM descartável. Esses comandos não configuram
esse isolamento nem executam `test-all`, fuzzing, testes de tamanho exato do
codec, SDK/interoperabilidade ou análises Frama-C/Jasmin. Registre os logs
completos, compilador/flags, commit e hashes da fonte com alterações locais;
um smoke test aprovado não autoriza a release.

Uma nova tentativa em 2026-10-17 fixou a fonte corrigida de 282 arquivos, a
base histórica de 243 arquivos e a seleção existente de runtime/ferramentas
da CLI. A admissão retornou 78 com 4.754.292 KiB disponíveis, abaixo do piso
inalterado de 5 GiB no host. Não houve imagem, controle no hóspede ou teste
do produto; a VM mantém 2 CPUs/2 GiB. Separadamente, uma regressão privada
do wrapper reproduziu seis aprovações indevidas quando o QEMU encerrava com
zero apesar de uma transcrição incompleta ou bloqueada do hóspede. Seus
11 testes com fixtures agora passam ao exigir cada controle, controle negativo
dos sanitizadores e marcador de etapa do produto uma vez e em ordem, além
do término completo. Falhas do produtor, coletor e integridade continuam
propagadas. Esses fixtures testam o wrapper, não o runtime dos sanitizadores
ou a correção do codec. Essa tentativa não executou a VM da fonte atual;
a evidência posterior de runtime está abaixo.

Em 2026-10-18, um snapshot recém-fixado de 284 arquivos passa no perfil
limitado da CLI GCC ASan/LSan/UBSan dentro da VM descartável real. A memória
disponível supera o piso inalterado de 5 GiB no preflight, na compressão da
imagem e no lançamento. O hóspede de 2 CPUs/2 GiB verifica isolamento,
limites de cgroup, limpeza, timeout e saída antes dos controles negativos
dos sanitizadores e das etapas do produto. O alvo mantém 768 MiB/16 tarefas,
temporários de 512 MiB e arquivos de 64 MiB; cada etapa limita a saída a
4 MiB. Os controles negativos de acesso fora do heap, leak e overflow de
inteiro com sinal são rejeitados com os diagnósticos esperados. A CLI
instrumentada passa então em `test-asan-run` e no smoke funcional instalado
com detecção de leaks habilitada. Testes separados, não instrumentados, de
SDK interno/licenças/símbolos e três casos de interoperabilidade ML-KEM/OpenSSL
passam. Os 25 registros obrigatórios aparecem uma vez e em ordem; status da
VM, coletor, preservação e protocolo são zero. SHA-256 do transcript bruto:
`4b6fbfaf54090103f6dd536208ac94f71c800b8e769bcce097964162d783c156`.
As alterações posteriores apenas documentam resultados. Isso não qualifica
`test-all` completo, tamanho exato, fuzzing, SDK externo/PQBOX, GUI, pacotes
nativos ou a release; sucesso no SDK/interoperabilidade não representa
cobertura de sanitizadores dessas etapas.

Uma repetição formal posterior inicialmente não iniciou: os caminhos fixados
do perfil de validação, Frama-C 29.0 e Why3 1.7.2 estavam indisponíveis. O
primeiro gate ANS parou antes da análise; os checks posteriores não executaram.
Essa tentativa falha continua registrada, sem novo resultado formal.

Em 2026-10-19 UTC, substituição autenticada e grafts normais do Guix restauraram
o conjunto privado Frama-C 29.0/Why3 1.7.2. Os hashes NAR recursivos foram
conferidos; o perfil do usuário e a configuração de confiança não mudaram.
Os quatro gates Frama-C reais e inalterados passaram então com GCC 14.3.0:

A tabela preserva os resultados de 2026-10-19. Consulte o
[perfil ANS atual](#limites-ans-com-saída-de-tamanho-exato) para o escopo
ampliado.

| Gate | Resultado observado | Limite |
| --- | --- | --- |
| Metadados ANS malformados | 138/358 instruções, zero alarmes, 20 pré-condições válidas | Três fixtures, não o decodificador completo |
| Logaritmo ANS | 15/15 instruções, duas assertions e duas pré-condições válidas | Faixas unsigned modeladas |
| WP do leitor ANS | 30 metas JSON exatas, 16 Qed e 14 Z3; console 34/34 | Inicialização/extração sob pré-condições do chamador, não recarga |
| Eva da AES portátil | 162/162 instruções, 21 assertions válidas, sete pré-condições válidas, 64 checks de bytes | Quatro blocos NIST fixos, não todas as chaves ou modos |

As três etapas Eva iniciais saíram com 125 após seus resumos porque o
supervisor privado selecionava um arquivo `WHY3CONFIG` ausente. Criar e
registrar a mesma configuração antes de cada invocação corrigiu as execuções;
as falhas originais continuam como evidência de falha, não de aprovação.
Nenhuma fonte do produto, teste público, opção do analisador, critério de
aceitação ou limite de recursos mudou.

O leitor usou Z3 4.13.0, aceito pelo parser existente. Why3 1.7.2 avisou na
detecção privada que a versão do solver não era reconhecida. Registre esse
aviso separadamente da aprovação do gate do analisador/relatório; isso não
qualifica um ambiente de solver reconhecido nem o programa completo. A
repetição Jasmin posterior abaixo não resolve obrigações dos chamadores C
nem valida pacotes finais. A aceitação final da release continua pendente.

A repetição posterior em 2026-10-19 UTC usa o executável oficial Z3 4.12.2 já
preservado com seu runtime glibc/GCC fixado. Novas conferências coincidem com os
hashes históricos do ZIP, executável, licença MIT, runtime e dados de detecção
Why3. O SHA-256 do executável é
`4f490bb1b8f4d71dea98cbd4a7b56a3fdf261ba8ca30a65f22a359d51e70ebd8`.
A API da release original não forneceu digest; esses hashes identificam os bytes
preservados, sem verificar assinatura upstream ou qualificar a ferramenta de
forma independente. Não foi preciso baixar, recompilar, alterar configuração
global ou acrescentar dependência ao produto.

Sob os mesmos limites sem rede, o binário real informa 4.12.2, Why3 1.7.2 o
reconhece e entradas SMT reais retornam os `unsat` e `sat` exigidos antes da
análise. Os quatro gates inalterados da tabela acima passam novamente. WP do
leitor informa exatamente 30 metas JSON válidas, 16 Qed e 14 Z3 4.12.2, com
34/34 no console. A condição de reconhecimento do supervisor privado também
passa em sete controles executáveis após reproduzir e corrigir quatro
aprovações indevidas; esses controles sintéticos não são resultados de análise.
Os gates reais afetados são repetidos após a correção. O aviso inicial de
configuração ausente é preservado antes de sua criação bem-sucedida; não ocorre
aviso de versão não reconhecida. A execução anterior com 4.13.0 não é renomeada
nem descartada. Obrigações formais mais amplas, pacotes finais e aceitação para
produção continuam separados e pendentes.

Em 2026-10-20, os mesmos quatro gates Frama-C mantidos passaram novamente na
árvore congelada de 291 arquivos, sem alterar opções, critérios de aceitação
ou limites de recursos. O gate das fontes selecionadas de Jasmin 2026.09.0
também passou em perfis separados comum e de fixtures C com UBSan sem
recuperação: cinco grupos de análise de fontes, 1.026 blocos AES e 1.539 casos
AES4 por perfil. UBSan instrumenta os fixtures C, não a assembly nem os
executáveis dos analisadores. Essas repetições não qualificam pacotes finais
nem estabelecem uma prova do programa completo.

Um novo `check` estrito com GCC 14.3.0 e o smoke funcional da CLI real também
passam na fonte C inalterada com SDK/PQBOX/Jasmin e Cargo desativados. Os onze
skips preservam os limites de Windows nativo/ABI específica do Clang, SDK
externo, loop device privilegiado, shells opcionais e renderizadores de manual.
O perfil C existente usa limites de 600 segundos de CPU por processo e de
tempo total, mais cinco de tolerância para encerramento; é separado do perfil
formal inalterado de 125 segundos totais/120 de CPU. Ambos mantêm afinidade
em duas CPUs, 1 GiB de espaço de endereçamento por processo, temporários
privados de 128 MiB e logs de 1 MiB, não cotas agregadas de RAM/CPU. Isso não
qualifica `test-all` completo, nova VM com sanitizadores, pacotes nativos,
GUI, plataformas ou aceitação final da release.

#### Perfis opcionais de integração e assembly

`test-all` inclui `tests/test_audit.sh`, que executa os caminhos autenticados
do SDK somente quando o ZUPT é compilado com um SDK de sistema compatível
(`WITH_SDK=1`); caso contrário,
registra um skip explícito. Em um checkout limpo com a integração opcional
instalada, repita a suíte com `WITH_SDK=1` e os flags de link exigidos pelo
SDK. Execute `make clean` antes de mudar o compilador ou os flags de recursos:
o Make não acompanha esses valores como dependências dos arquivos objeto.
Guarde toda a saída, incluindo os testes pulados, no registro da auditoria.

Em x86_64, a integração da assembly incluída é um teste adicional e explícito:

```sh
make clean
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
```

Teste separadamente os status do scanner de avisos do supervisor Jasmin:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-source-wrapper
```

Essa regressão do `check` padrão executa o script real do gate de fontes com
ferramentas simuladas. Os quatro controles verificam continuidade sem aviso,
rejeição de aviso, erro `2` do scanner e status simulado `127` de scanner
indisponível. Falhas do scanner precisam interromper antes das etapas
seguintes, preservar o status e emitir diagnóstico. Um controle aprovado
informa explicitamente um resultado sintético, não as mensagens de falha
esperadas das ferramentas simuladas. Não há análise Jasmin real; esses
controles não exigem o compilador nem as ferramentas opcionais de análise.

No Linux x86_64, analise e regenere as cinco fontes Jasmin atuais:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-jasmin-source
```

Esse alvo explícito exige Jasmin 2026.09.0 (`jasminc`, `jasmin-ct` e
`jasmin-checksafety`), compilador C, `objcopy` e `readelf` do GNU binutils, `cmp`, `awk`,
`pkg-config` e arquivos de desenvolvimento do `libcrypto` OpenSSL. Ajuste
os caminhos com `JASMINC`, `JASMIN_CT`, `JASMIN_SAFETY`, `OBJCOPY` e `READELF`
quando necessário. No Guix, mantenha o wrapper do linker do toolchain no
`PATH`; selecione `objcopy`/`readelf` pelos overrides explícitos, sem colocar
um diretório de binutils puro antes do linker. A ausência dos metadados de
busca de bibliotecas pode impedir o executável de carregar `libcrypto`.
Os testes da AES gerada exigem CPU com AES-NI e AVX habilitado pelo sistema
operacional; dependências ou recursos de CPU ausentes fazem o alvo falhar,
sem skip.

A repetição comum de 2026-10-23 UTC passa nas cinco análises das fontes e
comparações de instruções, em 1.026 blocos AES e 1.539 casos AES4. Também
passa nas sete comparações com membros dos pacotes, em dois controles exatos
de rejeição do ambiente, quatro controles sintéticos de avisos e dezessete
controles da limpeza. Para executar os controles distribuídos junto com o
gate real das fontes:

```sh
make -j1 CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  test-jasmin-source-wrapper test-jasmin-wipe-checker test-jasmin-source
```

Use um ambiente descartável, sem rede, com as dependências e limites
descritos aqui. A execução registrada usa o runtime fixado e GCC 14.3.0;
esse comando isolado não impõe isolamento nem limites de recursos. Seu
snapshot de runtime com 294 arquivos precede os ajustes finais de
documentação. Essa repetição comum não fornece novo resultado UBSan, prova
dos chamadores da aplicação, apagamento de registradores ou aprovação de
pacotes finais. Uma tentativa separada de prova do logaritmo ANS não foi
incorporada: a variante privada com divisão provou seu contrato limitado,
mas falhou na comparação exigida dos objetos completos; a prova mais forte
da implementação original com shift continuava incompleta naquele checkpoint.
A prova limitada posterior acima encerra somente o contrato declarado do
auxiliar. O comportamento do codec mantido permanece inalterado.

A repetição independente anterior registrada em 2026-10-19 UTC usou o runtime
Jasmin 2026.09.0 existente, com hashes conferidos, sem o perfil Frama-C então indisponível.
Os três executáveis e quatro bibliotecas APRON são comparados byte a byte
com os membros dos pacotes fixados por hash. A cadeia de hashes dos pacotes e
o registro histórico de assinatura são preservados; isso não é uma nova
auditoria independente de assinatura. Essa repetição Jasmin não exige
instalar ferramentas, alterar perfis ou substituir analisadores. Os fixtures
com GCC 14.3.0 normal e um perfil separado UBSan sem recuperação passam,
cada um, no gate das cinco fontes, em 1.026 blocos e 1.539 casos AES4. A
repetição UBSan qualificada primeiro rejeita um controle real de overflow
com sinal, com status 1. Após fornecer as dependências acima, repita o perfil
dos fixtures em uma cópia limpa da fonte:

```sh
make CC=gcc WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 \
  CFLAGS='-O1 -g -Werror -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -DNDEBUG -fsanitize=undefined -fno-sanitize-recover=undefined' \
  LDFLAGS='-fsanitize=undefined -fno-sanitize-recover=undefined' \
  test-jasmin-source
```

As execuções registradas usam afinidade nas CPUs 0/1, limites herdados por
processo de 1 GiB de espaço de endereçamento e 120 segundos de CPU, prazo
externo de 125 segundos com cinco de tolerância para encerramento e 128 MiB
de temporários privados. Não são cotas agregadas de RAM/CPU por cgroup.
Somente caminhos nomeados de ferramentas em leitura são expostos; home,
credenciais, rede, daemon e KVM do host ficam indisponíveis. O UBSan
instrumenta os fixtures C, não a assembly. A segurança continua condicional
às pré-condições dos chamadores. A tentativa do leitor naquele snapshot
anterior parou antes da análise porque seu executável fixado estava ausente;
veja acima o resultado posterior da restauração. Após restaurar, uma nova
comparação dos membros dos pacotes e o mesmo perfil de fixtures UBSan
qualificado também passam, novamente com 1.026 blocos e 1.539 casos AES4.
Nenhuma repetição Jasmin substitui os gates Frama-C ou qualifica pacotes finais.

#### Runtime com Jasmin e suíte da fonte atual

A repetição mais recente, em 2026-10-21 UTC, usa a fonte corrigida de 294
arquivos com GCC 14.3.0 e `WITH_JASMIN=1`. Passam `check` estrito, 16 vetores
criptográficos, o smoke funcional da CLI e 14 checks multithread.
F-06 informa o caminho real Jasmin AES-NI, 2.000 round trips
normais e zero falhas de criptografia, divergências ou adulterações de um bit
do HMAC aceitas. Permanecem 11 skips explícitos: Windows nativo, fixture
bionic com Clang selecionado, cinco casos SDK externo, dispositivo loop
privilegiado e zsh/fish/ferramentas de manual.

A mesma CLI recém-testada também passa nos 12 métodos do helper portátil e
seus subcasos. Reproduza os comandos de runtime e o gate adicional do helper
em uma única cópia limpa de build com:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
bash scripts/test-installed-zupt.sh ./zupt
sh tests/test_threaded.sh ./zupt
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 test-portable-gui
```

Esse alvo é separado de `test-all` e não precisa de binding Qt. Exercita o
helper real com contêineres `.zupt` genuínos não criptografados em nível 9,
inventário exato de 17 arquivos, checksums e extração idêntica byte a byte.
Os negativos cobrem falhas da CLI, membros alterados/ausentes/inseguros,
fontes de políticas, saídas existentes e substituição/colisão de diretórios.
Saídas temporárias não são artefatos publicados. Não exercita uma janela Qt
nem instalação nativa da GUI.

O perfil nativo mantém CPUs 0/1, espaço de endereçamento de 1 GiB por processo,
CPU e prazo externo de 600 segundos com tolerância de cinco segundos para
encerramento, scratch de 128 MiB e saída bruta de 1 MiB. Status de processo/
coletor 0/0; passam os pós-checks da fonte e das entradas/ferramentas. As
identidades dos helpers nomeados do host são verificadas antes e depois,
não a closure completa de dependências. Essa execução não implica novos
ASan/UBSan, `test-all` completo do perfil opcional, prova formal ou aprovação
dos pacotes finais. O tempo impresso pelo teste multithread é informativo:
N=1 levou 10 ms e N=4, 13 ms (0,8x). Não é benchmark do codec nem evidência
de ganho de velocidade. A atualização final dos documentos fica fora do
snapshot medido; os gates de fontes/pacotes/plataformas/assinaturas e revisão
formal exigida continuam regendo a publicação. SHA-256 do log bruto completo:
`978a5250920ee8712cb1c9ae7eca297b46f8d094b92a31f9440bd85c5c30cf57`.

Em 2026-10-19 UTC, o snapshot fixado de 291 arquivos também passa nos checks
da CLI real com Jasmin, não somente nos fixtures gerados. Em cópia limpa sobre
x86_64 com AES-NI e AVX habilitado pelo sistema, reproduza os comandos com:

```sh
make -j2 CC=gcc CFLAGS='-O2 -g -Werror' CARGO=false \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 check
bash scripts/test-installed-zupt.sh ./zupt
sh tests/test_threaded.sh ./zupt
```

GCC 14.3.0 alcança o caminho Jasmin AES-NI de F-06: 2.000 round trips honestos,
zero erros de criptografia, divergências ou adulterações HMAC de um bit aceitas
silenciosamente. Passam os 14 testes multithread; permanecem 11 skips explícitos
de plataforma/provedor/ferramenta. O envelope nativo registrado usa CPUs 0/1,
1 GiB de espaço virtual por processo, limites de CPU e externo de 600 segundos,
cinco segundos de tolerância, temporários de 128 MiB e log bruto de 1 MiB.
Não há acesso à rede ou ao home do host; não são cotas agregadas por cgroup
nem cobertura da assembly por sanitizadores.

Uma VM descartável separada passa no `test-all` inalterado com Jasmin desativado
e depois nos checks do SDK interno. Reproduza os comandos em cópia limpa dentro
de VM adequadamente isolada, usando a toolchain GCC selecionada:

```sh
strict_cflags='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wformat=2 -Werror'
make -j1 CC=gcc CFLAGS="$strict_cflags" \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 test-all
make -j1 CC=gcc CFLAGS="$strict_cflags" \
  WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0 audit-licenses sdk-test sdk-verify-symbols
```

A VM registrada usa 2 CPUs/2 GiB, cgroup do alvo de 768 MiB/16 tarefas,
temporários de 512 MiB, arquivos de 64 MiB, saída de 4 MiB por etapa e prazos
inalterados de 300 segundos por etapa. O espaço virtual do ASan não recebe um
limite artificial. Passam os 16 controles de isolamento/recursos e três
negativos reais de sanitizadores antes do produto, os 24 registros ordenados
e os checks independentes de status. O `test-all` inclui 22 checks gerais,
14 multithread, 10 PQ, 14 de dedup, o gate de regressão de tempo, 81 casos de
tamanho exato com ASan, 1.024 bijeções BCJ, dois round trips BCJ de binário
real e três casos de interoperabilidade ML-KEM/OpenSSL. A suíte de round trips
do SDK passa em 15 casos, e seu check de símbolos passa. O negativo de arquivo
corrompido emite deliberadamente falha de verificação; o teste exige rejeição.
A execução mantém 15 ocorrências de skip, incluindo SDK externo/PQBOX
desativados, plataformas/ferramentas ausentes e o caso privilegiado de loop
device. Sucesso no SDK não representa cobertura dele por sanitizadores.
Os picos dos cgroups suíte/SDK são 245.923.840/95.727.616 bytes, sem evento
inesperado de OOM/limite de tarefas ou descendente remanescente. SHA-256 bruto:
`5192b640065e80f4420ee4b862735ad7c5912f5aa1be76a217f0ea16c94e6074`.

Uma execução separada com Clang 22.1.8 passa nos mesmos alvos do produto
no snapshot atual de 291 arquivos. Use `CC=clang` nos dois comandos acima
com uma instalação funcional do Clang e runtime ASan correspondente; o guest
Guix registrado usa aliases privados do diretório de recursos para o runtime
instalado e fixado, não outro compilador. Passam os 24 registros ordenados e
os status independentes, incluindo regressão de tempo, 81 casos de tamanho
exato com ASan, checks BCJ e 15 casos da suíte de round trip do SDK. As 15
ocorrências de skip
incluem OpenSSL indisponível no guest; os três casos de interoperabilidade
GCC não são contados como cobertura Clang. Os picos dos cgroups suíte/SDK são
239.464.448/33.640.448 bytes, sem evento inesperado de OOM/limite de tarefas
ou descendente remanescente. SHA-256 bruto:
`100c3c234487384b76361a33950c46e6f839ced6940acff1382be0b4cb92b592`.

A execução seguinte inclui as duas entradas `bin` ausentes do OpenSSL, já
cobertas pelo hash da ferramenta, sem remover entradas nem mudar testes.
Com os mesmos bytes de código do produto e apenas docs de resultados
atualizados, passa novamente na suíte completa, SDK e protocolo de 24 registros.
As três comparações reais ML-KEM/OpenSSL passam; restam 14 outros skips.
Os picos dos cgroups suíte/SDK são 242.233.344/33.619.968 bytes, sem evento
inesperado de OOM/limite de tarefas ou descendente remanescente. A imagem tem
132.982.776 bytes sob o mesmo teto de 128 MiB. SHA-256 bruto:
`c72055db573ba7d556395403f59f480e6bc4fdfbb97559c358639457e2ef0f6e`.

A primeira imagem Clang excedeu o teto inalterado de 128 MiB por arquivo
antes do boot; nenhum teste do produto executou nessa tentativa. A seguinte
preserva cada byte selecionado dos fontes/ferramentas e usa CRC32, uma thread
XZ, BCJ x86 e LZMA2 preset 9 no transporte. A imagem tem 132.702.328 bytes,
abaixo do teto de 134.217.728 bytes; a pequena margem não garante entradas
futuras. Seis checks reais de transporte e 12 controles do wrapper passam
antes da VM. Esses checks da imagem privada não são provas do produto,
fuzzing ou análise formal.

Um perfil anterior parou antes de `test-all` porque a seção `.text` do decoder
difere da referência histórica de casts. Quatro guardas posteriores de alocação
pelo número de literais alteram esse código intencionalmente. Preserve a falha
de identidade; não mude o hash esperado nem afirme que passou. O perfil
explícito da fonte atual executa a suíte real separadamente, com os mesmos
testes e limites. Esses resultados não provam tempo constante, qualificam todos
os perfis opcionais ou encerram gates formais mais amplos, plataformas nativas
e pacotes finais.

O fixture separado `test-jasmin-wipe-checker` também exige `sed`, Bash e `awk`.
A validação combinada registrada usou GNU sed 4.9; confira sua presença no
`PATH` ao executar esse fixture ou `release-check`.

O alvo verifica compilação, segurança sob as pré-condições emitidas para o
chamador, contratos explícitos de tempo constante, DOIT e CT/DOIT após lowering
das instruções. Para AES4, o comando de segurança declara explicitamente os
papéis de ponteiros/contagem:

```sh
jasmin-checksafety --arch=x86-64 \
  --param 'zupt_aes256_ctr4>out_ptr,in_ptr,key_ptr,ctr_ptr;nblocks' \
  jasmin/zupt_aes_ctr4.jazz
```

Os dois laços AES4 possuem anotações de término. O resultado continua
condicional às faixas de alocação e regras de aliasing do chamador em
[`include/zupt_jasmin.h`](../include/zupt_jasmin.h): spans válidos sem wrap,
`nblocks <= SIZE_MAX/16`, entrada/saída idênticas ou disjuntas e a separação
indicada para chave/contador. A execução anterior sem parametrização atingiu
seu limite de 120 segundos e continua como resultado histórico `BLOQUEADO`,
separado da verificação parametrizada.

Antes de comparar `.text`, o gate exige que cada objeto gerado/de execução
exporte a função global exata no início da seção e não contenha relocations.
Somente os bytes das instruções não validam referências a símbolos externos.
Confere quinze stores de limpeza da pilha para AES de bloco e dezesseis para
AES4. AES4 usa um frame de 256 bytes (240 das chaves de rodada e 16 do
contador); a descida máxima de RSP a partir da entrada da função é 264 bytes
sob o alinhamento da ABI SysV x86_64. Isso não prova limpeza de registradores
nem do padding de alinhamento.

Na fonte fixa de 248 arquivos, os gates GCC 14 e Clang 22 passaram, cada um,
em 1.026 casos de um bloco (dois vetores NIST e 1.024 blocos diferenciais
OpenSSL) e 1.539 casos AES4. O fixture AES4 cobre buffers separados/in-place
e desalinhados,
chamadas divididas, wrap dos 64 bits inferiores do contador e contagem zero.
Canários cobrem escritas, não limites de leitura da assembly. Esses testes de
correção não estabelecem ganho de throughput, equivalência FIPS completa,
todos os chamadores C nem os binários finais dos pacotes. Os resumos de arrays
de ponteiros da análise não comprovam ausência de leituras nesses arrays.

A mesma fonte fixa passou no alvo AES nativo com UBSan estrito nos dois
compiladores, nos controles simulados separados, no gate Frama-C Eva real de
vetores fixos e no inventário de licenças. Esses checks no host são separados
das suítes completas em VM e não resolvem as obrigações WP mais amplas nem os
checks finais de pacotes e assinaturas.

Para testar o chamador MAC C/assembly real, use outra cópia limpa da fonte:

```sh
make WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=1 \
  CFLAGS='-O1 -g -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=undefined' \
  test-f06 test-vectors
./test_vectors
```

Repita com `CC=clang` em uma árvore limpa separada. `test-f06` executa 2.000
round trips e alterações de um bit do MAC, percorrendo os 256 bits da tag.
`test-vectors` apenas compila o executável; o último comando executa suas
16 verificações. A redução MAC unsigned evita overflow assinado quando o
acumulador da assembly tem apenas o bit mais alto ativo. Preserva as duas
versões legadas do MAC, sem alterar o formato do arquivo.

Os dois executáveis inicializam o detector real de CPU antes dos testes e
informam o caminho AES selecionado. Mesmo com assembly habilitada, o build usa
C portátil quando AES-NI ou AVX habilitado pelo sistema estão indisponíveis;
isso não é resultado de teste da assembly. Repita a receita com
`WITH_JASMIN=0` em outra árvore limpa para testar explicitamente o caminho
portátil. A fonte canônica atual passou nos quatro perfis de compilador/recurso
com 16 vetores e 2.000 round trips F-06 em cada um, sem aceitar MACs alterados.
Checks anteriores GCC 14 e Clang 22 também usaram instrumentação privada no
link para confirmar chamadas às implementações reais C, de um bloco, de
quatro blocos e ao fallback com os recursos desabilitados. Essa instrumentação
é evidência de cobertura, não prova do contrato completo do dispatch C.

Para a revisão formal, execute Eva e WP do Frama-C em um ambiente fixado e
guarde os logs brutos. O harness Eva limitado, o ponto de entrada do
decodificador sem restrições e cada obrigação WP não resolvida devem ser
relatados separadamente. Um build de assembly bem-sucedido não regenera nem
verifica formalmente as fontes `.jazz`; isso exige o compilador Jasmin
correspondente e seu toolchain reprodutível.

#### Análise WP focada no escalonamento de chaves AES

Na execução histórica somente com Qed, as anotações de laço em
`src/zupt_aes256.c` melhoraram a análise de `zupt_aes256_init` sem alterar
seu contrato público nem as instruções de
execução. Com Frama-C 29.0, GCC 14.3.0, `gcc_x86_64`, `Typed+int` e Qed
interno, o resultado amplia 16/39 para 39/58 objetivos concluídos (37 Qed,
um de término, um inalcançável). Dezenove continuam desconhecidos: oito
acessos à memória, quatro limites de índices, três verificações de aritmética
assinada, três obrigações do prefixo inicializado e a pós-condição de
inicialização. Hipóteses de separação do modelo Typed também permanecem
abertas. É uma análise parcial de contratos da fonte, não prova de equivalência
funcional AES/FIPS. As anotações introduzem obrigações adicionais, por isso
os totais de objetivos do baseline e da análise atual são diferentes.

Para executar as opções históricas somente com Qed, use o trecho abaixo
em Bash na raiz do repositório com as ferramentas fixadas no `PATH`,
`timeout` do GNU coreutils e `taskset` do util-linux. Reproduzir os totais
antigos de 39/58 exige o snapshot anterior da fonte, antes das máscaras e
assertions internas; a fonte atual gera um conjunto diferente de objetivos. A
execução registrada usou CPUs 0 e 1; escolha dois IDs permitidos pelo seu
ambiente. Um shell Guix temporário e fixado pode fornecer `frama-c@29.0
gcc-toolchain@14 bash-minimal coreutils util-linux`; registre o commit dos
canais e as versões exatas das ferramentas.

```sh
wp_dir=$(mktemp -d) || exit
gcc_path=$(command -v gcc) || exit
audit_cpus=0,1
analysis_status=0
(
  ulimit -v 1048576 || exit
  LC_ALL=C WHY3CONFIG=/dev/null taskset -c "$audit_cpus" \
    timeout --signal=TERM --kill-after=5s 120s \
    frama-c -machdep gcc_x86_64 \
      -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
      -cpp-extra-args="-I$PWD/include" \
      -wp -wp-rte -wp-model Typed+int \
      -wp-fct zupt_aes256_init -wp-prover qed -wp-timeout 2 \
      -wp-par 2 -wp-memlimit 256 -wp-out "$wp_dir/wp-out" \
      -wp-report-json "$wp_dir/results.json" src/zupt_aes256.c
) >"$wp_dir/analysis.log" 2>&1 || analysis_status=$?
printf '%s\n' "$analysis_status" >"$wp_dir/analysis.exit"
cat "$wp_dir/analysis.log"
printf 'Analysis exit: %s; evidence: %s\n' "$analysis_status" "$wp_dir"
```

Isso seleciona todas as obrigações dessa função, incluindo RTE, frame,
término e inicialização, sem escolher somente os objetivos comprovados.
`-wp-prover qed` executa o provador interno; `-wp-prover none` apenas gera
obrigações e não é uma execução de prova Qed. O limite de 1 GiB de memória
virtual vale por processo, não para o conjunto. Guarde o log e o relatório
JSON; **saída 0 do processo não significa PASS de prova**. Avisos, objetivos
desconhecidos/não comprovados, timeouts, ferramentas ausentes ou falha de
execução bloqueiam um gate estrito de prova. O processo registrado saiu com
0, mas seu gate estrito saiu com 1.

Uma execução separada e selada em 2026-10-07 passou no gate estrito WP da
inicialização AES: 60/60 obrigações no console e 58/58 objetivos JSON únicos,
não smoke, todos válidos. Ela preserva os 56 IDs do baseline e comprova
`old_prefix_initialized` e `new_word_initialized` antes de usá-los como cortes
internos de prova. Nenhuma pré-condição pública, invariante, condição de frame
ou pós-condição foi removida ou enfraquecida. Duas máscaras redundantes do
byte superior explicitam os índices SBOX; GCC 14 e Clang 22 emitiram `.text`
idêntica antes e depois dessa mudança.

A execução usou Frama-C 29.0, GCC 14.3.0, Why3 1.7.2 e Z3 4.12.2 reconhecido.
O SHA-256 da fonte é
`35562ca8e0861db3fbd185cf9ba61c1d6e43c097f34a6d38fb254c83352a4e1b`;
o SHA-256 do log bruto completo da VM é
`4efe9b76ae541c9e8c594f92a9542d46e611914cb7c6ef052339160b6b4ae19b`.
A VM teve duas CPUs e 2 GiB de RAM; o cgroup do alvo teve 768 MiB, 16 tarefas,
scratch de 512 MiB e limite de saída de 4 MiB. Foram mantidos dois segundos e
256 MiB por provador, dois jobs e prazo de análise de 120 segundos. Os quatro
blocos fixos NIST e o controle com byte esperado incorreto também passaram
nos respectivos gates.

Para a invocação Z3 abaixo, primeiro prepare uma configuração Why3 privada
cujo `why3 config detect` e `why3 config show` reconheçam Z3 **4.12.2**.
Registre a configuração, o driver, o binário do solver e os hashes das
ferramentas. Não reutilize `WHY3CONFIG=/dev/null` do perfil somente com Qed.
Com as variáveis Bash do trecho anterior:

```sh
WHY3CONFIG="$wp_dir/why3.conf" LC_ALL=C taskset -c "$audit_cpus" \
  timeout --signal=TERM --kill-after=5s 120s \
  frama-c -machdep gcc_x86_64 \
    -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
    -cpp-extra-args="-I$PWD/include" \
    -wp -wp-rte -wp-model Typed+int \
    -wp-alias-vars SBOX,RCON -wp-msg-key=prover -wp-no-init-const \
    -wp-fct zupt_aes256_init -wp-prover z3 \
    -wp-timeout 2 -wp-par 2 -wp-memlimit 256 \
    -wp-out "$wp_dir/wp-z3-out" \
    -wp-report-json "$wp_dir/results-z3.raw.json" src/zupt_aes256.c
```

Esse comando é a invocação da análise, não o ambiente completo da VM, seus
limites e verificador. Preserve o status, o log integral e o relatório original.
Frama-C 29.0 pode emitir números como `0.`; mantenha os bytes brutos ao
normalizar com jq e confira a identidade dos arrays interpretados antes da
checagem JSON estrita. Exija todos os IDs esperados, incluindo as duas
assertions, vereditos válidos/passed, provadores reconhecidos e nenhum aviso
ou objetivo incompleto. Só contagens ou saída 0 são insuficientes. Não há alvo
Make WP independente publicado; `test-frama-aes-nist` é o gate executável
separado da fixture Eva.

`-wp-alias-vars SBOX,RCON` modela explicitamente esses globais endereçáveis.
`-wp-no-init-const` omite os valores literais dos inicializadores, não a validade
nem a inicialização. O resultado cobre as obrigações selecionadas de limites/RTE,
frame, inicialização e término sob o modelo e as pré-condições. Não comprova
equivalência funcional AES/FIPS, resistência a canais laterais, o programa
completo, empacotamento Guix nativo nem prontidão para produção.

Os auxiliares aritméticos agora têm frames de função e um frame, invariante
e variante explícitos do laço `gmul`. Seis linhas adicionais ACSL não alteram
C executável nem pré-condições públicas. Com o mesmo perfil fixado de
ferramentas/modelo/recursos, uma execução WP separada de `xtime,gmul` passou
em 19/19 obrigações no console e 17/17 objetivos JSON exatos. Preserva seis
IDs do baseline; os dois objetivos antigos de término dividido são substituídos
pelo término da função e pelos checks separados, obrigatórios, de positividade
e decréscimo da variante. O timeout de término original sem anotações é preservado.
Não foi usada hipótese `-wp-variant-with-terminates` nem novo axioma.

Reproduza a análise dos auxiliares com a configuração Why3 preparada:

```sh
WHY3CONFIG="$wp_dir/why3.conf" LC_ALL=C taskset -c "$audit_cpus" \
  timeout --signal=TERM --kill-after=5s 120s \
  frama-c -machdep gcc_x86_64 \
    -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
    -cpp-extra-args="-I$PWD/include" \
    -wp -wp-rte -wp-model Typed+int \
    -wp-alias-vars SBOX,RCON -wp-msg-key=prover -wp-no-init-const \
    -wp-fct xtime,gmul -wp-prover z3 \
    -wp-timeout 2 -wp-par 2 -wp-memlimit 256 \
    -wp-out "$wp_dir/wp-helpers-out" \
    -wp-report-json "$wp_dir/results-helpers.raw.json" src/zupt_aes256.c
```

O SHA-256 da fonte anterior somente dos auxiliares é
`f88d4c5ac413b63382fa1b3da27833b9d83c956429a1d4d1b7274df8b2503ce1`;
o SHA-256 do log da VM com gate estrito é
`3d1913df8ee03e2633bbb39349626c24c02f7e21600b133b34df0e4fb9e407be`.
Uma execução combinada separada na mesma fonte repetiu os 58 objetivos JSON
da inicialização, o resultado Eva real de sete propriedades e os 27 controles
do supervisor: SHA-256 do log bruto
`222aa0eeb158d335a4bac10ace69a36bd672df9c79d8a6e7cd09da494b9b89ce`.
Ambos os executáveis NIST completos do GCC continuaram idênticos byte a byte.
Preserve os IDs exatos, vereditos válidos, relatórios originais e checks de
recursos/diagnósticos; só totais não bastam. O resultado prova frames, limites
e término selecionados sob o modelo, não multiplicação GF funcional,
equivalência AES, correção do cifrador de bloco nem segurança do programa completo.

#### Checks WP dos laços de bloco AES portátil

O cifrador de bloco agora tem invariantes de limites e inicialização, cláusulas
de frame e variantes decrescentes nos sete laços. Essas 35 linhas de comentários
ACSL não alteram C executável, pré-condições públicas, API nem formato de arquivo.
A execução original sem anotações concluiu 113/144 objetivos, com 31 timeouts e
sete avisos de frame ausente em laços; esse resultado permanece separado. Com
as anotações, os 214 objetivos JSON distintos passaram: 28 obrigações de
estabelecimento/preservação de invariantes, 14 de positividade/decréscimo de
variantes, inicialização da saída, término e as demais obrigações selecionadas
de frame/limites/RTE. Inicialização e auxiliares passaram separadamente na
mesma fonte, com 58/58 e 17/17 objetivos JSON.

Reproduza a invocação limitada usando a configuração Why3 preparada e as
variáveis Bash anteriores:

```sh
WHY3CONFIG="$wp_dir/why3.conf" LC_ALL=C taskset -c "$audit_cpus" \
  timeout --signal=TERM --kill-after=5s 120s \
  frama-c -machdep gcc_x86_64 \
    -cpp-command="$gcc_path -C -E -I." -cpp-frama-c-compliant \
    -cpp-extra-args="-I$PWD/include" \
    -wp -wp-rte -wp-model Typed+int \
    -wp-alias-vars SBOX,RCON -wp-msg-key=prover -wp-no-init-const \
    -wp-fct zupt_aes256_encrypt_block -wp-prover z3 \
    -wp-timeout 2 -wp-par 2 -wp-memlimit 256 \
    -wp-out "$wp_dir/wp-block-out" \
    -wp-report-json "$wp_dir/results-block.raw.json" src/zupt_aes256.c
```

Exija todas as identidades exatas dos objetivos, vereditos válidos/passed,
resultados de solver reconhecido e nenhum diagnóstico, desconhecido, timeout
ou falha. Só o comando não impõe todo o ambiente da VM/checker. A execução
registrada usa VM de 2 CPUs/2 GiB, etapa de 768 MiB/16 tarefas, scratch de
512 MiB, limite de saída de 4 MiB e os mesmos limites de dois segundos,
dois jobs e 256 MiB por prover. Nenhuma hipótese de modelo ou novo axioma foi
introduzido. O GCC pré-processou as fontes original e modificada de forma
idêntica. Não é equivalência funcional AES/FIPS, prova de tempo constante,
prova de todos os chamadores nem auditoria de segurança do programa completo.

SHA-256 da fonte:
`972f426d977df29cd193eb2a6f52a2c0775a480683d5d65f134c48046884d93e`.
SHA-256 do log integrado da VM:
`d0d7f3f8e2d3fc30f068ca20fda4c2b19dca323d2d280eaa4b6b448959d6c597`.
Também passam o gate Eva real, com 21 propriedades válidas, sete pré-condições
válidas, 162/162 instruções, 64 chamadas ao oráculo de bytes e retorno de
`main`, além dos 28 controles do supervisor. Caminhos exatos antigos do store
ficaram indisponíveis; novas cópias instaladas de Frama-C 29.0/Why3 1.7.2 e
kernel da VM descartável foram explicitamente fixadas com hashes diferentes,
não tratadas como substitutas idênticas byte a byte. Falhas de preparação sem
awk e sem plugins permanecem registradas. O runtime Frama-C completo precisa
das dependências do core Eva, incluindo inout e scope; não suprima os avisos.
A dependência exata PPL 1.2 ausente no runtime Jasmin foi posteriormente
restaurada privadamente após autenticar o NAR oficial completo do Guix.
O store/perfis do host e as dependências do produto não foram alterados.
Execuções atuais de `test-jasmin-source` e `test-jasmin-source-wrapper` com
GCC 14.3.0 e Clang 22.1.8 terminam com status zero: cinco fontes, instruções
de execução correspondentes, 1.026 blocos AES, 1.539 casos CTR e quatro
controles do supervisor por compilador. Pré-condições do chamador e limites
originais dos recursos foram preservados. São checks de fontes/fixtures,
não aprovação dos pacotes finais nem do programa completo.
SHA-256 dos logs brutos, GCC:
`4a990a39e123c650f331576251b38c6a40bc073fc758e51627b301292d25a5c6`;
Clang: `86df7db5a0a40e29ef4a667e66add827679164e3ddcd28b3c3fa99bbffbce372`.

As execuções WP históricas mais amplas permanecem separadas: Qed concluiu
285/653 objetivos; o diagnóstico com Z3 4.13.0 concluiu 346/653, com 305
timeouts e dois desconhecidos, usando uma versão de solver não reconhecida
pelos dados de detecção do Why3 disponível. Essas execuções com avisos não
fecham o gate formal mais amplo da release.
Esses totais são históricos, não um inventário atual de objetivos pendentes.
As provas posteriores por função usam conjuntos de obrigações diferentes;
não foi demonstrada reconciliação objetivo por objetivo. Não subtraia suas
contagens aprovadas de 653 nem trate os recortes como validação criptográfica
completa.

### Falha anterior de recursos na cobertura contínua

A campanha anterior em VM descartável permanece registrada como reprovada. Ela usou o snapshot
de 257 arquivos, Clang 22.1.8, objetos escalares do codec, sete sementes
validadas, três controles de sanitizador, entrada máxima de 4 KiB, saída de
65.536 bytes e um único processo libFuzzer contínuo com orçamento de 30 segundos
e limite RSS inalterado de 512 MiB. A execução parou após cerca de 8,04 segundos.
O executável exato tem SHA-256
27ffda8eecf2108b5481f47f8efd5bff23d3084564f925ed37ad4e143dae19a3. Ele
terminou com status 71 após 2.360.279 execuções e 2.040 unidades novas a
598 MiB. O pico do cgroup foi 660.992.000 bytes, sem evento de OOM ou limite
de processos. A entrada salva de 127 bytes tem SHA-256
d378fd4c77b7c57cc96bc62e04a69ad8fc3f95b849c76791c256e1ab38eba534.

A reconstrução nos mesmos caminhos lógicos reproduziu o hash do executável.
A simbolização do contexto de heap exibido retornou `___interceptor_malloc`,
`operator new(unsigned long)` e `main`. Esse contexto cobre 24.383.368 dos
24.791.125 bytes vivos; o log registra separadamente 244.292.744 bytes em
quarentena. O contexto não explica o RSS completo nem exclui contribuições
de alocações do codec. Isso não é aprovação nem vazamento confirmado no codec
e não justifica aumentar o limite RSS.
A repetição em VM com o executável exato processou essa entrada de 127 bytes
uma vez em 1 ms, com status zero, pico de 47 MiB e nenhum artefato. O cgroup
do alvo atingiu 63.795.200 bytes, sem evento de OOM, limite de processos ou
descendente remanescente. A repetição bem-sucedida de 1.549 bytes pertence a
uma campanha anterior. Esses testes de uma entrada não substituem a campanha
contínua. O status externo zero da VM registra seu encerramento; confira
separadamente o status e os diagnósticos preservados de cada alvo.

Campanhas contínuas posteriores e limitadas em VM passaram nos respectivos
snapshots registrados, incluindo a campanha de 2026-10-14 após as alterações
de alocação de sequências documentada no [README.pt-BR.md](../README.pt-BR.md).
Esses resultados não reclassificam esta falha anterior nem aprovam alterações
posteriores da fonte ou pacotes nativos.

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
