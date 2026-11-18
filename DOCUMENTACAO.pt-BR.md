<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Documentação operacional do ZUPT

Este documento reúne instalação, uso seguro, distribuição e validação do
ZUPT 5.2.10, com formato desktop 1.6. O [guia de usuário em português](docs/GUIA_USUARIO.pt-BR.md)
detalha os fluxos da CLI e da GUI. [INSTALL.md](INSTALL.md),
[DISTRIBUTION.md](DISTRIBUTION.md), [SECURITY.md](SECURITY.md) e
[THREAT_MODEL.md](THREAT_MODEL.md) complementam a referência técnica.

Escolha os pacotes, tags e checksums na
[página de releases](https://github.com/cristiancmoises/zupt/releases).
Os pacotes históricos mantêm seus formatos originais; use a ferramenta
correspondente para tar, ZIP, DMG ou formatos nativos.

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
Consulte os limites de execução, cancelamento e exposição de argumentos no
[guia detalhado da GUI](gui/README.md) e nos
[modos e limites de segurança](#4-modos-e-limites-de-segurança).

Para usar o frontend portátil, verifique primeiro a assinatura e os checksums
conforme a
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

O log da GUI oculta os valores de `-p` e `--password`, mas a CLI ainda recebe
esses valores nos argumentos do processo. Essa ocultação não protege contra
inspeção local. Fora da GUI, prefira `--pass-file`, `--pass-fd` ou
`--password-prompt` para evitar essa exposição.

## 5. Codec VaptVupt incluído

A fonte 5.2.10 inclui VaptVupt 2.65.13; a versão histórica 5.2.9 inclui
2.65.11. O adaptador mantém:

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

A matriz completa, os requisitos e os limites ficam em [AUDIT.md](AUDIT.md).
Execute cada perfil na revisão exata em análise, com ferramentas reais e seus
pré-requisitos disponíveis. Registre comandos, versões, diagnósticos e status.

| Grupo | Comando ou alvo | Escopo |
|---|---|---|
| Fontes e licenças | `make audit-licenses source-audit` | Execute antes de gerar binários e verifique também os arquivos-fonte exportados. |
| CLI e arquivos | `make check`, `make test-all` | Repita com GCC e Clang; inclua as regressões de formato, caminhos, senhas e integridade. |
| SDK interno | `make sdk-test` | Callbacks, E/S e publicação de chaves; não equivale à integração com SDK externo. |
| Sanitizadores | `make test-asan-run` | Compila e executa; `test-asan` sozinho apenas compila. |
| GUI | `make check-gui`, `make test-portable-gui` | Exige Qt e CLI funcionais; a validação off-screen não substitui os pacotes instalados. |
| Frama-C e Jasmin | [Matriz formal](AUDIT.md#formal-verification) | Seis análises C e cinco fontes Jasmin, com modelos e precondições explícitos. |
| Pacotes | Workflows nativos e `scripts/test-installed-zupt.sh` | Conteúdo, dependências, instalação, round trip e remoção no sistema e na arquitetura declarados. |

Use `WITH_SDK=0 WITH_PQBOX=0 WITH_JASMIN=0` no perfil C padrão. Integrações
opcionais e o runtime `WITH_JASMIN=1` precisam de qualificação própria. O alvo
`release-check` inclui as análises formais mantidas; `check` e `test-all` não
substituem essa condição de release. `WITH_JASMIN=1` sozinho não verifica as
fontes Jasmin.

Registre `PASS`, `FAIL`, `SKIP`, `NOT RUN` ou `BLOCKED` por alvo. Uma ferramenta
ausente, um teste antigo ou uma execução em outra arquitetura não aprova o alvo
atual. Os testes extraídos de DEB/RPM não equivalem à instalação nativa;
compiladores fictícios e injeções de falha validam a infraestrutura dos testes,
não substituem a execução real. Fontes, guias, pacotes e assinaturas devem
corresponder à revisão final publicada.

## 7. Política de distribuição

Git e o arquivo-fonte devem conter somente código-fonte, documentação, testes,
receitas e dados necessários. Objetos, executáveis, bibliotecas compiladas,
pacotes e artefatos de CI ficam fora do histórico Git.

Os binários pertencem às páginas de release, com procedência da tag de runtime
e do commit efetivo de empacotamento documentadas. A 5.2.10 usa cinco bundles `.zupt`
genuínos, sem criptografia, com VaptVupt no nível 9: fonte, CLI Linux x86_64,
CLI Windows x86_64, DMG CLI macOS **arm64, não universal**, e frontend portátil
da GUI. O frontend contém fonte/scripts, não Python, Qt ou CLI empacotados.
DEB/RPM/SRPM da CLI e da GUI mantêm seus formatos nativos. A lista exata está em
[README.pt-BR.md](README.pt-BR.md); o antigo conjunto de 13 arquivos é histórico.

Em um diretório vazio, salve o pacote, a [lista de hashes SHA-256](https://github.com/cristiancmoises/zupt/releases/download/v5.2.10/SHA256SUMS),
a [assinatura da lista](https://github.com/cristiancmoises/zupt/releases/download/v5.2.10/SHA256SUMS.asc)
e a [chave pública](https://github.com/cristiancmoises/zupt/releases/download/v5.2.10/release-key.asc).
Os mesmos arquivos estão na [release do Codeberg](https://codeberg.org/berkeley/zupt/releases/tag/v5.2.10).

Execute `gpg --show-keys --fingerprint release-key.asc`. Confira se o arquivo contém uma única
chave pública e confirme a impressão digital completa por um canal independente de confiança. A impressão digital esperada é
`0CFA43B9AA9642EAAF2BE983C4C661C9ECFB46E8`.
Em seguida, verifique a assinatura da lista e o hash do pacote baixado. Este exemplo verifica o código-fonte.

```sh
gpg --dearmor --output release-key.gpg release-key.asc &&
gpgv --keyring ./release-key.gpg SHA256SUMS.asc SHA256SUMS &&
awk '$2 == "zupt-5.2.10-source.zupt"' SHA256SUMS | sha256sum --check -
```

Para conferir outro pacote com a lista já verificada, repita a última linha com o nome exato do arquivo entre aspas duplas.
Se baixou todos os pacotes e a chave pública, `sha256sum --check SHA256SUMS` verifica as 12 entradas.
Quando o pacote de código-fonte retornar `OK`, teste e extraia o arquivo.

```sh
zupt test zupt-5.2.10-source.zupt &&
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

Uma CLI desktop 5.2.9 confiável é uma opção para abrir bundles simples do
formato 1.6. Verifique a compatibilidade dos artefatos escolhidos; isso não
estabelece interoperabilidade de arquivos criptografados ou de modos PQ.
Não publique novos `.tar.gz` como downloads manuais. Os arquivos gerados
automaticamente pelo forge e os tarballs internos do SRPM/OBS são entradas de
construção distintas, não esses bundles públicos.

Use somente os pins correspondentes à release oficial escolhida. Gere a URL
e o checksum de cada receita a partir da tag assinada e registre o commit da
receita; não ignore diferenças de checksum.

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
