<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Documentação operacional do ZUPT 5.2.9

Este documento reúne instalação, uso seguro, distribuição e validação para a
versão em português do Brasil. Os documentos técnicos em inglês continuam
sendo a referência detalhada: [INSTALL.md](INSTALL.md),
[DISTRIBUTION.md](DISTRIBUTION.md), [SECURITY.md](SECURITY.md) e
[THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Instalação a partir do código-fonte

O perfil padrão não usa bibliotecas opcionais empacotadas no repositório.
Instale um compilador C11, GNU Make, Bash, Python 3, `file`, `tar`, `gzip` e as
ferramentas de desenvolvimento da plataforma.

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

## 2. Integrações opcionais

`WITH_SDK=1` habilita `--pq-sdk` e o caminho Argon2id fornecido por uma
instalação de sistema do `libvuptsdk`. `WITH_PQBOX=1` habilita `--pq-box` por
meio de uma instalação de sistema do `libpqvaptvupt`. As opções são
independentes e falham explicitamente se cabeçalhos ou flags de link estiverem
ausentes. A compilação não procura binários opcionais dentro do repositório e
não cria RPATH automático.

## 3. Operação básica

```sh
zupt compress -l 5 backup.zupt pasta/
zupt list backup.zupt
zupt test backup.zupt
zupt extract -o restaurado backup.zupt
```

Use um destino de extração novo ou previamente verificado. Confira o resultado
com comparação de hashes ou arquivos, não apenas pelo código de saída.

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

ZUPT 5.2.9 inclui VaptVupt 2.65.11. O adaptador mantém:

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

Antes de criar uma tag, execute em uma árvore limpa e comprometida:

```sh
make WITH_SDK=0 WITH_PQBOX=0 release-check
bash scripts/check-source-only.sh
bash tests/test_source_only.sh
bash tests/test_packaging_syntax.sh
git diff --check
```

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

Registre `PASS`, `FAIL`, `SKIP` ou `BLOCKED` por alvo. Um teste antigo, pulado
ou executado em outra arquitetura não aprova a release atual.

## 7. Política de distribuição

Git e o arquivo-fonte devem conter somente código-fonte, documentação, testes,
receitas e dados necessários. Objetos, executáveis, bibliotecas compiladas,
pacotes e artefatos de CI ficam fora do histórico Git.

Os artefatos binários pertencem apenas às páginas de release. Cada arquivo
deve nascer da tag anotada e imutável, passar pelo teste de sua plataforma e
aparecer em `SHA256SUMS`. Os doze payloads esperados, mais `SHA256SUMS`, formam
o conjunto de 13 arquivos descrito em [README.pt-BR.md](README.pt-BR.md).

As receitas AUR, Homebrew e Guix só podem receber o hash final depois que o
arquivo-fonte reproduzível da árvore comprometida estiver pronto. Nunca publique
um marcador `REPLACE_AFTER...`; a árvore marcada deve conter os hashes finais.
Nunca mova uma tag para corrigir uma falha.

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
