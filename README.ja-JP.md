# Rolodex DNS

> 言語：[English](README.md) ｜ [繁體中文](README.zh-TW.md) ｜ [简体中文](README.zh-CN.md) ｜ [Español (España)](README.es-ES.md) ｜ [Español (México)](README.es-MX.md) ｜ **日本語**

プライバシーを最優先するスプリットホライズン DNS サーバー兼再帰／転送リゾルバー。暗号化トランスポート、DNSSEC、gRPC による管理を備え、Rust で書かれています。

Rolodex DNS は UDP、TCP、TLS（DoT）、HTTPS（DoH）、QUIC（DoQ）上で DNS を提供し、外部解決よりも優先されるローカルレコードデータベースを持ちます。レコードは gRPC でリモート管理します（TCP 上では共有秘密による認証、Unix ソケット上では認証なし）。ドメインオーバーレイを伴う TLD レベルの解決に対応しているので、内部の DNS 表現が常に優先されます。組み込みの DNS 応答キャッシュにより、一度見たレコードについては上流リゾルバーへのクエリ漏洩が起きません。

ローカルでない名前は、既定では**ルートサーバーから反復的に**解決され、暗号化上流（DoH/DoT）と平文上流へ順に落ちていきます。そのため、外向きのポート 53 を遮断するネットワークでも解決が生き延びます。[上流解決](#上流解決)を参照してください。

ルートから解決された応答は、既定で IANA のトラストアンカーに対して **DNSSEC 検証**されます。Bogus なデータは決して提供もキャッシュもされません。[DNSSEC](#dnssec)を参照してください。

Rolodex DNS はさらに、スパム／マルウェアを濾すためのドメインブロックリスト（DNSBL）、DNSSEC のゾーン署名、DANE TLSA 証明書関連付け、組み込みの ACME 認証局、DNS64 の AAAA 合成、ネットワーク単位の DNS 分割、そして統合 DHCPv4 サーバーに対応します。

はじめてですか？ まずは **[設定ガイド](CONFIGURATION.ja-JP.md)** から。動く最小の設定から各サブシステムまでをタスク指向でたどり、デプロイの形ごとに実例を一つずつ示します。

## 機能

- **プライバシー最優先の DNS キャッシュ**：ローカルでの DNS 応答キャッシュにより上流へのクエリ漏洩を防ぎます。一度キャッシュされれば、どのフォワーダーにも接触せずローカルで答えます。純粋な権威サーバーにするには `forwarders: []` を設定してください。
- **暗号化トランスポート**：DNS-over-TLS（DoT、ポート 853）、DNS-over-HTTPS（DoH、ポート 443、GET/POST 両対応）、DNS-over-QUIC（DoQ、ポート 8853）
- **スプリットホライズン DNS**：ローカルデータベースのレコードは、外部で解決された結果よりも常に優先されます
- **UDP と TCP 上の DNS**：どちらのトランスポート層についても完全なプロトコル対応
- **回復力のあるフォールバックを備えた再帰リゾルバー**：既定ではルートサーバーからの反復解決、次に公開リゾルバーへの DoH/DoT、次に設定されたフォワーダー、次に平文の公開リゾルバー —— そのため `:53` を遮断するネットワーク（および DoT の `:853` を塞ぐ DPI）でも解決が働き続けます。粘着する階層により死んだ経路でタイムアウトを払い続けずに済み、階層が切り替わるたびにキャッシュが破棄されます
- **TTL を尊重するリゾルバーキャッシュ**：永続化されるゾーン→ネームサーバーの委任キャッシュ（再起動をまたいで温かい）、グルー／グルー無し NS 参照／CNAME ホップのためのメモリ内キャッシュ、そして RFC 2308 のネガティブキャッシュ —— いずれも残りの寿命とともに提供されます
- **アドレスファミリの認識**：背景のプローブが IPv4/IPv6 の実際のインターネット到達性を試験し、この機体が経路を持たないファミリの A または AAAA 応答を抑制します。クライアントは死んだスタックで止まらず、もう一方へ落ちられます
- **転送リゾルバー**：設定可能な上流 DNS フォワーダー。`resolution.mode: forward` により排他的に使えます
- **TLD／ドメインオーバーレイ**：任意の階層（TLD を含む）にレコードを追加して公開 DNS を上書きできます
- **DNSSEC 署名**：Ed25519（推奨）および ECDSA P-256/P-384 の鍵生成、ゾーン署名、DS レコードの計算。RSA/SHA-256 は検証はできますが生成はできず（`ring` に RSA 鍵の生成が無いため）、認証付き否定（NSEC/NSEC3）は生成されません
- **DNSSEC 検証**：反復的に解決された応答は IANA のルートトラストアンカーに対して検証されます。既定で有効です（`dnssec.validate`）。信頼の連鎖は委任をたどる歩みと並んで上から下へ構築されるので、DS のために余分なクエリはかかりません。未署名の委任は未署名であることを*証明*しなければならない（署名された NSEC/NSEC3）ので、署名の剥ぎ取りはダウングレードになりません。Bogus なデータは SERVFAIL となり決してキャッシュされず、AD は真に Secure な応答にのみ立ちます
- **DANE TLSA ＋ ACME 発行者**：証明書からの TLSA レコード生成、組み込みの ACME 認証局（ゾーン単位の中間 CA）、自己署名ルート CA の生成、ACME DNS-01 チャレンジの処理（`_acme-challenge` の TXT レコードをそのまま提供）
- **DNS 経由の CA 配布**：ルート CA とゾーン単位の中間 CA の連鎖が `CERT` レコード（RFC 4398）として、また分割された `TXT` のフォールバックとともに公開されます。そのゾーンを解決できるクライアントなら誰でも CA を取得して信頼でき、ポータルへのアクセスは要りません（[CA の配布と信頼](#ca-の配布と信頼)を参照）
- **22 のレコード型**：A、AAAA、CNAME、MX、TXT、NS、SOA、SRV、PTR、URI、SSHFP、DNAME、ANAME、ZONEMD、TLSA、CERT、DNSKEY、DS、RRSIG、NSEC、NSEC3、NSEC3PARAM。22 種すべてを保存・一覧できます。NSEC、NSEC3、NSEC3PARAM は決して生成も提供もされません（[DNSSEC](#dnssec)を参照）
- **DNS ワイルドカード**：RFC 4592 に準拠したワイルドカード照合（`*.example.com.` は単一ラベルの置換に一致し、完全一致が優先されます）
- **権威 DNS**：ローカルゾーンと明示的に宣言された権威ゾーンについて AA ビットを立てます
- **EDNS（RFC 6891）**：OPT レコード対応、ペイロードサイズの折衝、DNSSEC のための DO ビット、バージョン 0 超に対する BADVERS
- **DNS64（RFC 6147）**：A レコードからの AAAA 合成、プレフィックスは設定可能（既定 `64:ff9b::/96`）
- **TTL ドリフト**：固定モード（期間の加算／減算、`"1h30m"` のような複合形式にも対応）と、実験的な対数モード（遅延に基づく）
- **QNAME の大小文字ランダム化**：0x20 符号化により転送クエリの QNAME の大小文字をランダム化し、キャッシュ汚染に対抗します
- **gRPC による管理**：共有秘密または Unix ソケットによる認証で、gRPC からレコードをリモート管理します
- **ブロックリスト**：メモリ内キャッシュを伴う DNSBL プロバイダーの照会に加え、独自項目のためのローカルブロックリストデータベース
- **DNSBL 対応**：ドメインブロックリスト（Spamhaus DBL、SURBL、URIBL）を外部解決の前に照会するので、以前に転送応答がキャッシュされていても、載っている名前は拒否されます
- **ブロックリストの拒否の扱い**：DNSxL は「載っている」も「もう問い合わせるな」も同じ種類の `A` レコードで返します。そこで拒否コード（`127.255.255.254`、`127.0.0.1`、…）は掲載では*ない*ものとして認識され、そのプロバイダーは冷却期間のあいだ参照のローテーションから外されます —— そのプロバイダーに照会したすべての名前を NXDOMAIN にする代わりに
- **ブロックリストの許可リスト**：すべてのリストと両方の関門を覆う一つの逃げ道 —— 一つの項目が、ある名前とその配下を DNSBL／ローカルの照会から免除し、あるアドレス（逆引き名でも IP リテラルでも）を逆引き照会から免除します
- **再帰のアクセス制御**：`security.recursion_cidrs` が誰に*上流*解決を駆動させるかを決めます。既定はインターネットから到達不能な範囲なので、既定の `0.0.0.0:53` バインドがオープンリゾルバーになることはありません。見知らぬ相手もこのサーバーの権威応答は受け取れます
- **ネットワークスコープ**：スコープ単位のレコードと IP に基づくアクセス制御によるスプリットホライズン DNS ビュー。スコープの強制は設定されたオーバーレイ（WireGuard）CIDR に限られ、ループバック、LAN、コンテナからの発信元は信頼され、決して拒否されません
- **ネットワーク単位の所有 TLD**：スコープが所有する全域で一意な TLD。オーバーレイのピア間で分割され、決して上流へ転送されません。TLD ごとに任意で**入口 DNS リスナー**を持てます。これはそのネットワーク自身のアドレスで応答し、登録済みの名前をその入口コントローラーへ書き換えます
- **統合 DHCPv4 サーバー**：スコープ単位のアドレスプール、粘着する MAC 束縛、A/PTR の自動登録、サイト固有オプションによる証明書配布、背景でのリース掃除
- **自動の逆引き PTR レコード**：gRPC 経由で追加された A/AAAA レコードに対応する `in-addr.arpa`／`ip6.arpa` の PTR を任意で維持します（`dns.auto_ptr`）
- **プロキシ対応**：HTTP CONNECT、SOCKS5、または DoH プロキシ経由で DNS クエリを転送します
- **Prometheus メトリクス**：任意の、既定では無効な `/metrics` エンドポイント。ラベルの濃度が有界な 80 のメトリクスファミリを公開します —— 段階ごとの応答帰属や TLD ごとの分離を含むので、スプリットホライズンの流れが外から読み取れます。クエリ名がラベルになることはありません
- **SQLite による永続化**：DNS レコードは再起動をまたいで残ります
- **TLS のホットリロード**：証明書ファイルは 30 秒ごとに監視され、更新された組は DoT、DoH、DoQ、ACME、登録ポータルによってその窓の内に提供されます。再起動も接続の切断もありません。再構築が失敗した場合 —— 切り詰められたファイルや、ACME クライアントの二回の書き込みの間に落ちた監視 —— は、以前の証明書を提供し続け、次の監視で再試行します
- **性能**：マルチスレッドの tokio ランタイム、ロックフリーなブロックリストとリゾルバーの状態（`AtomicBool` ＋ `ArcSwap` ＋アトミック）、スコープ／ゾーン／TLD／ブロックリスト項目のためのメモリ内起動キャッシュ、上流転送のための UDP ソケットプール、そして全体にわたる DashMap/DashSet による並行キャッシュ

## ビルド

```
make build
```

## テスト

```
make test
```

lint（翻訳のずれの検査、`cargo fmt --check` ＋ `clippy --all-targets -D warnings`）、Go の統合テストと単体テスト、Rust の統合テストと単体テスト、JavaScript の lint／統合／単体テスト、そして文書化された PromQL の実行検査を走らせます。Rust の統合層には、DNSSEC の署名と検証（直列化の時点で応答が改竄される、署名済みの模擬階層に対して行うので、各テストは「正当なデプロイが攻撃されている」姿になります）、ブロックリストの NXDOMAIN 契約、ブロックリストの拒否コード、DoQ、プロキシ、TLS のリロード、ZONEMD、ACME の運用、そしてセキュリティ指摘ごとの `security_*` 群という、実ソケットを使う試験群が含まれます。同じ実行を `/tmp/rolodex-dns/log` 配下のタイムスタンプ付きログファイルへ tee するには `make test-log` を使ってください（`LOG_DIR` で上書き可）。失敗しても最後に出力されます。層ごとの実行：`make lint`、`make rust-test`、`make rust-integration-test`、`make go-test`、`make go-integration-test`、`make js-test`、`make js-integration-test`。

`make test` は `make prometheus-test` も走らせます。これは、このファイルに記された PromQL クエリのすべてを、稼働中のサーバーを収集する実物の Prometheus コンテナを通して実行します —— 存在しない系列を名指ししているだけでなく、*PromQL として*不正なクエリを捕まえるためです。podman を必要としますが、無い場合は失敗するのではなく**声を上げて省略**します。そのためコンテナランタイムの無い機械でも実行は緑のままで、しかもクエリが検証されたふりはしません。その省略を明確な失敗にするには `ROLODEX_PROMETHEUS_REQUIRED=1` を、イメージのミラーを指すには `ROLODEX_PROMETHEUS_IMAGE` を設定してください。

## 開発

試験と開発のためにローカルの開発サーバーを起動します：

```
make dev
```

これは次を行います：
1. プロジェクトをデバッグモードでビルド（`cargo build`）
2. 次の設定で `dev.yml` を用いてサーバーを起動：
   - `127.0.0.1:5300` と主たる外向き IP のポート `5300` 上の DNS リスナー（UDP と TCP）
   - `/tmp/rolodex-dns.sock` の gRPC Unix ソケット（TCP の gRPC リスナーは無し）
   - `/tmp/rolodex-dns-dev.db` の SQLite データベース
   - 認証は不要
   - ブロックリストの照会は無効
   - 既定の上流フォワーダー（`8.8.8.8:53`、`8.8.4.4:53`）。既定の `auto` 解決チェーンの `local` 階層として使われます

`make help` はすべてのターゲットを説明付きで、節ごとにまとめて一覧します（既定のゴールでもあるので、素の `make` でも表示されます）。

リリース最適化された開発サーバーを使うには：
```
make dev-release
```

バイナリを Cargo の bin ディレクトリへインストールするには：
```
make install
```

開発サーバーが動き出したら、`rolodex-dns-cli` バイナリか、`/tmp/rolodex-dns.sock` に接続した Go クライアントライブラリで管理できます。サーバーを止めるには Ctrl+C を押してください。

## コンテナイメージ

Rolodex DNS はビルドホスト上で `cargo-zigbuild` によりバイナリをクロスコンパイルし、そのうえで、削ぎ落とされたバイナリと CA バンドルだけを含む軽量なランタイムイメージ（`debian:bookworm-slim`）を組み立てます。`Containerfile` には意図的に **`RUN` ステップが一つもありません**。これこそが、どのホストからでも、エミュレーションもビルダー VM も無しに、どのアーキテクチャ向けのイメージでも作れるようにしているものです。

イメージは `linux/amd64` と `linux/arm64` を覆うマルチアーキテクチャのマニフェストリストとして `quay.io/town/rolodex` に公開されます。

### マルチアーキテクチャのビルド

ビルドは**ネイティブ**です：各アーキテクチャはそのアーキテクチャのホスト上でコンパイルされます。どのイメージにも `uname -m` の機械名を用いたアーキテクチャ接尾辞が付きます（OCI の `amd64`/`arm64` 名では*なく* `-x86_64` または `-aarch64`）。そのためデプロイ先のホストは、対応付けなしに `` <tag>-`uname -m` `` を取得できます。別立てのマニフェスト手順が、アーキテクチャ別のイメージを一つのマルチアーキテクチャタグへまとめます。

#### アーキテクチャの選択：`TARGET`

`TARGET` はすべてのコンテナターゲット（`image`、`push-arch`、`push-rc`、`push-release`）についてアーキテクチャを選びます。既定はホストのアーキテクチャで、town-os の `install` リポジトリが用いる `TARGET=` の流儀に合わせてあるので、同じ値をどちらにも渡せます：

| `TARGET` | ビルドされるもの |
| -------- | ------ |
| *（未設定）* | ホストのアーキテクチャ |
| `x86_64`、`x86`、`amd64` | amd64 イメージ、`-x86_64` のタグ |
| `aarch64`、`arm64` | arm64 イメージ、`-aarch64` のタグ |
| `rpi` | arm64 イメージ、`-aarch64` のタグ |
| `rg35xxpro`、`rg35xx-pro`、`rg35xx`、`anbernic` | arm64 イメージ、`-aarch64` のタグ |

これ以外の値は、受け付けられる値を並べたエラーになります。ボードの種別はイメージを変えません —— rolodex-dns はボードごとではなくアーキテクチャごとに一つのコンテナイメージを配ります —— が、`install` では固有の意味を持つ `TARGET=rg35xxpro` がここでも筋の通った解決をするように受け付けられます。

**どのホストでもどのアーキテクチャでもビルドできます。** よそのアーキテクチャの `TARGET` はエミュレートではなくクロスコンパイルされるので、拒まれる組み合わせもビルダー VM もありません —— 下のクロスコンパイルを参照してください。

`podman build` の RUN ステップはホストのネットワークを共有します（`--network=host`）。ホストのループバック上の DNS リゾルバー（たとえば rolodex 自身）を使えるようにするためです。`BUILD_NETWORK=` で降りられます。

マルチアーキテクチャイメージを公開するまでの一連の流れ —— アーキテクチャごとに一つのホスト：

1. amd64 ホストで：`make push-release` → `…:latest-x86_64`（と日付タグ）を push。
2. arm64 ホストで：`make push-release` → `…:latest-aarch64`（と日付タグ）を push。
3. どちらかのホストで（両方が push され次第）：`make manifest-release` → マルチアーキテクチャの `…:latest` マニフェストリストを作成して push。

`quay.io/town/rolodex:latest` を取得する側は、そうすると自分のアーキテクチャに合ったイメージを透過的に受け取ります。

#### クロスコンパイル

どちらのアーキテクチャも、`make` を走らせたホストの上で、zig を C クロスコンパイラ兼リンカとする `cargo-zigbuild` によりクロスコンパイルされます。`make deps` はツールチェーン一式を**root なしで**用意し、あわせて `python3` を確認します（`make translation-check` が必要とするもので、root なしでは導入できません）：

```bash
make deps        # rustup のターゲット ＋ cargo-zigbuild ＋ zig、JS の開発依存、そして python3 の確認
make cross-deps  # Rust のクロスツールチェーンだけ
```

素の `rustup target add` では足りません：`rusqlite` は SQLite の同梱 C ソースをコンパイルし、`ring` は C とアセンブリをコンパイルするので、本物のクロス **C** ツールチェーンが無ければビルドは `cc` の段階で失敗します。zig はディストリ固有のパッケージ無しにそれを与え、固定した glibc（`GLIBC_VERSION`、`debian:bookworm` に合わせて既定は `2.36`）に対してリンクするので、ビルドホストが何を積んでいてもバイナリはランタイムイメージ上で動きます。

固定されたバージョンはいずれも上書き可能です：`ZIG_VERSION`、`ZIGBUILD_VERSION`、`GLIBC_VERSION`。

```bash
make image TARGET=x86_64         # クロスコンパイル ＋ amd64 イメージの組み立て
make push-release TARGET=aarch64 # クロスコンパイル ＋ arm64 イメージの push
make push-release-all            # 両アーキテクチャ ＋ マニフェスト、一つのホストから
```

`make image-amd64`、`push-rc-amd64`、`push-release-amd64` は `TARGET=x86_64` 形の別名として残っています。

### ビルド

**ホスト**のアーキテクチャ向けのリリースイメージをビルドします（`quay.io/town/rolodex:latest-<arch>` としてタグ付け）：

```
make image
```

特定のアーキテクチャ向けにビルド：

```
make image TARGET=x86_64
make image TARGET=aarch64
```

特定のタグでビルド：

```
make IMAGE_TAG=v1.2.3 image
```

Cargo のレジストリと git のキャッシュは再ビルドを速めるため `.cache/` に永続化されます。

### Push

Quay.io にログインします（`QUAY_USERNAME` と `QUAY_PASSWORD` を環境または `.env` から読みます）：

```
make quay-login
```

`TARGET` 向けのリリース候補イメージをビルドして push します（`rc.YYYYMMDD-<arch>` と `rc.latest-<arch>`、たとえば `rc.latest-x86_64` / `rc.latest-aarch64` を自動でタグ付け）：

```
make push-rc
make push-rc TARGET=x86_64    # 明示的なアーキテクチャ
```

`TARGET` 向けのリリースイメージをビルドして push します（`release.YYYYMMDD-<arch>` と `latest-<arch>` を自動でタグ付け）：

```
make push-release
make push-release TARGET=aarch64
```

#### マルチアーキテクチャマニフェストの組み立て

**すべての**アーキテクチャについてアーキテクチャ別イメージを push し終えたら（それぞれのネイティブホストで `push-rc`／`push-release` を実行）、どのホストからでもマルチアーキテクチャのマニフェストリストを組み立てて push できます：

```
make manifest-rc       # rc.latest-x86_64 ＋ rc.latest-aarch64 → rc.latest（および rc.YYYYMMDD の日付タグ）をまとめる
make manifest-release  # latest-x86_64 ＋ latest-aarch64 → latest（および release.YYYYMMDD の日付タグ）をまとめる
```

マニフェストはレジストリに既にあるイメージから組み立てられるので（`podman manifest add docker://…`）、アーキテクチャ別イメージがローカルに存在している必要はありません。

#### 特定のタグを push する

自動生成される日付ベースのタグの代わりに、正確なタグでビルドして push するには `IMAGE_TAG` を使います。アーキテクチャ接尾辞はアーキテクチャ別イメージには依然として付きます：

```
make IMAGE_TAG=v1.2.3 push-release    # quay.io/town/rolodex:v1.2.3-<arch> を push
make IMAGE_TAG=v1.2.3 manifest-release # v1.2.3-x86_64 ＋ v1.2.3-aarch64 → v1.2.3 をまとめる
```

`push-rc` / `manifest-rc` でも同じことができます：

```
make IMAGE_TAG=v1.2.3-rc1 push-rc
make IMAGE_TAG=v1.2.3-rc1 manifest-rc
```

すでにビルド済みのイメージを、再ビルドせずに別のタグで push するには：

```
sudo podman tag quay.io/town/rolodex:latest quay.io/town/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:v1.2.3
```

まったく別のレジストリへ push するには：

```
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push registry.example.com/myorg/rolodex:v1.2.3
```

### 後片付け

ローカルのコンテナイメージを削除します：

```
make clean-containers
```

## 設定

Rolodex DNS は YAML ファイルから設定を読みます（既定：`rolodex-dns.yml`、`-c`／`--config` で上書き可）。どの節も任意です —— ファイルが無ければサーバーは既定値で起動します。

一度に一つのサブシステムずつ設定を組み上げていく手引きと、デプロイの形ごとの実例については、**[設定ガイド](CONFIGURATION.ja-JP.md)** を参照してください。以下のリファレンスは完全なフィールド一覧です。

### バインドアドレスの構文

バインドアドレスの文字列（`dns.bind`、`dot.bind`、`doh.bind`、`doq.bind`、`grpc.tcp_bind`、`dhcp.bind` が使います）は四つの形を受け付けます：

| 形 | 例 | 説明 |
| ---- | ------- | ----------- |
| `ip:port` | `192.168.1.1:53` | 特定の IPv4 アドレスとポートにバインド |
| `[ipv6]:port` | `[::1]:53` | 特定の IPv6 アドレスとポートにバインド（角括弧は必須） |
| `primary:port` | `primary:53` | OS の既定経路の外向き IP を検出してそこにバインド |
| `interface:port` | `eth0:53` | 名前で指したネットワークインターフェイス上のすべての IP にバインド |

`primary` というキーワードは、OS が公開インターネットへ届くために使うであろう IP アドレスを（`8.8.8.8:53` への、実際には送信しない UDP connect により）検出し、そのアドレス上に単一のリスナーをバインドします。このキーワードは大小文字を区別しません。

インターフェイスへのバインドは、そのインターフェイスに割り当てられたすべての IPv4 と IPv6 のアドレスを解決し、それぞれに別々のリスナーを作ります。たとえば `eth0` が `192.168.1.5` と `fe80::1` を持つなら、`eth0:53` は `192.168.1.5:53` と `[fe80::1]:53` の両方にリスナーを作ります。

`dot.bind` と `doq.bind` は、**単一のバインド文字列でも、その一覧でも**受け取ります：

```yaml
dot:
  bind:
    - "0.0.0.0:853"
    - "[2001:db8::1]:853"
```

一覧は、一つのリスナーが両方のアドレスファミリを覆うための手立てです。`0.0.0.0` は
IPv4 だけを指し、`[::]` は両方の可搬な代わりにはなりません。`net.ipv6.bindv6only=0`
（Linux の既定）のもとでは `[::]` のソケットは v4 射影のトラフィックも受け取るので、
同じポートの `0.0.0.0` のソケットと衝突し、あとからバインドしたほうが `EADDRINUSE`
で失敗します。代わりに v6 のアドレスを名指してください。各項目は上の四つの書き方を
それぞれ通り、重複は二度バインドされるのではなく取り除かれます。裸の文字列も引き続き
受け取られるので、一覧の書き方が存在する前に書かれた設定はすべてそのまま
解析されます。

`dns.bind` フィールドはプロトコルとアドレスの組の一覧です。各項目は `udp` または `tcp` を鍵、バインドアドレスを値とする単一鍵のマップです：

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "lo:53"
    - tcp: "eth0:53"
```

### 設定例

```yaml
# データベースファイルのパス
database_path: rolodex-dns.db

# 上流 DNS フォワーダー（address:port 形式）。auto チェーンの "local" 階層として、
# または resolution.mode が "forward" のときは唯一の上流として使われます。
# 純粋な権威サーバーにするには（resolution.mode: forward とともに）空の一覧にします
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

# 上流解決の戦略（すべてのフィールドは任意。既定値を示します）
resolution:
  mode: auto              # "auto"（階層チェーン）、"recursive"（ルートのみ）、"forward"
  root_hints: []          # 組み込みの IANA ルートアドレスを上書き
  secure_upstreams:       # 暗号化階層。ルートからの再帰が失敗したときに試されます
    - transport: https    # "https"（DoH :443、推奨）または "tls"（DoT :853）
      addr: "1.1.1.1:443" # IP で接続するので事前の DNS は不要
      hostname: cloudflare-dns.com  # 検証される SNI ／証明書名
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  public_fallback:        # 平文の Do53。最後に試されます
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  switch_grace_failures: 3      # 階層の格下げが確定するまでの、外れたクエリの数
  recovery_probe_secs: 60       # 格下げされたチェーンが上から再試行する間隔
  delegation_persist_min_ttl: 300  # これを超える TTL の委任を永続化します
  default_ttl: 300              # 何も TTL を持たない場合にのみ使う予備の値

# ルートから解決された応答の DNSSEC 検証（反復経路のみ）
dnssec:
  validate: true          # Bogus なデータは SERVFAIL となり決してキャッシュされません
  trust_anchors: []       # 空 = IANA のルート鍵。上書きはそれらを置き換えます

# 各項目はプロトコル（udp/tcp）とバインドアドレスを組にします。
# バインドアドレスは ip:port、[ipv6]:port、primary:port、interface:port を受け付けます。
dns:
  bind:
    - udp: "0.0.0.0:53"     # 特定のインターフェイスにバインドするなら "eth0:53"
    - tcp: "0.0.0.0:53"
  auto_ptr: false           # gRPC 経由で追加された A/AAAA の逆引き PTR を維持
  ingress_listen_port: 53   # TLD ごとの入口リスナーのポート（IP は TLD ごと）

# DNS-over-TLS（RFC 7858）
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false
    # 証明書が生成されるときにのみ使われます。ループバックの名前とリスナー自身の
    # バインドアドレスは自動で覆われるので、この機体をクライアントが呼ぶ
    # ほかの名前をここに並べます。
    self_signed_sans: []

# DNS-over-HTTPS（RFC 8484）
doh:
  bind: "0.0.0.0:443"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false
  enable_h3: false

# DNS-over-QUIC（RFC 9250）
doq:
  bind: "0.0.0.0:8853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

grpc:
  # TCP の gRPC リスナー（空文字列で無効）
  tcp_bind: "127.0.0.1:50051"
  # Unix ソケットのパス（空文字列で無効）
  unix_socket: /var/run/rolodex-dns.sock
  # TCP の gRPC 認証のための共有秘密（Unix ソケットには不要）
  shared_secret: your-secret-here

# ドメインブロックリスト（名前で照会。外部解決の前に行われます）
dnsbl:
  # ブロックリストの照会を全体として有効／無効にします（既定：false）
  enabled: false
  # こちらのクエリを拒否したプロバイダーがローテーションから外れる秒数
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
      # 「掲載」ではなく「クエリを拒否」を意味するコード。組み込みの一式を使うなら省略。
      # "none" ひとつだけを書くと、このプロバイダーの拒否検出を無効にします。
      refusal_codes: []
      # ローテーションから外す時間のプロバイダー単位の上書き（継承するなら省略）
      refusal_cooldown_secs: 3600
    - zone: multi.surbl.org
      enabled: true

# 統合 DHCPv4 サーバー（節を省くと無効）
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # 必須：ホスト名は <host>.lan.<tld>. として登録されます
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60

# ACME 発行者／認証局（節を省くと無効）
acme:
  bind: "0.0.0.0:8555"                    # クライアント向けの ACME HTTPS リスナー
  portal_bind: "127.0.0.1:8500"           # 信頼されたネットワーク向けの登録ポータル
  directory_url: "https://dns.example.com:8555/acme"  # クライアントに広告されます
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  tlsa_port: 443
  tlsa_proto: tcp
  require_eab: true
  issuance_scope: managed_zones           # または "any"

# 転送する DNS クエリのための HTTP プロキシ
proxy:
  url: "http://proxy:8080"
  auth: "user:pass"
  mode: "connect"  # "connect"（HTTP CONNECT トンネル）、"socks5"（SOCKS5 プロキシ）、"doh"（DoH クエリをプロキシ）

# TTL ドリフトの調整
ttl_drift:
  mode: "fixed"          # "fixed" または "logarithmic"（実験的）
  fixed_adjustment: "5m" # 例："5m"、"-30s"、"1h30m"、"2d12h"（固定モードのみ）
  log_multiplier: 1.0    # 乗数（対数モードのみ、実験的）

# DNS64 の AAAA 合成
dns64:
  enabled: false
  prefix: "64:ff9b::"    # 既定のよく知られたプレフィックス（64:ff9b::/96）

# アドレスファミリごとの応答の選好
address_family:
  mode: auto              # "auto"（プローブして抑制）、"off"、"force4"、"force6"
  probe_interval_secs: 30
  fail_threshold: 2       # ファミリが落ちたと見なすまでの失敗周期の数
  probe_timeout_secs: 2
  targets_v4: ["1.1.1.1:443", "8.8.8.8:443"]
  targets_v6: ["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]

# セキュリティの設定
security:
  qname_case_randomization: true  # 転送クエリのための 0x20 符号化
  overlay_cidrs: ["10.64.0.0/10"] # ネットワークスコープの強制を受ける発信元の範囲
  # 誰が上流解決を駆動してよいか。この一覧の外の発信元も、このサーバーが権威を
  # 持つ応答は受け取れますが、機体の外へ届くものはすべて REFUSED になります。
  # 空の一覧 = 誰に対しても純粋に権威のみ。
  recursion_cidrs:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "100.64.0.0/10"
    - "::1/128"
    - "fe80::/10"
    - "fc00::/7"

# Prometheus の収集エンドポイント（節を省くとリスナーを起動しません）
metrics:
  bind: "127.0.0.1:9153"
  # TLD ごとのクエリメトリクスで独自の `tld` ラベルを与えられる TLD。所有 TLD は
  # 自動で追跡されます。追跡されていないものはすべて `other` にまとめられます。
  tracked_tlds:
    - common
```

### 設定オプション

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `database_path` | `"rolodex-dns.db"` | SQLite データベースファイルのパス |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | 上流 DNS リゾルバーのアドレス（`auto` モードでは `local` 階層、`forward` モードでは唯一の上流） |
| `resolution.mode` | `"auto"` | 上流の戦略：`"auto"`（階層チェーン）、`"recursive"`（ルートのみ）、`"forward"`（フォワーダーのみ）。**起動時の種にすぎません** —— `SetResolutionMode` は動いているサーバーのモードを再起動なしで変え、`GetResolutionMode` は実際に有効なものを報告します |
| `resolution.root_hints` | `[]`（組み込みの IANA ルート） | `recursive`／`auto` モードで使うルートサーバーのヒントを上書きします |
| `resolution.secure_upstreams` | DoH 上の Cloudflare ＋ Google | `secure` 階層の暗号化上流：`{transport, addr, hostname, path}` |
| `resolution.public_fallback` | `["1.1.1.1:53", "8.8.8.8:53"]` | 平文の公開リゾルバー。`auto` モードで最後に試されます |
| `resolution.switch_grace_failures` | `3` | `auto` の階層格下げが確定するまでの、連続して外れたクエリの数 |
| `resolution.recovery_probe_secs` | `60` | 格下げされた `auto` チェーンが最上位階層から再試行する間隔 |
| `resolution.delegation_persist_min_ttl` | `300` | 学習した委任を SQLite に永続化するための最小 TTL |
| `resolution.default_ttl` | `300` | レコードや応答が自前の TTL を持たない場合の予備の TTL |
| `dnssec.validate` | `true` | 反復的に解決された応答を DNSSEC 検証します（`recursive` モードと `auto` のルート階層）。Bogus および Indeterminate なデータは SERVFAIL となり、決してキャッシュされません |
| `dnssec.trust_anchors` | `[]`（IANA のルート鍵） | DNSKEY の表示形式によるアンカー、`"<flags> <protocol> <algorithm> <base64 key>"` —— `dig DNSKEY .` が表示するとおりの RDATA フィールドです。すべてのフィールドが起動時に検証され、不正なものは即座の失敗となります。上書きは IANA の鍵に**加える**のではなく**置き換えます** |
| `dns.bind` | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | DNS リスナー。`{udp: アドレス}`／`{tcp: アドレス}` 項目の一覧 |
| `dns.auto_ptr` | `false` | gRPC 経由で追加された A/AAAA について逆引き PTR レコードを維持します |
| `dns.ingress_listen_port` | `53` | TLD ごとの入口リスナーの UDP/TCP ポート（バインド IP は TLD ごと） |
| `dns.udp_shards` | `0`（コアごとに一つ） | UDP の待ち受けアドレスごとにバインドされる `SO_REUSEPORT` ソケットの数。単一のソケットはリスナーを直列化し —— 受信ループは一つ、どの応答も同じソケット —— CPU の飽和よりずっと手前でスループットに蓋をします。分割すればカーネルがデータグラムをコア間に散らせます。従来の単一ソケットの挙動にするには `1` を設定します |
| `dot.bind` | `""`（無効） | DoT リスナー。interface:port に対応（通常はポート 853）。**単一のアドレスまたは一覧**を受け取ります —— 一覧は、一つのリスナーが両方のアドレスファミリを覆うための手立てです |
| `dot.tls.cert_path` | `""` | DoT の TLS 証明書のパス |
| `dot.tls.key_path` | `""` | DoT の TLS 秘密鍵のパス |
| `dot.tls.auto_self_signed` | `true` | DoT の自己署名証明書を自動生成します |
| `dot.tls.self_signed_sans` | `[]` | 生成される DoT 証明書に追加するサブジェクト代替名。ループバック一式とリスナーのバインドアドレスは自動で追加されます。ワイルドカードのバインド（`0.0.0.0`）は何も寄与しないので、この機体の名前はここに書いてください |
| `doh.bind` | `""`（無効） | DoH リスナー。interface:port に対応（通常はポート 443） |
| `doh.tls.cert_path` | `""` | DoH の TLS 証明書のパス |
| `doh.tls.key_path` | `""` | DoH の TLS 秘密鍵のパス |
| `doh.tls.auto_self_signed` | `true` | DoH の自己署名証明書を自動生成します |
| `doh.tls.self_signed_sans` | `[]` | `dot.tls.self_signed_sans` と同じ、DoH 向け |
| `doh.enable_h3` | `false` | DoH の HTTP/3（QUIC）トランスポートを有効にします |
| `doq.bind` | `""`（無効） | DoQ リスナー。interface:port に対応（通常はポート 8853）。`dot.bind` と同じく、**単一のアドレスまたは一覧**を受け取ります |
| `doq.tls.cert_path` | `""` | DoQ の TLS 証明書のパス |
| `doq.tls.key_path` | `""` | DoQ の TLS 秘密鍵のパス |
| `doq.tls.auto_self_signed` | `true` | DoQ の自己署名証明書を自動生成します |
| `doq.tls.self_signed_sans` | `[]` | `dot.tls.self_signed_sans` と同じ、DoQ 向け |
| `grpc.tcp_bind` | `"127.0.0.1:50051"` | TCP の gRPC リスナー。interface:port に対応（空で無効） |
| `grpc.unix_socket` | `"/var/run/rolodex-dns.sock"` | Unix ソケットのパス（空で無効） |
| `grpc.shared_secret` | `""` | TCP の gRPC 認証のための共有秘密（空 = 認証なし） |
| `dnsbl.enabled` | `false` | ドメインブロックリスト（DNSBL）の照会を全体として有効にします |
| `dnsbl.providers[].zone` | -- | 問い合わせる DNSBL ゾーン（照会される名前が前に付けられます） |
| `dnsbl.providers[].enabled` | `true` | 個々の DNSBL プロバイダーを有効／無効にします |
| `dnsbl.providers[].refusal_codes` | `[]`（組み込みの一式） | 「掲載」ではなく「クエリを拒否」を意味する応答。各項目は IPv4 アドレスまたは `アドレス/プレフィックス` です。空は組み込みの一式を意味し、`none` ひとつだけならそのプロバイダーの検出を無効にします。明示的な一覧は既定を拡張するのではなく置き換え、解釈できないコードは起動時に拒否されます（[拒否コード](#拒否コードとプロバイダーのローテーション)を参照） |
| `dnsbl.providers[].refusal_cooldown_secs` | （一覧の既定） | 拒否のあとローテーションから外す時間のプロバイダー単位の設定 |
| `dnsbl.refusal_cooldown_secs` | `3600` | 自前の設定を持たないプロバイダーについて、拒否したプロバイダーがローテーションから外れる秒数。`0` は「冷却なし」ではなく「既定を使う」を意味します |
| `dhcp.bind` | `"0.0.0.0:67"` | DHCP リスナー（節が無い = DHCP は無効） |
| `dhcp.tld` | -- | DHCP を有効にするなら必須：ホスト名は `<host>.lan.<tld>.` として登録されます |
| `dhcp.default_lease_duration` | `3600` | 既定のリース期間（秒） |
| `dhcp.reclaim_timeout` | `86400` | 期限切れから IP を回収するまでの秒数 |
| `dhcp.sweep_interval` | `60` | 背景でのリース掃除の間隔（秒） |
| `acme.bind` | `"0.0.0.0:8555"` | クライアント向けの ACME HTTPS リスナー（節が無い = ACME は無効） |
| `acme.portal_bind` | `"127.0.0.1:8500"` | 信頼されたネットワーク向けの登録ポータルのリスナー |
| `acme.directory_url` | `"https://localhost:8555/acme"` | クライアントに広告される外部の ACME ディレクトリ URL（設定してください） |
| `acme.root_ca_cn` | `"Rolodex Root CA"` | 起動時に作られるルート CA のコモンネーム |
| `acme.leaf_validity_days` | `90` | 発行されるリーフ証明書の有効期間 |
| `acme.tlsa_port` / `acme.tlsa_proto` | `443` / `"tcp"` | 名前ごとに DANE-TA の TLSA レコードを公開する場所 |
| `acme.require_eab` | `true` | アカウント登録に External Account Binding を要求します |
| `acme.issuance_scope` | `"managed_zones"` | `"managed_zones"`（ゾーンに CA が必要）または `"any"` |
| `proxy.url` | `""`（無効） | 転送する DNS クエリのための HTTP プロキシ URL |
| `proxy.auth` | `""` | プロキシの認証（`"user:pass"`） |
| `proxy.mode` | `"connect"` | プロキシのモード：`"connect"`（HTTP CONNECT）、`"socks5"`（SOCKS5）、`"doh"` |
| `ttl_drift.mode` | `"disabled"` | TTL ドリフトのモード：`"disabled"`、`"fixed"`、`"logarithmic"` |
| `ttl_drift.fixed_adjustment` | `""` | 固定の TTL 調整。単純な形（`"5m"`、`"-30s"`、`"1h"`、`"2d"`）と複合の期間（`"1h30m"`、`"2d12h"`）に対応 |
| `ttl_drift.log_multiplier` | `0.1` | 対数モードの乗数（上流の遅延に基づいて TTL を調整します） |
| `dns64.enabled` | `false` | DNS64 の AAAA 合成を有効にします |
| `dns64.prefix` | `"64:ff9b::"` | DNS64 合成のための IPv6 プレフィックス |
| `security.qname_case_randomization` | `true` | 0x20 の QNAME 大小文字ランダム化を有効にします |
| `security.overlay_cidrs` | `["10.64.0.0/10"]` | 信頼できないオーバーレイのピアとして扱われ、スコープを強制される発信元の範囲。それ以外の発信元はすべて信頼されます |
| `security.recursion_cidrs` | ループバック、RFC 1918、リンクローカル、ULA、CGNAT | **上流**解決を駆動してよい発信元の範囲。それ以外にはローカル／権威のデータが提供され、機体の外へ届くものはすべて REFUSED になります。空の一覧は誰に対しても再帰を閉じます（[再帰のアクセス制御](#再帰のアクセス制御)を参照） |
| `address_family.mode` | `"auto"` | `"auto"`（プローブして、経路の無いファミリを抑制）、`"off"`、`"force4"`、`"force6"` |
| `address_family.probe_interval_secs` | `30` | `auto` モードでの経路到達性プローブの間隔（秒） |
| `address_family.fail_threshold` | `2` | ファミリが落ちたと印を付けるまでの連続失敗周期の数（回復は即座です） |
| `address_family.probe_timeout_secs` | `2` | 各プローブの宛先ごとの TCP 接続タイムアウト |
| `address_family.targets_v4` / `targets_v6` | `:443` 上の Cloudflare/Google | ファミリごとのプローブ先（IP リテラル） |
| `metrics.bind` | `127.0.0.1:9153` | Prometheus の `/metrics` HTTP リスナー。interface:port に対応。この節は任意で既定では省かれ、その場合リスナーは起動しません（[Prometheus メトリクス](#prometheus-メトリクス)を参照） |
| `metrics.tracked_tlds` | `[]` | TLD ごとのクエリメトリクスで独自の `tld` ラベル値を与えられる TLD。所有 TLD は自動で追跡され、`common` は組み込みの一般 TLD 一式に展開され、追跡されていないものはすべて `other` にまとめられます |

## 使い方

### サーバー

```
rolodex-dns [OPTIONS]

Options:
  -c, --config <CONFIG>  設定ファイルのパス [既定: rolodex-dns.yml]
  -h, --help             ヘルプを表示
```

### CLI クライアント

`rolodex-dns-cli` は、稼働中の Rolodex DNS サーバーを gRPC 管理インターフェイス経由で管理するためのコマンドラインクライアントです。TCP と Unix ソケットの両方のトランスポートに対応します。

```
rolodex-dns-cli [OPTIONS] <COMMAND>
```

#### 全体オプション

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-a, --address <ADDRESS>` | `127.0.0.1:50051` | TCP 接続のための gRPC サーバーアドレス（host:port）。`--unix-socket` が設定されているときは無視されます。 |
| `-u, --unix-socket <PATH>` | -- | Unix ドメインソケットのパス。`--address` より優先されます。Unix ソケット接続は認証を迂回します。 |
| `-t, --auth-token <TOKEN>` | `""` | TCP 接続のための認証トークン。サーバーに共有秘密が設定されているときは必須です。Unix ソケット接続では無視されます。 |
| `-h, --help` | -- | ヘルプを表示 |
| `-V, --version` | -- | バージョンを表示 |

#### コマンド

| コマンド | 説明 |
|---------|-------------|
| **レコード** | |
| `add-record` | ローカルデータベースに DNS レコードを追加 |
| `remove-record` | ローカルデータベースから DNS レコードを削除 |
| `list-records` | 任意のフィルタで DNS レコードを一覧 |
| **フォワーダーと解決** | |
| `set-forwarders` | 実行中に上流 DNS フォワーダーを設定 |
| `set-resolution-mode` | 上流の解決モード（`auto`、`recursive`、`forward`）を実行中に切り替え |
| `get-resolution-mode` | いま効いている解決モードを表示 |
| **ブロックリスト** | |
| `set-dnsbl-config` | 実行中にドメインブロックリスト（DNSBL）の設定を変更 |
| `get-dnsbl-config` | 現在の DNSBL 設定を取得 |
| `flush-cache` | ブロックリストの結果キャッシュを破棄 |
| `add-local-blocklist` | ローカルブロックリストに項目を追加 |
| `remove-local-blocklist` | ローカルブロックリストの項目を削除 |
| `list-local-blocklist` | ローカルブロックリストの全項目を一覧 |
| `add-dnsbl-allow` | ある名前（とその配下）をブロックリストの照会から免除 |
| `remove-dnsbl-allow` | DNSBL 許可リストの項目を削除 |
| `list-dnsbl-allow` | DNSBL 許可リストの全項目を一覧 |
| **ネットワークスコープ** | |
| `create-scope` | 新しいネットワークスコープを作成 |
| `delete-scope` | ネットワークスコープとそのデータをすべて削除 |
| `list-scopes` | 設定されたネットワークスコープをすべて一覧 |
| `join-network` | IP をスコープに結び付ける |
| `leave-network` | IP のスコープとの結び付きを解除 |
| `list-associations` | IP とスコープの結び付きを一覧 |
| `add-scoped-record` | スコープ内に DNS レコードを追加 |
| `remove-scoped-record` | スコープから DNS レコードを削除 |
| `list-scoped-records` | スコープ内の DNS レコードを一覧 |
| `get-search-domains` | ある IP の検索ドメインを取得 |
| **所有 TLD ／入口** | |
| `add-scope-tld` | スコープに全域で一意な所有 TLD を登録（任意の `--listen-ip` で入口リスナーも起動） |
| `remove-scope-tld` | スコープから所有 TLD を削除 |
| `list-scope-tlds` | スコープが所有する TLD を一覧 |
| `set-scope-tld-forwarders` | スコープの TLD のピアフォワーダーを設定 |
| `list-scope-tld-forwarders` | スコープの TLD のピアフォワーダーを一覧 |
| `list-scope-tld-listeners` | スコープの TLD に結び付いた入口 DNS リスナーを一覧 |
| **権威ゾーン** | |
| `add-auth-zone` | ゾーンを権威として宣言 |
| `remove-auth-zone` | 権威一覧からゾーンを削除 |
| `list-auth-zones` | すべての権威ゾーンを一覧 |
| **キャッシュ** | |
| `cache-stats` | DNS キャッシュのヒット／ミス統計を表示 |
| `flush-dns-cache` | DNS 応答キャッシュを破棄 |
| **DHCP** | |
| `add-dhcp-pool` / `remove-dhcp-pool` / `list-dhcp-pools` | スコープ単位の DHCP アドレスプールを管理 |
| `list-dhcp-leases` / `delete-dhcp-lease` | DHCP リースを調べ、削除 |
| `set-dhcp-cert` / `remove-dhcp-cert` / `list-dhcp-certs` | DHCP オプションによる証明書配布を管理 |
| **DNSSEC** | |
| `generate-dnssec-key` | DNSSEC 鍵ペア（KSK または ZSK）を生成 |
| `list-dnssec-keys` | ゾーンの DNSSEC 鍵を一覧 |
| `sign-zone` | ゾーンをその DNSSEC 鍵で署名 |
| **DANE / ACME** | |
| `generate-tlsa` | 証明書から TLSA レコードを生成 |
| `request-acme-cert` | ACME DNS-01 で証明書を要求 |
| `acme-status` | ACME 証明書の状態を確認 |
| `ensure-zone-ca` | ゾーン単位の中間 CA の存在を確かめ、ルートと中間の PEM を表示し、CA の連鎖を DNS に公開 |
| `create-eab` / `remove-eab` | ゾーンに限定された EAB 資格情報を発行または削除 |
| `list-acme-accounts` | 登録済みの ACME アカウントを一覧 |
| `list-acme-certs` | 発行済みの証明書を一覧 |
| **TTL ドリフト** | |
| `set-ttl-drift` / `get-ttl-drift` | TTL ドリフトの設定を変更／取得 |
| **DNS64** | |
| `set-dns64` / `get-dns64` | DNS64 の設定を変更／取得 |
| **可観測性** | |
| `latency-stats` | サーバーごとの上流クエリ遅延を表示 |

トランスポート（DoT/DoH/DoQ）、プロキシ、そしていくつかの DNSSEC/DANE 操作は gRPC からは使えますが CLI のサブコマンドはありません —— [追加の gRPC メソッド](#追加の-grpc-メソッド)を参照してください。各コマンドのフラグ一式は `rolodex-dns-cli <COMMAND> --help` で確認できます。

##### `add-record`

ローカルデータベースに DNS レコードを追加します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/AddRecord`

```
rolodex-dns-cli add-record -n <NAME> -v <VALUE> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | 完全修飾ドメイン名（例 `"example.com."` —— 末尾のドットを推奨） |
| `-r, --record-type <TYPE>` | `a` | DNS レコード型（レコード型の表を参照） |
| `-v, --value <VALUE>` | -- | レコードのデータ。形式はレコード型によります（レコード型の節を参照） |
| `--ttl <TTL>` | `300` | 生存時間（秒）。0 を設定するとサーバーは 300 を既定とします |
| `-p, --priority <PRIORITY>` | `0` | MX と SRV レコードの優先度。値が小さいほど優先度は高くなります。ほかの型では無視されます |

例：
```bash
# TCP 経由で A レコードを追加
rolodex-dns-cli -a 127.0.0.1:50051 -t my-secret add-record \
  -n example.com. -r a -v 10.0.0.1 --ttl 600

# Unix ソケット経由で MX レコードを追加
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  -n example.com. -r mx -v mail.example.com. -p 10

# CNAME レコードを追加
rolodex-dns-cli add-record -n www.example.com. -r cname -v example.com.

# SRV レコードを追加
rolodex-dns-cli add-record -n _sip._tcp.example.com. -r srv \
  -v "5 5060 sip.example.com." -p 10

# URI レコードを追加
rolodex-dns-cli add-record -n example.com. -r uri \
  -v "10 1 \"https://example.com/\"" -p 10

# SSHFP レコードを追加
rolodex-dns-cli add-record -n host.example.com. -r sshfp \
  -v "2 1 123456789abcdef..."

# ワイルドカードレコードを追加
rolodex-dns-cli add-record -n "*.example.com." -r a -v 10.0.0.99
```

##### `remove-record`

ローカルデータベースから DNS レコードを削除します。名前で削除し、任意で型と値のフィルタを掛けられます。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/RemoveRecord`

```
rolodex-dns-cli remove-record -n <NAME> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | 削除するレコードの完全修飾ドメイン名 |
| `-r, --record-type <TYPE>` | -- | 指定すると、この型のレコードのみを削除します。省くとその名前のすべての型を削除します |
| `-v, --value <VALUE>` | -- | 指定すると、この値と完全に一致するレコードのみを削除します |

例：
```bash
# ある名前のすべてのレコードを削除
rolodex-dns-cli remove-record -n old.example.com.

# ある名前の A レコードのみを削除
rolodex-dns-cli remove-record -n example.com. -r a

# 値を指定して特定のレコードを削除
rolodex-dns-cli remove-record -n example.com. -r a -v 10.0.0.1
```

##### `list-records`

ローカルデータベースの DNS レコードを、任意のフィルタで一覧します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/ListRecords`

```
rolodex-dns-cli list-records [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | ドメイン名でフィルタします。すべての下位ドメインに一致させるワイルドカード接頭辞 `"*."` に対応（例 `"*.example.com."`） |
| `-r, --record-type <TYPE>` | -- | レコード型でフィルタします。省くとすべてのレコード型を返します |

例：
```bash
# すべてのレコードを一覧
rolodex-dns-cli list-records

# 特定の名前のレコードを一覧
rolodex-dns-cli list-records -n example.com.

# すべての下位ドメインを一覧
rolodex-dns-cli list-records -n "*.example.com."

# AAAA レコードのみを一覧
rolodex-dns-cli list-records -r aaaa
```

##### `set-forwarders`

実行中に上流 DNS フォワーダーを設定します。フォワーダーの一覧全体を置き換えます。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/SetForwarders`

```
rolodex-dns-cli set-forwarders -f <ADDR>...
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-f, --forwarders <ADDR>...` | -- | `"host:port"` 形式の上流 DNS サーバーのアドレス。複数のアドレスは空白で区切ります |

例：
```bash
# Google と Cloudflare の DNS を設定
rolodex-dns-cli set-forwarders -f 8.8.8.8:53 1.1.1.1:53

# 単一のフォワーダーを設定
rolodex-dns-cli set-forwarders -f 9.9.9.9:53

# すべてのフォワーダーを削除（純粋な権威モード）
rolodex-dns-cli set-forwarders -f ""
```

##### `set-resolution-mode`

このサーバーが権威を持たない名前の解決のしかたを、再起動なしで切り替えます。設定
ファイルの `resolution.mode` は起動時の種にすぎません —— 実際に問い合わせを解決して
いるモードを変えるのはこちらです。
**gRPC のパス：** `/rolodex_dns.RolodexDnsService/SetResolutionMode`

```
rolodex-dns-cli set-resolution-mode -m <MODE>
```

| オプション | 既定 | 説明 |
|------------|------|------|
| `-m, --mode <MODE>` | -- | `auto`、`recursive`、`forward` のいずれか。大文字小文字は区別しません |

認識できないモードは、設定ファイルのように黙って `auto` へ落とすのではなく
`InvalidArgument` で拒否されます。モードを打ち間違えた呼び出し側に対して、機体が
あるモードにあると告げながら別のモードで解決している、ということがあってはなりません。

例：
```bash
# ルート優先のフォールバックチェーン（既定）
rolodex-dns-cli set-resolution-mode -m auto

# フォールバックなしで、ルートからの反復のみ
rolodex-dns-cli set-resolution-mode -m recursive

# 設定されたフォワーダーのみ
rolodex-dns-cli set-resolution-mode -m forward
```

`auto` へ*切り替える*と階層の暖機がやり直されるので、切り替え直後の最初の
問い合わせが冷えた階層の代償を払うことは
ありません。

##### `get-resolution-mode`

現在有効なモードを表示します。これは実際に問い合わせを解決しているモードであって、
設定ファイルが名指しているものとは限りません —— `set-resolution-mode` のあとでは
両者は異なります。
**gRPC のパス：** `/rolodex_dns.RolodexDnsService/GetResolutionMode`

```
rolodex-dns-cli get-resolution-mode
```

例：
```bash
$ rolodex-dns-cli get-resolution-mode
Resolution mode: auto
```

##### `flush-cache`

ブロックリストの結果キャッシュを破棄します。以後のクエリについて新鮮な参照を強います。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/FlushCache`

```
rolodex-dns-cli flush-cache
```

##### `create-scope`

予約された `.home` ドメインを持つ新しいネットワークスコープを作成します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

```
rolodex-dns-cli create-scope -n <NAME> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | ネットワークスコープの一意な名前（例 `"office"`、`"lab"`） |
| `-d, --home-domain <DOMAIN>` | `"<name>.home."` | このスコープのために予約する `.home` ドメイン。省くと `"<name>.home."` が既定になります |

例：
```bash
# 既定の home ドメインでスコープを作成
rolodex-dns-cli create-scope -n office
# home ドメイン "office.home." を持つスコープ "office" が作られます

# 独自の home ドメインでスコープを作成
rolodex-dns-cli create-scope -n lab -d lab.internal.
```

##### `delete-scope`

ネットワークスコープと、そのレコードおよび結び付きをすべて削除します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

```
rolodex-dns-cli delete-scope -n <NAME>
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | 削除するスコープの名前 |

##### `list-scopes`

設定されたネットワークスコープをすべて一覧します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

```
rolodex-dns-cli list-scopes
```

##### `join-network`

IP アドレスをネットワークスコープに結び付けます。この結び付きには TTL があり、定期的に更新しなければなりません。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/JoinNetwork`

```
rolodex-dns-cli join-network -i <IP> -s <SCOPE> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | 結び付けるクライアントの IP アドレス（例 `"192.168.1.100"`） |
| `-s, --scope <SCOPE>` | -- | 参加するネットワークスコープの名前 |
| `--ttl <TTL>` | `300` | 結び付きの TTL（秒）。期限が切れる前に更新しなければなりません。0 なら既定は 300 です |

例：
```bash
# 既定の TTL で参加
rolodex-dns-cli join-network -i 192.168.1.100 -s office

# 独自の TTL で参加
rolodex-dns-cli join-network -i 10.0.0.5 -s lab --ttl 600
```

##### `leave-network`

ある IP アドレスとネットワークスコープとの結び付きを解除します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

```
rolodex-dns-cli leave-network -i <IP>
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | 結び付きを解除するクライアントの IP アドレス |

##### `list-associations`

IP とスコープの結び付きを、任意でスコープごとに絞って一覧します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

```
rolodex-dns-cli list-associations [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | スコープ名でフィルタします。省くとすべての結び付きを一覧します |

##### `add-scoped-record`

特定のネットワークスコープ内に DNS レコードを追加します。スコープ付きレコードは、そのスコープに結び付いた IP からのみ見えます。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

```
rolodex-dns-cli add-scoped-record -s <SCOPE> -n <NAME> -v <VALUE> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | レコードを追加するネットワークスコープ |
| `-n, --name <NAME>` | -- | 完全修飾ドメイン名 |
| `-r, --record-type <TYPE>` | `a` | DNS レコード型 |
| `-v, --value <VALUE>` | -- | レコードのデータ |
| `--ttl <TTL>` | `300` | 生存時間（秒） |
| `-p, --priority <PRIORITY>` | `0` | MX と SRV レコードの優先度 |

例：
```bash
# スコープ付きの A レコードを追加
rolodex-dns-cli add-scoped-record -s office -n printer.office.home. -v 192.168.1.50

# スコープ付きの CNAME を追加
rolodex-dns-cli add-scoped-record -s lab -n app.lab.home. -r cname -v server.lab.home.
```

##### `remove-scoped-record`

特定のネットワークスコープから DNS レコードを削除します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

```
rolodex-dns-cli remove-scoped-record -s <SCOPE> -n <NAME> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | レコードを削除するネットワークスコープ |
| `-n, --name <NAME>` | -- | 完全修飾ドメイン名 |
| `-r, --record-type <TYPE>` | -- | レコード型でフィルタ |
| `-v, --value <VALUE>` | -- | 完全一致する値でフィルタ |

##### `list-scoped-records`

ネットワークスコープ内の DNS レコードを一覧します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

```
rolodex-dns-cli list-scoped-records -s <SCOPE> [OPTIONS]
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | 問い合わせるネットワークスコープ |
| `-n, --name <NAME>` | -- | ドメイン名でフィルタ（ワイルドカード接頭辞 `"*."` に対応） |
| `-r, --record-type <TYPE>` | -- | レコード型でフィルタ |

##### `get-search-domains`

クライアントの IP アドレスに対する検索ドメインを取得します。
**gRPC パス：** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

```
rolodex-dns-cli get-search-domains -i <IP>
```

| オプション | 既定 | 説明 |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | 調べるクライアントの IP アドレス |

## gRPC API

管理 API は `proto/rolodex_dns.proto` に定義されています。すべてのメソッドは、TCP で接続するときの共有秘密による認証のために `auth_token` フィールドを受け付けます。Unix ソケット接続は認証を迂回します。

API の完全なリファレンスは proto ファイルを参照してください。サービスは 74 の RPC メソッドを定義しており、レコード管理、ネットワークスコープ、所有 TLD と入口、ブロックリスト、DHCP、暗号化トランスポート、DNSSEC、DANE/ACME、キャッシュ、DNS64、メトリクス、可観測性を覆います。

### サービス：`rolodex_dns.RolodexDnsService`

#### `AddRecord`

**パス：** `/rolodex_dns.RolodexDnsService/AddRecord`

ローカルデータベースに DNS レコードを追加します。

**パラメータ：**
- `record`（DnsRecord、必須）：追加する DNS レコード
  - `name`（string）：完全修飾ドメイン名（例 `"example.com."`）
  - `record_type`（RecordType）：DNS レコードの型（下のレコード型を参照）
  - `value`（string）：レコードのデータ（IP アドレス、ホスト名など）
  - `ttl`（uint32）：生存時間（秒）。既定：0 を設定すると 300
  - `priority`（uint32）：MX/SRV レコードの優先度（ほかの型では無視）。既定：0
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `RemoveRecord`

**パス：** `/rolodex_dns.RolodexDnsService/RemoveRecord`

ローカルデータベースから DNS レコードを削除します。

**パラメータ：**
- `name`（string、必須）：完全修飾ドメイン名
- `record_type`（RecordType）：設定するとこの型のレコードのみを削除します。未設定（A/0）ならその名前のすべてのレコードを削除します
- `value`（string）：空でなければ、この値と完全に一致するレコードのみを削除します
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `removed_count`（uint32）：削除されたレコードの数
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `ListRecords`

**パス：** `/rolodex_dns.RolodexDnsService/ListRecords`

ローカルの DNS データベースを、任意のフィルタで問い合わせます。

**パラメータ：**
- `name_filter`（string）：ドメイン名でフィルタします。すべての下位ドメインに一致させるワイルドカード接頭辞 `"*."` に対応（例 `"*.example.com."`）
- `record_type_filter`（RecordType）：レコード型でフィルタ（`filter_by_type` が真のときのみ適用）
- `filter_by_type`（bool）：`record_type_filter` を適用するかどうか。既定：偽
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `records`（repeated DnsRecord）：一致した DNS レコード

#### `SetForwarders`

**パス：** `/rolodex_dns.RolodexDnsService/SetForwarders`

実行中に上流 DNS フォワーダーを設定します。

**パラメータ：**
- `forwarders`（repeated string）：`"host:port"` 形式の上流 DNS サーバーアドレスの一覧（例 `"8.8.8.8:53"`）
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `SetResolutionMode`

**パス：** `/rolodex_dns.RolodexDnsService/SetResolutionMode`

上流の解決モードを実行時に変更します。

`resolution.mode` はそれ以外では起動時にしか読まれない設定であり、そのためこれは、
オーケストレーターがそのファイルを書き直してプロセスを再起動しない限り変えられない
唯一の上流の挙動でした —— そして機体で唯一のリゾルバーの再起動は、その上のすべてに
とっての DNS の停止です。

**パラメータ：**
- `mode`（string）：`"auto"`（ルート優先のフォールバックチェーン）、`"recursive"`（ルートからの反復のみ）、`"forward"`（設定されたフォワーダーのみ）。大文字小文字は区別しません
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

認識できないモードは、設定ファイルの経路のように `auto` へ落とすのではなく
`InvalidArgument` を返します。ファイルは、警告を読めるオペレーターが起動時に一度
読むものです。しかし RPC の向こうには答えを待つ呼び出し側がおり、頼んでもいない
モードで解決しながら「成功」と告げることこそ、`:53` を濾すネットワーク上で機体が
`recursive` に落ち、あらゆる名前が失敗する理由がログのどこにも無い、という事態の
始まりです。

`auto` へ**切り替える**と、起動時の経路と同じ階層の暖機が走るので、切り替え
直後の最初の問い合わせが冷えた階層の代償を払うことはありません。階層の回復
探索は無条件に走るので、実行時に `auto` へ切り替えられたモードでも、回復した
階層を取り戻せます。

#### `GetResolutionMode`

**パス：** `/rolodex_dns.RolodexDnsService/GetResolutionMode`

現在有効な解決モードを返します —— 設定ファイルが名指しているものではなく、実際に
問い合わせを解決しているほうです。`SetResolutionMode` の呼び出しのあとでは両者は
異なります。

**パラメータ：**
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `mode`（string）：`"auto"`、`"recursive"`、`"forward"` のいずれか

#### `FlushCache`

**パス：** `/rolodex_dns.RolodexDnsService/FlushCache`

ブロックリストの参照キャッシュを消去します。

**パラメータ：**
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `CreateNetworkScope`

**パス：** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

予約された `.home` ドメインを持つ新しいネットワークスコープを作成します。

**パラメータ：**
- `scope`（NetworkScope、必須）：作成するスコープ
  - `name`（string）：スコープの一意な名前（例 `"office"`、`"lab"`）
  - `home_domain`（string）：予約する `.home` ドメイン。既定：空なら `"<name>.home."`
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `DeleteNetworkScope`

**パス：** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

ネットワークスコープと、そのレコードおよび結び付きをすべて削除します。

**パラメータ：**
- `name`（string、必須）：削除するスコープの名前
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `ListNetworkScopes`

**パス：** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

設定されたネットワークスコープをすべて取得します。

**パラメータ：**
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `scopes`（repeated NetworkScope）：設定されたすべてのスコープ

#### `JoinNetwork`

**パス：** `/rolodex_dns.RolodexDnsService/JoinNetwork`

クライアントの IP アドレスをネットワークスコープに結び付けます。この結び付きには TTL があり、DNS 解決を保つには定期的に更新しなければなりません。

**パラメータ：**
- `ip_address`（string、必須）：結び付けるクライアントの IP（例 `"192.168.1.100"`）
- `scope_name`（string、必須）：参加するネットワークスコープの名前
- `ttl_seconds`（uint64）：TTL（秒）。既定：0 を設定すると 300。期限が切れる前に更新しなければなりません。
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `LeaveNetwork`

**パス：** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

ある IP アドレスとネットワークスコープとの結び付きを解除します。

**パラメータ：**
- `ip_address`（string、必須）：結び付きを解除するクライアントの IP
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `GetNetworkAssociations`

**パス：** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

IP とスコープの結び付きを取得します。

**パラメータ：**
- `scope_name`（string）：スコープ名でフィルタします。空ならすべての結び付きを返します。
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `associations`（repeated NetworkAssociation）：一致した結び付き
  - `ip_address`（string）：結び付いた IP
  - `scope_name`（string）：スコープ名
  - `ttl_seconds`（uint64）：結び付きの TTL

#### `AddScopedRecord`

**パス：** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

特定のネットワークスコープ内に DNS レコードを追加します。スコープ付きレコードは、そのスコープに結び付いた IP からのみ見えます。

**パラメータ：**
- `scope_name`（string、必須）：レコードを追加するスコープ
- `record`（DnsRecord、必須）：追加する DNS レコード
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `RemoveScopedRecord`

**パス：** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

特定のネットワークスコープから DNS レコードを削除します。

**パラメータ：**
- `scope_name`（string、必須）：レコードを削除するスコープ
- `name`（string、必須）：レコードを削除する対象の FQDN
- `record_type`（RecordType）：任意の型フィルタ
- `value`（string）：任意の完全一致値フィルタ
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `success`（bool）：操作が成功したかどうか
- `removed_count`（uint32）：削除されたレコードの数
- `message`（string）：`success` が偽のときのエラーメッセージ

#### `ListScopedRecords`

**パス：** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

ネットワークスコープ内の DNS レコードを問い合わせます。

**パラメータ：**
- `scope_name`（string、必須）：問い合わせるスコープ
- `name_filter`（string）：ドメイン名でフィルタ（ワイルドカード接頭辞 `"*."` に対応）
- `record_type_filter`（RecordType）：レコード型でフィルタ（`filter_by_type` が真のときのみ適用）
- `filter_by_type`（bool）：`record_type_filter` を適用するかどうか。既定：偽
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `records`（repeated DnsRecord）：一致したスコープ付きレコード

#### `GetSearchDomains`

**パス：** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

クライアントの IP アドレスに対する検索ドメインを取得します。その IP が結び付いているスコープの `.home` ドメインを返します。

**パラメータ：**
- `ip_address`（string、必須）：調べるクライアントの IP
- `auth_token`（string）：認証のための共有秘密

**応答：**
- `search_domains`（repeated string）：その IP の検索ドメイン（通常はスコープの `.home` ドメイン）

#### 追加の gRPC メソッド

次のメソッドも利用できます。要求と応答の完全な定義は `proto/rolodex_dns.proto` を参照してください。

| メソッド | 説明 |
|--------|-------------|
| `AddAuthoritativeZone` | ゾーンを権威として宣言（AA ビット、上流への転送なし） |
| `RemoveAuthoritativeZone` | 権威一覧からゾーンを削除 |
| `ListAuthoritativeZones` | すべての権威ゾーンを一覧 |
| `GetCacheStats` | DNS キャッシュの統計を取得（項目数、ヒット、ミス） |
| `FlushDnsCache` | DNS 応答キャッシュを消去 |
| `SetTtlDriftConfig` | TTL ドリフトの調整を設定（固定または対数モード） |
| `GetTtlDriftConfig` | TTL ドリフトの設定を取得 |
| `GetQueryLatencyStats` | サーバーごとの上流クエリ遅延の統計を取得 |
| `SetResolutionMode` / `GetResolutionMode` | 上流の解決モードを実行時に切り替え、いま効いているモードを読む |
| `SetTrackedTlds` / `ListTrackedTlds` | 追跡する TLD の一覧を置き換え、保存・所有・実効の集合を読む |
| `AddLocalBlocklistEntry` | ローカルブロックリストに項目を追加 |
| `RemoveLocalBlocklistEntry` | ローカルブロックリストの項目を削除 |
| `ListLocalBlocklistEntries` | ローカルブロックリストの全項目を一覧 |
| `SetDnsblConfig` / `GetDnsblConfig` | ドメインブロックリスト（DNSBL）の設定を変更／取得 |
| `AddDnsblAllowlistEntry` | ある名前（とその配下）をブロックリストの照会から免除 |
| `RemoveDnsblAllowlistEntry` | DNSBL 許可リストの項目を削除 |
| `ListDnsblAllowlistEntries` | DNSBL 許可リストの全項目を一覧 |
| `AddScopeTld` | スコープに全域で一意な所有 TLD を登録。任意の `listen_ip` を与えると入口 DNS リスナーも起動します |
| `RemoveScopeTld` | 所有 TLD を削除（使われなくなり次第、その入口リスナーも） |
| `ListScopeTlds` | スコープが所有する TLD を一覧 |
| `SetScopeTldForwarders` / `ListScopeTldForwarders` | TLD のピアフォワーダーを管理 |
| `ListScopeTldListeners` | スコープの TLD に結び付いた入口 DNS リスナーを一覧 |
| `AddDhcpPool` / `RemoveDhcpPool` / `ListDhcpPools` | スコープ単位の DHCP アドレスプールを管理 |
| `ListDhcpLeases` / `DeleteDhcpLease` | DHCP リースを調べ、削除 |
| `SetDhcpCertOption` / `RemoveDhcpCertOption` / `ListDhcpCertOptions` | DHCP オプションによる証明書配布を管理 |
| `EnsureZoneCa` | ゾーン単位の中間 CA が無ければ作成。ルートと中間の PEM を返します |
| `CreateEabCredential` / `RemoveEabCredential` | ゾーンに限定された EAB 資格情報を発行または削除 |
| `ListAcmeAccounts` / `ListAcmeCertificates` | ACME アカウントと発行済み証明書を一覧 |
| `SetDotConfig` / `GetDotConfig` | DNS-over-TLS の設定を変更／取得 |
| `SetDohConfig` / `GetDohConfig` | DNS-over-HTTPS の設定を変更／取得 |
| `SetDoqConfig` / `GetDoqConfig` | DNS-over-QUIC の設定を変更／取得 |
| `SetProxyConfig` / `GetProxyConfig` | HTTP プロキシの設定を変更／取得 |
| `GenerateDnssecKey` | ゾーンの DNSSEC 鍵ペアを生成 |
| `ListDnssecKeys` | ゾーンの DNSSEC 鍵を一覧 |
| `DeleteDnssecKey` | DNSSEC 鍵を削除 |
| `GetDsRecords` | 親ゾーンへの委任のための DS レコードを取得 |
| `SignZone` | ゾーンをその DNSSEC 鍵で署名（または再署名） |
| `GenerateTlsaRecord` | PEM 証明書から TLSA レコードを生成 |
| `ListTlsaRecords` | あるドメインの TLSA レコードを一覧 |
| `GenerateDaneRootCa` | 自己署名の DANE ルート CA を生成 |
| `RequestAcmeCert` | ACME DNS-01 チャレンジで証明書を要求 |
| `GetAcmeStatus` | あるドメインの ACME 証明書の状態を取得 |
| `SetDns64Config` / `GetDns64Config` | DNS64 合成の設定を変更／取得 |

### レコード型

| enum 値 | 名前 | 説明 |
|-----------|------|-------------|
| 0 | `A` | IPv4 アドレスの対応付け。値：IPv4 アドレス（例 `"192.168.1.1"`） |
| 1 | `AAAA` | IPv6 アドレスの対応付け。値：IPv6 アドレス（例 `"::1"`） |
| 2 | `CNAME` | 正準名の別名。値：宛先の FQDN（例 `"target.example.com."`） |
| 3 | `MX` | メール交換。値：メールサーバーの FQDN。`priority` フィールドを使います |
| 4 | `TXT` | テキストレコード。値：テキストの内容 |
| 5 | `NS` | ネームサーバー。値：ネームサーバーの FQDN |
| 6 | `SOA` | 権威の開始。値：`"mname rname serial refresh retry expire minimum"`（空白区切り） |
| 7 | `SRV` | サービスの位置。値：`"weight port target"`（空白区切り）。`priority` フィールドを使います |
| 8 | `PTR` | 逆引き DNS のためのポインタ。値：宛先の FQDN |
| 9 | `URI` | URI リソースレコード（RFC 7553）。値：`"priority weight \"uri\""` |
| 10 | `SSHFP` | SSH フィンガープリント（RFC 4255）。値：`"algorithm fp_type fingerprint"` |
| 11 | `DNAME` | 委任名（RFC 6672）。値：宛先の FQDN（サブツリー全体を書き換えます） |
| 12 | `ANAME` | 別名（ドラフト）。値：宛先の FQDN（クエリ時に解決され、ゾーン頂点でも使えます） |
| 13 | `ZONEMD` | ゾーンメッセージダイジェスト（RFC 9156）。値：`"serial scheme hash_algorithm digest"` |
| 14 | `TLSA` | TLS 証明書の関連付け（RFC 6698）。値：`"usage selector matching_type cert_data"` |
| 15 | `DNSKEY` | DNSSEC の公開鍵。DNSSEC 鍵生成により自動で管理されます |
| 16 | `DS` | 委任署名者。DNSSEC により自動で管理されます |
| 17 | `RRSIG` | DNSSEC のリソースレコード署名。ゾーン署名により自動で管理されます |
| 18 | `NSEC` | 次のセキュアレコード（DNSSEC）。ゾーン署名により自動で管理されます |
| 19 | `NSEC3` | 次のセキュアレコード v3（DNSSEC）。ゾーン署名により自動で管理されます |
| 20 | `NSEC3PARAM` | NSEC3 のパラメータ（DNSSEC）。ゾーン署名により自動で管理されます |
| 21 | `CERT` | DNS 内の証明書格納（RFC 4398）。値：`"cert_type key_tag algorithm base64_cert_data"`。CA の連鎖の配布に使われます |

## プライバシー最優先のキャッシュ

Rolodex DNS は DNS 応答をローカルにキャッシュするので、同じ名前への繰り返しのクエリは、どの上流フォワーダーにも接触せずに答えられます。これにより DNS クエリの漏洩が防がれます —— 一度レコードがキャッシュされてしまえば、そのクエリが再び行われたことを外部の観測者が見ることはありません。

キャッシュは二種類の項目を区別します：

- **ローカルレコード**（SQLite データベース由来）：安定した TTL でメモリ内にキャッシュされます（減衰しません）。これらの項目はキャッシュの裏の格納先には永続化されません。すでにデータベースの中に居るからです。メモリ内の DNS キャッシュは、gRPC 経由でレコードが追加・削除・変更されるたびに自動で無効化されるので、変更は即座に効きます。
- **転送された応答**（上流リゾルバー由来）：減衰する TTL でキャッシュされ、SQLite が裏にあるキャッシュ表に永続化されます。再起動時には永続化された項目が読み直されるので、キャッシュは最初から温かい状態です。

否定の応答（権威ある NXDOMAIN/NODATA）は別にキャッシュされ、その期間は RFC 2308 のネガティブ TTL（`min(SOA MINIMUM, SOA TTL)`）を、ゾーンが公開したとおりに用います。ある名前にローカルレコードを追加すると、その名前のキャッシュ済みの否定は破棄されるので、新しく追加された名前はネガティブ TTL を待たずに即座に解決します。

キャッシュの統計は `GetCacheStats` から得られ、キャッシュは `FlushDnsCache` で破棄できます。

プライバシーを最大にするには、`resolution.mode: forward` と `forwarders: []` を設定して、外部解決を一切行わない純粋な権威サーバーとして Rolodex DNS を動かしてください。すべての応答はローカルデータベースから返ります。

## 上流解決

ローカルで満たされなかった名前は `resolution.mode` に従って解決されます：

| モード | 挙動 |
| ---- | -------- |
| `auto`（既定） | 下記の階層フォールバックチェーン |
| `recursive` | ルートサーバーからの反復のみ。上流リゾルバーには決して接触しません |
| `forward` | 設定された `forwarders` にのみ転送 |

**設定ファイルは起動時の種にすぎません。** `resolution.mode` は起動時に一度だけ
読まれます。そこから先、有効なモードは [`SetResolutionMode`](#setresolutionmode) が
最後に設定したものであり、[`GetResolutionMode`](#getresolutionmode) が報告するのは
実際に問い合わせを解決しているほうです。切り替えのあとでは両者は異なります ——
モードを変えるために動いているサーバーを再起動することは決してありません。機体で
唯一のリゾルバーの再起動は、その上のすべてにとっての DNS の停止だからです。
`rolodex-dns-cli set-resolution-mode` / `get-resolution-mode` は、この二つの呼び出しを
シェルから行うものです。

**`arpa.` はこの機体の外で解決されることが決してありません。** どのモードでも、`arpa.` とその配下のすべては、ローカルデータ —— 保存された PTR、スコープ付きレコード、管理下または権威のある逆引きゾーン —— から答えられるか、さもなくば **REFUSED** になります。このサブツリーの何かがルートサーバーやフォワーダー、暗号化上流へ送られることはありません。NXDOMAIN ではなく REFUSED であるのは、サーバーがある名前空間について答えることを辞退しているのであって、その名前が存在しないと主張しているわけではないからです。

この規則はラベルの境界で一致するので、`notarpa.` や `arpa.example.com` はふつうの名前として通常どおり解決します。人が使う機体でこれを有効にする前に知っておくべき帰結が二つあります。データを持たないアドレスの逆引きは、インターネットから答えるのではなく拒否されること（`dig -x 8.8.8.8`）。そして `ipv4only.arpa` が拒否され、NAT64 を探すクライアントはそれを「ここに NAT64 は無い」と読むことです。

### `auto` フォールバックチェーン

階層は、もっとも好ましい（もっとも信頼できる）ものから順に試されます：

| 階層 | 経路 | 理由 |
| ---- | ---- | --- |
| 0 | ルートサーバーからの反復 | 第三者があなたのクエリを見ることはありません |
| 1 | `resolution.secure_upstreams` への DoH（`:443`）または DoT（`:853`） | 暗号化されており、`:53` の遮断を生き延びるポートを使います |
| 2 | `forwarders` への平文 Do53 | ローカルの、あるいは DHCP が配ったリゾルバー |
| 3 | `resolution.public_fallback` への平文 Do53 | 最後の手段 |

DoT より DoH が好まれるのは、`:443` がふつうの HTTPS に見え、DoT の接続は開かせておいてその TLS セッションを落とすような深層パケット検査を生き延びるからです。安全な上流は **IP で**接続され、証明書は設定された `hostname` に対して検証されるので、この階層は起動のための事前の DNS を必要としません。

階層が「勝つ」のは、トランスポートが成功し、かつ rcode が NoError か NXDOMAIN のときだけです。SERVFAIL、REFUSED、解釈できない応答は下へ落ちます。勝った階層は**粘着**するので、クエリのたびに死んだ経路でタイムアウトを払うことはありません。より好ましい階層への回復は即座に起こりますが、劣る階層への格下げは `resolution.switch_grace_failures` 回の連続して外れたクエリを経てはじめて確定するので、一度の不安定なクエリがリゾルバーを揺さぶることはありません。**クライアントのクエリが探りを入れることは決してありません**：開始階層は常に確定した階層です。背景のタスクがそれより上の階層を `resolution.recovery_probe_secs` ごとに自前の使い捨ての炭鉱のカナリアで試し直します。そして階層 0 を取り戻すには、ルートゾーン自身の `DNSKEY` について DNSSEC 検証された応答が要ります —— 単に届くだけで良いなら、`:53` を乗っ取る中間装置が自らをもっとも信頼できる階層として据えられてしまいます。確定した階層の切り替えはいずれも DNS キャッシュを破棄するので、ある階層からの応答が別の階層へ切り替わったあとに残ることはありません。

### 反復リゾルバー

リゾルバーは委任の連鎖をルートから —— ルート → TLD → 権威と —— 再帰要求ビットを落としてたどり、経路外からのなりすましに対してトランザクション ID と質問の名前で応答を検証しながら、UDP 上を進み、切り詰めがあれば自動で TCP へ落ちます。

- **ルートヒントとプライミング。** IANA の 13 のルートアドレス（IPv4 のみなので、v4 だけのホストが v6 のルートで止まることはありません）は起動のための足がかりです。起動時に Rolodex はルートたちに「ルートは誰か」を尋ね、生きた `.` の NS 集合を本物の TTL とともにキャッシュします。プライミングがクエリの経路上で走ることは決してなく、失敗した場合はヒントが予備として残ります。`resolution.root_hints` で上書きできます。
- **サーバー間での負荷の分散。** ネームサーバーは `ヒット数 × 平均遅延` が最小のものが選ばれます。これはクエリを `ヒット数 ∝ 1/遅延` の形で配分します：速いサーバーがより多くを担いますが、健全なサーバーはどれも幾らかを担います。これは、冷えたクエリのすべてを一つのルート（「最初の」でも「最速の」でも）に釘付けにすることを意図的に避けます。そうするとレート制限を招き、参照のたびにタイムアウトと切り替えが起きるからです。
- **失敗時のバックオフ。** 失敗したサーバーは 2 秒間そのまま外れ、連続する失敗ごとに倍増して最大 300 秒まで伸び、最初の成功で解除されます。バックオフ中のサーバーは最後に並べられますが、決して落とされません。そのため、すべてが失敗しているときでも解決は前へ進みます。
- **有界な仕事量。** ネームサーバーごとに 1.5 秒のタイムアウト、30 の紹介、16 の CNAME ホップ、深さ 16、グルー無しの委任ごとに 4 のネームサーバー、そしてクライアントの参照一回あたり上流クエリ 64 という厳格な上限 —— 軸ごとの上限は掛け算になるので、総量は真正面から抑えられています。

### リゾルバーのキャッシュ

応答キャッシュの下には、TTL を尊重する二つのキャッシュがあり、再帰が下りていく途中で学んだことを保持します：

- **委任キャッシュ** —— ゾーン → ネームサーバーのアドレス。あらゆる紹介から学びます。温まった `.com` の参照はルートへのホップを丸ごと省きます。TTL が `resolution.delegation_persist_min_ttl`（既定 300 秒）を超える委任は SQLite に永続化され起動時に読み直されるので、再起動しても温かい状態で戻ってきます。ルートと TLD の NS 集合は数日単位の TTL を持つので、保つ価値のある項目がちょうど生き残ります。
- **レコードキャッシュ** —— グルー、グルー無しの NS 名の参照、CNAME ホップ。`(名前, 型)` を鍵とし、*残りの*寿命とともに提供されます。

どちらもレコードの変更を生き延び（レコードを一つ追加したからといって世界中の名前をルートへ送り返してはならない）、`auto` モードでの階層切り替えのときにのみ消去されます。

TTL は公開されたとおり正確に尊重されます —— ゾーンの SOA のネガティブ TTL も含め、決して切り詰められません。`resolution.default_ttl` は、使える TTL を何も持たない場合にのみ適用されます。

## アドレスファミリによる絞り込み

ネットワークは日常的に IPv6 の既定経路を広告しておきながら、v6 のトラフィックをすべて黙って捨てます（v4 だけの NAT では鏡像の事態が起きます）。ホストが経路を持たないファミリのアドレスを渡されたクライアントは、もう一方へ落ちる代わりに、死んだファミリの上で止まります —— v6 が壊れた回線でコンテナイメージの取得が固まる、あの失敗です。

`address_family.mode: auto`（既定）では、背景のプローブが公開のエニーキャストリゾルバーへ `:443` で TCP 接続します —— 実際のトラフィックが使うポートであり、一部のネットワークが課す `:53`／`:853` の遮断を生き延びるポートです —— そうしてファミリごとの*実際の*到達性を試験します。到達できないファミリの A/AAAA レコードは応答から落とされ（NODATA になり）、クライアントは動く方のスタックへ落ちられます。

最初のプローブは起動時に同期的に走り、決定的です。そのため死んだファミリの回線上で起動した場合、最初のクエリからそのファミリは抑制されます。その後は、それまで動いていたファミリは `address_family.fail_threshold` 回の連続失敗周期を経てはじめて落ちたと印を付けられ、一方で回復は最初の成功で効きます。常に両方のファミリで答えるには `mode: off` を、プローブせずに一方に固定するには `force4`／`force6` を設定してください。

## 暗号化トランスポート

Rolodex DNS は、DNS クエリの盗聴を防ぐために三つの暗号化 DNS トランスポートプロトコルに対応します：

**DNS-over-TLS（DoT）** —— RFC 7858、既定ポート 853、ALPN トークン `dot`。TCP 上の DNS を TLS で包んだ標準的なもので、枠取りも同じ 2 バイトの長さ接頭辞です。ALPN トークンは要求されるのではなく広告されます：`dot` を提示するクライアントはそれを折衝し、ほかのプロトコルだけを提示するクライアントは拒否され、ALPN 拡張をまったく送らないクライアントにはそのまま提供されます。YAML の `dot` 節か、gRPC の `SetDotConfig` で設定します。

**DNS-over-HTTPS（DoH）** —— RFC 8484、既定ポート 443。HTTPS 上の DNS クエリで、GET（`/dns-query?dns=<base64>`）と POST（`application/dns-message`）の両方のメソッドに対応します。任意で QUIC 上の HTTP/3 にも対応します（`enable_h3: true`）。YAML の `doh` 節か、gRPC の `SetDohConfig` で設定します。

**DNS-over-QUIC（DoQ）** —— RFC 9250、既定ポート 8853。低遅延の暗号化解決のための QUIC トランスポート上の DNS クエリです。YAML の `doq` 節か、gRPC の `SetDoqConfig` で設定します。

三つのプロトコルはいずれも TLS 証明書を必要とします。自分の証明書と鍵を与えるか、`auto_self_signed: true` を設定して Rolodex DNS に自己署名証明書を自動生成させることができます。生成される証明書は `localhost`、`127.0.0.1`、`::1`、そしてリスナー自身のバインドアドレスを覆います。クライアントがこの機体を呼ぶほかの名前 —— ホスト名、`.local` の名前、LAN の別名 —— は `self_signed_sans` に追加してください。認証名を設定されたクライアントはそれを確かめますし、ワイルドカードのバインドは自前の名前を何も寄与しないからです。

## DNSSEC

Rolodex DNS には独立した二つの DNSSEC の半身があります：自分のゾーンに**署名**することと、上流から解決した応答を**検証**することです。両者はコードを共有しません —— 署名側は自分で書いたデータベースの行を扱い、あらゆるバイトを支配しますが、検証側は、その誠実さこそが問われている相手から届いた何かを扱うのであり、この二つは食い違えなければなりません。

### ゾーンへの署名

署名は次のアルゴリズムに対応します：

- **Ed25519**（推奨）—— 小さな鍵と署名、速い署名
- **ECDSA P-256/SHA-256** と **ECDSA P-384/SHA-384**

**RSA/SHA-256（アルゴリズム 8）は生成できず**、`generate-dnssec-key` はこれを拒否します：`ring` には RSA 鍵の生成がありません。*解釈*はできるので、そのアルゴリズムで登録済みの既存の鍵の行は一覧できますし、上流ゾーンからの RSA 署名は検証できますが、ここで何かがそれで署名することはありません。端から端まで守り通せないアルゴリズムは、黙って別のもので代替されるのではなく、鍵の生成の時点で拒否されます。あるアルゴリズムを名乗りながら別のアルゴリズムの鍵素材を載せた DNSKEY は、互いに食い違う DS と DNSKEY と RRSIG 一式を生み、その失敗はローカルではなく検証するリゾルバーの側で表に出るからです。

Ed448 は ring 暗号クレートの制約により対応していません。

#### 署名の手順

1. ゾーンのために鍵署名鍵（KSK）とゾーン署名鍵（ZSK）を生成します：
   ```bash
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
   ```

2. ゾーンに署名します：
   ```bash
   rolodex-dns-cli sign-zone --zone example.com.
   ```

3. レジストラ向けの DS レコードを取得します。これに対応する CLI のサブコマンドはありません —— `GetDsRecords` の gRPC メソッドを呼ぶ（たとえば Go クライアントの `GetDsRecords(ctx, zone)`）か、任意の DNS クライアントでゾーンから DS レコードを問い合わせてください。

署名は頂点の DNSKEY RRset を公開し直し、RRset ごとに一つの RRSIG を作ります。レコードを追加または変更したあとは `sign-zone` を実行し直してください。既存の RRSIG は積み上がるのではなく置き換えられます。

**認証付き否定は生成されません。** NSEC、NSEC3、NSEC3PARAM は保存も一覧もできるレコード型ですが、`sign-zone` はそれらを生成も提供もしません。したがってここで署名されたゾーンは、何が存在するかは証明しますが、何が存在しないかは証明しません。

DNSKEY、DS、RRSIG はそれぞれの型コードで提供され、その RDATA は署名側がハッシュするのと同じ正準符号化器が作ります —— 線上へ出るものは、署名されたものとバイト単位で同一です。

### 上流の検証

**反復的に**解決された応答は IANA のルートトラストアンカーに対して検証されます。これは既定で有効です：

```yaml
dnssec:
  validate: true        # 既定値
  trust_anchors: []     # 空 = IANA のルート鍵
```

適用されるのは反復経路だけです —— `recursive` モードと、`auto` のルート階層です。転送された応答は他人の再帰の要約であり、それを検証するには連鎖を自分でたどり直すことになりますが、それこそがルート階層そのものです。したがって階層 0 より下へ格下げされた `auto` チェーンは未検証であり、AD を立てないことでそう告げます。

RFC 4033 §5 の四つの判定は明確に区別されます：

| 判定 | 意味 | 提供する？ |
| ------- | ------- | ------- |
| `Secure` | 署名がトラストアンカーまで連鎖している | はい。求めたクライアントには AD を立てて |
| `Insecure` | 連鎖が**証明可能な形で**止まっている —— 経路上のある委任に DS が無く、その不在自体が署名されている | はい、AD は落として |
| `Bogus` | データが署名されていると主張し、その主張が成り立たない | **決して。** SERVFAIL |
| `Indeterminate` | 判断に必要なものを得られなかった | **決して。** SERVFAIL |

安全性を担っている区別は Insecure 対 Bogus です。「署名が無い」ことは Insecure では*ありません* —— 経路上の攻撃者はどんな応答からでも署名を剥ぎ取れます。Insecure なのは、署名された NSEC/NSEC3 が上の委任における DS の不在を証明したときだけであり、それは親の鍵なしには攻撃者に偽造できません。その証明こそが NSEC/NSEC3 の仕掛けの存在理由です。それが無ければ、検証器は攻撃者によって検証器でないものへ引き下げられるだけのものになります。

実際の挙動は次のとおりです：

- **連鎖は上から下へ**、リゾルバーがすでに行っている委任をたどる歩みと並んで構築されるので、DS は紹介に相乗りして無料で届きます。検証済みの鍵集合（および証明済みで安全でない委任）はゾーンごとにキャッシュされるので、温まったゾーンでは導出をやり直す費用がかかりません。
- **Bogus な応答は決してキャッシュされません**。肯定でも否定でもです —— キャッシュされた Bogus な否定は、その TTL のあいだ本物の名前を押し潰してしまいます。`auto` モードでは検証の失敗は階層の失敗ではなく*決定的な*応答なので、壊れた署名が、検証しない上流を通して洗浄されることはありません。
- **AD が立つのは `Secure` のときだけ**であり、しかも DO か AD を立てたクライアントに対してのみです。ローカルデータから組み立てられた応答が AD を立てることはありません。
- **DO を立てていないクライアントには RRSIG/NSEC/NSEC3 が取り除かれます**（RFC 4035 §3.2.1）。ただしその型を名指しで求めた場合は除きます —— 署名された A レコードはおおよそ三倍の大きさになり、小さな質問への大きな応答こそ、`security.recursion_cidrs` が閉じるために存在する増幅の形だからです。
- **対応していないアルゴリズムは Bogus ではなく Insecure です**（RFC 6840 §5.11）：こちらにアルゴリズムが無いことは、そのゾーンの障害ではありません。RSA/SHA-1/256/512、両方の ECDSA 曲線、Ed25519 はいずれも検証できます。NSEC3 の反復回数が 100 を超えるものは、計算するのではなく安全でないものとして扱われます（RFC 9276）。
- **検証の費用は、経路上のゾーンごとにおよそ一つの追加クエリ**です。そのため検証が有効なとき、参照ごとのクエリ予算は基本の 64 に加えて 32 を得ます。
- **拒まれた応答は拒まれるのであって、問い直されません。** ルート階層では、応答を差し止める判定は*決定的な* SERVFAIL です：そのクエリが暗号化上流やフォワーダーへ落ちることはなく、何もキャッシュされず、検証に失敗した紹介は委任もグルーも残しません。
- **検証できないルートゾーンもまた拒まれます。** ルート自身の DNSKEY をアンカーに結べないことは、かつてはエラーとして表に出ていました。フォールバックチェーンはそれを「ルートが到達不能」と読み、検証しない上流から答えていました —— つまりルートの DNSKEY の取得を壊せば、Bogus の判定を一つも出さずに検証を経路から外せてしまったのです。今ではそれは一つの判定です。*到達*できないルートは、意図的に、依然として下へ落ちます：到達不能は不正ではありません。この引き換えは現実のものであり、述べておく価値があります —— このビルドが知らないトラストアンカーは、静かな格下げではなく DNS の停止になります。そして `dnssec.validate: false` が逃げ道です。
- **不正な DNSSEC を提供するルートサーバーはルート集合から外されます**。期間は 15 分、違反ごとに倍増して 24 時間で頭打ちになります。判断に使うのは、他の誰にも尋ねずに確かめられる唯一の主張です：そのサーバーのルート DNSKEY を、ローカルのアンカーに照らすことです。この罰はサーバーが素早く応答しても続き、解除されるのは*検証に通る*応答によってのみ（待つことによっては決して）で、最後に残った一つのルートには決して適用されません —— すべてのルートが同時に失敗するなら、それは十三台の不良サーバーではなく、ゾーンかアンカーのほうです。適用されるのはルートサーバーに対してのみです。ルートより下では、検証の失敗はたいていそのゾーン自身の署名の誤りであり、それらはすでに閉じる方向で失敗します。責めはメモリ上にあり、再起動を生き延びません。`rolodex_dns_dnssec_blamed_roots` を見張ってください。

`dnssec.validate: false` を設定すると、以前とまったく同じに解決します：外向きの DO ビットなし、信頼の連鎖なし、Bogus なデータに対する SERVFAIL なし。

**トラストアンカー。** `dnssec.trust_anchors` は DNSKEY の表示形式を取ります —— `"<flags> <protocol> <algorithm> <base64 key>"`、`dig DNSKEY .` が表示するとおりの四つの RDATA フィールドです。上書きは IANA の鍵に加えるのではなく**置き換える**ので、私的なルートはそれ自身の鍵だけにアンカーされます。すべてのフィールドが起動時に検証され、不正な形式のアンカーは静かなフォールバックではなく即座の失敗となります —— 実在の DNSKEY に一致しえないアンカーは、原因がアンカーだと指し示すものが何も無いまま、署名されたすべてのゾーンを失敗させるからです。

判定は Prometheus 上で `rolodex_dns_dnssec_verdicts_total{verdict}` として、`dnssec_servfail_total`、`dnssec_blamed_roots`、`key_cache_entries` とともに見られます。

## CA の配布と信頼

Rolodex DNS はそれ自身が ACME の認証局です：自己署名の**ルート CA** が**ゾーン単位の中間 CA** に署名し、各中間 CA が ACME エンドポイントを通じて発行されるリーフ証明書に署名します。クライアントがそれらの証明書を信頼するには、ルート CA を信頼する必要があります。Rolodex は CA の連鎖を三つの方法で配布します。

### DNS 経由の CA（TXT フォールバック付きの CERT レコード）

ゾーン単位の中間 CA が作られるたびに、Rolodex はルートと中間の証明書を **DNS そのものへ**公開します。そのゾーンを解決できるクライアントなら誰でも、登録ポータルに一度も触れずに CA を取得して信頼できます：

- **`CERT` レコード（RFC 4398）** —— `_ca.<zone>.` に、証明書ごとに一つのレコードを置きます。RDATA は `"1 0 0 <base64 DER>"` です（型 1 = PKIX/X.509、鍵タグとアルゴリズムは 0）。ルートは自己署名の証明書として見分けられます。どんな DNS クライアントでも使えます：
  ```bash
  dig CERT _ca.example.com
  ```
- **`TXT` レコード** —— `_rolodex-ca.<zone>.` に、同じ base64 の DER を 255 バイト以下の塊に分け、`rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>` の形に包んで置きます。`rolodex-ca:` という一意な接頭辞が、関係のない TXT データからその塊を区別し、明示的な連番により応答の順序にかかわらずクライアントが組み立て直せます。これは `CERT` を問い合わせられないリゾルバースタックのためのフォールバックです。

公開はべき等で（レコードは複製されず置き換えられます）、ゾーンの CA が確かめられるすべての地点で行われます：ポータルからの登録、`EnsureZoneCa`／`CreateEabCredential` の RPC、そして ACME のアカウント作成／finalize です。利用する側は `CERT` を優先し、`TXT` へ落ちるべきです。

### ブラウザ拡張

[`extension/`](extension/) 配下のブラウザ拡張には、ポータルに依存しない **DNS 経由の CA** パネルがあります：DoH の URL（たとえば `https://dns.example.com/dns-query`）とゾーンを与えると、DNS-over-HTTPS 経由で連鎖を取得し（`CERT` を優先し、`TXT` へ落ちます）、ルートと中間を見分け、任意で公開された DANE-TA の `TLSA` レコードに対して中間を検証し、ルート／中間／連鎖の PEM をダウンロードできるようにします。DNS のロジックは `extension/ca_dns.js` にあり、依存関係の無いブラウザモジュールとして JavaScript のテスト群からも再利用されています。

### ポータルと CLI

信頼されたネットワークでは、登録ポータル（`acme.portal_bind`、既定 `https://<host>:8500`）が `GET /api/ca` でルート CA を提供し、管理 CLI は連鎖全体を表示します：

```bash
# あるゾーンのルート ＋ 中間の PEM を表示
rolodex-dns-cli ensure-zone-ca --zone example.com

# あるいはポータルからルート CA をダウンロード
curl -k https://<host>:8500/api/ca -o rolodex-root-ca.pem
```

ルート CA の PEM を手に入れたら、それを各端末の信頼ストアに追加してください（たとえば Fedora/RHEL なら `update-ca-trust`、Debian/Ubuntu なら `update-ca-certificates`、macOS ならキーチェーンアクセス、Firefox ならブラウザ自身の証明書マネージャ）。ACME エンドポイントを通して発行されたサーバーは `リーフ ＋ 中間` の連鎖を提示し、それはこのルートに対して検証されます。DANE を解するクライアントはさらに、発行時に Rolodex が自動で公開する `TLSA` レコードによって中間を固定できます。

## DNS64

DNS64（RFC 6147）は、IPv4 だけのホストへ届く必要のある IPv6 だけのクライアントのために、A レコードから AAAA レコードを合成します。クライアントが AAAA レコードを問い合わせ、それが存在せず、しかし A レコードが存在するとき、Rolodex DNS は IPv4 アドレスを設定された IPv6 プレフィックスに埋め込んで合成 AAAA を組み立てます。

既定のプレフィックスは `64:ff9b::/96`（よく知られた NAT64 プレフィックス）です。たとえば `192.0.2.1` の A レコードは `64:ff9b::192.0.2.1`（`64:ff9b::c000:201`）として合成されます。

YAML で設定します：
```yaml
dns64:
  enabled: true
  prefix: "64:ff9b::"
```

あるいは実行中に gRPC から：`SetDns64Config` / `GetDns64Config`。

## Prometheus メトリクス

任意の `metrics` 節は、`/metrics` に平文 HTTP の収集エンドポイントを立てます。この節は**既定では無く**、そのためリスナーは起動せず、更新によって新しいポートが開くこともありません。

```yaml
metrics:
  bind: "127.0.0.1:9153"
  # 独自の `tld` ラベルを与えられる TLD。所有 TLD は自動で追跡されます。
  tracked_tlds:
    - common          # 組み込みの一般 TLD 一式に展開されます
    - lab.internal    # ほかに分離したいものがあれば名前で
```

このエンドポイントは認証されておらず、集計された数だけを載せます —— クエリ名も、レコードの値も、証明書の素材もありません。私的なアドレスにバインドしてください。既定はループバックです。ここで TLS を提供しないのは意図的です。そもそも公開の場から届くべきでないエンドポイントのために、収集する側すべてへ自己署名証明書を配ることになるからです。

80 のメトリクスファミリが公開されます。いずれも `rolodex_dns_` の接頭辞を持ち、クエリ、応答キャッシュ、ブロックリスト（拒否とローテーションから外れたプロバイダーを含む）、上流の階層、反復リゾルバー、DNSSEC の判定、スプリットホライズンの状態、DHCP、ACME、gRPC を覆います。

知っておく価値があるのは `rolodex_dns_answers_total{source}` です。これは、解決順序のどの段階が各応答を生んだかを報告します —— `cache`、`local`、`scoped`、`scope_fallback`、`tld_peer`、`blocklist`、`reverse_blocklist`、`dns64`、`upstream`、`authoritative_nxdomain`、`refused`、`error`。その合計はクエリの合計に等しく、それがスプリットホライズンの流れを外から読めるものにしています：

```
curl -s http://127.0.0.1:9153/metrics | grep answers_total
```

### 濃度

有界な濃度は設計上の制約です。見知らぬ相手が際限なく膨らませられるメトリクスエンドポイントは、監視の衣装をまとったメモリ枯渇の欠陥だからです。どのラベルも、固定の enum であるか、設定によって有界であるかのいずれかです。*クライアント*が膨らませられたはずの二つの次元は、どちらも受け皿にまとめられます：

| 次元 | 上限 | 受け皿 |
|-----------|-------|-----------|
| `qtype` | 既知のレコード型 23 種 | `OTHER` —— `TYPE4242` のクエリを浴びせても何も鋳造されません |
| `tld` | 所有 TLD と `metrics.tracked_tlds` | `other` —— でたらめな TLD を掃くスキャナは何も鋳造しません |

**クエリ名がラベルになることは決してありません。** TLD の接尾辞だけであり、しかも運用者がすでにその接尾辞を選んだ場合に限られます。

### TLD ごとの分離

`rolodex_dns_queries_by_tld_total{tld}` はクエリの流れを TLD ごとに分解します。これが、スプリットホライズンのデプロイにおいて各ネットワークを互いから、また公開インターネットから切り分けられるものにしています。追跡される集合を作るものは三つあります：

1. **所有 TLD、自動で。** ネットワークスコープが所有する TLD はすべて —— 各スコープの暗黙の `.home` ドメインも含めて —— 頼まれずとも追跡されます。ネットワーク自身の名前空間こそもっとも分離する価値があるものであり、それを二度（所有するために一度、追跡するために一度）名指しさせるのは、系列が黙って欠けるという形で現れる罠です。
2. **設定の一覧。** YAML の `metrics.tracked_tlds` です。`common` という項目は組み込みの一般 TLD 一式（`com.`、`net.`、`org.`、`io.`、`dev.`、…）に展開されるので、よくある公開 TLD が二十行ではなく一行で済みます。設定の項目は固定されます：再起動を生き延び、API から削除することはできません。
3. **保存された一覧。** 再起動なしに実行中に管理されます：

```bash
# 一般の一式に、例外的な TLD を一つ加えて追跡
rolodex-dns-cli set-tracked-tlds --tld common --tld lab.internal

# 保存された集合、所有の集合、実効の集合を表示
rolodex-dns-cli list-tracked-tlds

# 保存された一覧を空にする（所有 TLD と設定で固定された TLD は影響を受けません）
rolodex-dns-cli set-tracked-tlds
```

**実効**の集合は三つすべての和であり、実際に系列を生むのはそれです —— どちらのコマンドもそれを表示するのはそのためです。保存された一覧だけでは、どの系列が現れるかは分かりません。

### DNS と DHCP は別々に選べる

DNS と DHCP はたまたま同じプロセスを共有している別々のサービスであり、その系列はわざと引き離してあります：

- DHCP のファミリは、その次元に汎用の `type` と `state` ではなく **`message_type`** と **`lease_state`** というラベルを付けます。汎用のラベル名こそが、両方のサブシステムにまたがる集約 —— たとえば記録ルール中の `sum by (type) (...)` —— に、DHCP の ACK の数を DNS の数へ黙って混ぜ込ませるものです。
- DNS のまとめ（`queries_total`、`traffic_bytes_total`、`records_served_total`、`queries_by_tld_total`）は **DNS だけ**を数えます。`:67` の DHCP パケットが DNS のトラフィックとして数えられることは決してなく、DHCP が登録した名前が DNS のメトリクスに寄与するのは、誰かが実際にそれを解決したときだけです。

> **更新時の注意：** `rolodex_dns_dhcp_messages_total{type}` は `{message_type}` に、`rolodex_dns_dhcp_leases{state}` は `{lease_state}` になりました。古いラベル名で選択しているダッシュボードやアラートは更新が必要です。

### よく使うクエリ

```promql
# トランスポート別のクエリ率
sum by (proto) (rate(rolodex_dns_queries_total[5m]))

# 解決順序のどの段階が答えているか
sum by (source) (rate(rolodex_dns_answers_total[5m]))

# 全応答に占める NXDOMAIN の割合
sum(rate(rolodex_dns_queries_total{rcode="NXDOMAIN"}[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# 応答キャッシュのヒット率
sum(rate(rolodex_dns_cache_hits_total[5m]))
  / (sum(rate(rolodex_dns_cache_hits_total[5m])) + sum(rate(rolodex_dns_cache_misses_total[5m])))

# トランスポート別の p99 クエリ遅延
histogram_quantile(0.99, sum by (le, proto) (rate(rolodex_dns_query_duration_seconds_bucket[5m])))
```

トラフィック量と、そのうちどれだけが否定の応答ではなく実際のレコードなのか：

```promql
# 線上の入出バイト
sum by (direction) (rate(rolodex_dns_traffic_bytes_total[5m]))

# 増幅率：受信 1 バイトあたりの送出バイト。公開の場から届くリスナーで
# この値が上がっていく形は、反射攻撃の姿です。
sum(rate(rolodex_dns_traffic_bytes_total{direction="tx"}[5m]))
  / sum(rate(rolodex_dns_traffic_bytes_total{direction="rx"}[5m]))

# クエリあたりに返されたレコード数 —— 百万の NXDOMAIN と百万の中身のある
# 応答は、同じクエリ数でありながらまるで違う仕事量です。
sum(rate(rolodex_dns_records_served_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))
```

ブロックリスト —— 大切な組はブロック数と拒否数です。ブロックの計数器だけを見ていると、答えるのをやめたリストときれいなリストが見分けられないからです：

```promql
# どのリストが一致したかで分けたブロック数
sum by (kind) (rate(rolodex_dns_blocklist_blocks_total[5m]))

# 全トラフィックに占めるブロックの割合
sum(rate(rolodex_dns_blocklist_blocks_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# 一致した経路ごとの許可リストの活動。ここが上がるのは、暴発している
# リストを運用者が延々と貼り紙で塞いでいるということです。
sum by (kind) (rate(rolodex_dns_blocklist_allowlisted_total[5m]))

# あるプロバイダーが評判を報告する代わりにこちらを拒否しはじめた
sum by (kind) (rate(rolodex_dns_blocklist_refusals_total[5m])) > 0

# 現在ローテーションから外れているプロバイダー
rolodex_dns_blocklist_rotated_out > 0
```

TLD ごと、上流の健全性、DNSSEC：

```promql
# 追跡している TLD ごとのクエリ率。追跡していない受け皿は除く
sum by (tld) (rate(rolodex_dns_queries_by_tld_total{tld!="other"}[5m]))

# 追跡していない名前へのトラフィックが占める割合
sum(rate(rolodex_dns_queries_by_tld_total{tld="other"}[5m]))
  / sum(rate(rolodex_dns_queries_by_tld_total[5m]))

# 反復階層から格下げされている（0=ルート、1=暗号化、2=ローカル、3=公開）
rolodex_dns_upstream_active_tier > 0

# 階層の入れ替わり
sum by (direction) (rate(rolodex_dns_upstream_tier_switches_total[5m]))

# 検証に失敗した署名済みデータ：攻撃か、自分の署名を壊したゾーンか。
# ネットワークの障害である `indeterminate` とは別物です。
sum(rate(rolodex_dns_dnssec_verdicts_total{verdict="bogus"}[5m])) > 0

# 検証に通らない DNSSEC を提供したために現在外されているルートサーバー。
# 一定して非ゼロなら、乗っ取られたか壊れたルートの実体です。すべてが同時なら、
# それはサーバーではなくトラストアンカーかルートゾーンです。
rolodex_dns_dnssec_blamed_roots > 0

# 答えているゾーンの外へ委任したために捨てられた紹介
rate(rolodex_dns_resolver_out_of_bailiwick_total[5m]) > 0

# 参照ごとのクエリ予算によって打ち切られた参照
rate(rolodex_dns_resolver_budget_exhausted_total[5m]) > 0
```

DHCP、分離されたラベル名を使って：

```promql
# 状態ごとのリース
rolodex_dns_dhcp_leases{lease_state="active"}

# 型ごとの DHCP メッセージ率
sum by (message_type) (rate(rolodex_dns_dhcp_messages_total[5m]))

# プールの枯渇
rate(rolodex_dns_dhcp_allocation_failures_total[5m]) > 0
```

制御面とホストの到達性：

```promql
# 誰かが gRPC の共有秘密を推測している
rate(rolodex_dns_grpc_auth_failures_total[5m]) > 0

# ホストが経路を持たないアドレスファミリ。そのレコードは抑制されています
rolodex_dns_address_family_reachable{family="ipv6"} == 0
```

上のクエリはいずれも、そのメトリクス名とラベルの照合子を生きた公開出力に対して解決するテストに覆われています。そのため、文書化されたクエリが存在しない系列を指すことはありません。

## ブロックリスト

Rolodex DNS は二つのやり方で名前を遮り、どちらもブロックされたクエリに `NXDOMAIN` で答えます：

- **DNSBL プロバイダー** —— 名前で問い合わせる第三者のゾーン。下の [DNSBL（ドメインブロックリスト）](#dnsblドメインブロックリスト)で扱います。
- **ローカルの一覧** —— 運用者が手で遮った名前とアドレスの、データベースに支えられた表。

どちらも既定では無効／空です：プロバイダーが追加されるまで、外部への問い合わせは行われず、ブロックリストの運用者に名前が渡ることもありません。

### ローカルブロックリストのデータベース

ローカルの項目は運用者自身の一覧であり、どのプロバイダーに問い合わせるよりも先に照会されます。`AddLocalBlocklistEntry`、`RemoveLocalBlocklistEntry`、`ListLocalBlocklistEntries` で管理します。

項目は、正引き名の関門で照合される**ドメイン**か、逆引き参照で照合される**アドレス**を指せます。アドレスはどちらの書き方でも構いません —— リテラルでも、`dig -x` が表示する `in-addr.arpa`／`ip6.arpa` の名前でも —— どちらの綴りでも遮ります。アドレスを遮るのはこの一覧だけです：プロバイダーには解決しようとしている名前を尋ねるのであり、逆引きにおいてそれは、誰も評判を公開していない名前だからです。

```bash
# 特定の IP を理由付きで遮る
rolodex-dns-cli add-local-blocklist --name 10.0.0.5 --reason "known spam source"

# ローカルの項目を一覧
rolodex-dns-cli list-local-blocklist

# 項目を削除
rolodex-dns-cli remove-local-blocklist --name 10.0.0.5
```

### キャッシュ

- 肯定の結果（その名前は載っている）は、プロバイダーが返した TTL のあいだキャッシュされます
- 否定の結果（載っていない）は 5 分間キャッシュされます
- 参照のエラーはキャッシュされず、偽陽性を避けるために「載っていない」として扱われます
- 拒否もキャッシュされず、そのプロバイダーをローテーションから外します —— 下を参照
- キャッシュは `FlushCache` の gRPC メソッドで破棄でき、これはローテーションから外れたすべてのプロバイダーをローテーションへ戻します

### 拒否コードとプロバイダーのローテーション

DNSxL は、掲載も*あなた*への苦情も同じやり方で答えます：`127.0.0.0/8` 配下の `A` レコードです。`zen.spamhaus.org` は「載っている」を `127.0.0.2` で、「あなたは公開リゾルバー経由で問い合わせている」を `127.255.255.254` で告げ、**両者を区別するのはアドレスだけ**です。どんな `A` レコードも掲載だと読むと、あるブロックリストがあなたへの返答をやめると決めた瞬間が、そのプロバイダーに照会した*すべての*名前に対する NXDOMAIN へ変わります —— そしてそれは、あなたのクエリ量がそのプロバイダーの閾値を越えたときに始まります。問題なさそうに見えたデプロイの何時間、あるいは何週間もあとに。Spamhaus は直截に述べています。これらのコードは「いかなる種類の評判とも解釈されるべきではない」と。

そこで各プロバイダーは拒否コードの集合を持ちます。一致した応答は **`Refused`** です：掲載でもなく、否定でもなく、何もキャッシュされません —— 問い合わせた名前について何も学ばれなかったのです。同じ応答の中では、掲載よりも拒否が勝ちます。苦情を言っているプロバイダーが同時に評判を報告しているはずはありませんし、こちらへ倒れておけば*開く*方向に失敗するのに対し、逆の順序ではすべての名前について閉じる方向に失敗するからです。

プロバイダーが何も設定しないときに使われる組み込みの一式：

| コード | 意味 |
| ---- | ------- |
| `127.255.255.0/24` | Spamhaus のエラー範囲：`.252` はゾーン名の綴り誤り、`.254` は公開／開放リゾルバー経由のクエリ、`.255` は過剰なクエリ。三つのコードではなく範囲まるごとにしてあるのは、Spamhaus がこの範囲を予約しており、そこへ追加していくからです |
| `127.0.1.255` | Spamhaus DBL が IP クエリに答えたもの —— 「IP クエリには対応していない」 |
| `127.0.2.255` | Spamhaus ZRD が IP クエリに答えたもの —— 同上 |
| `127.0.0.1` | URIBL/SURBL の「クエリを遮った」。RFC 5782 §5 は DNSxL が `127.0.0.1` を掲載することも禁じているので、これが正当な掲載であることはありません |
| `127.0.0.255` | URIBL の「クエリを遮った」（割り当て超過） |

各項目は IPv4 アドレスか `アドレス/プレフィックス` です。**空は組み込みの一式を意味します** —— それが「コードなし」を意味することはありえません。この機能ができる前に書かれたすべての設定が空だからです。`none` ひとつだけの項目は、本物の掲載が上のいずれかと衝突する私的なブロックリストのために検出を無効にします。明示的な一覧はちょうどその一覧であり、既定が混ぜ込まれることはないので、書き下す運用者はそれを狭めることもできます。解釈できないコードは、飛ばされるのではなく拒否されます —— 起動時に、あるいは RPC からは `InvalidArgument` で。黙って適用されないコードは、掲載として読まれる拒否だからです。

**ローテーション。** 拒否があると、そのプロバイダーは `refusal_cooldown_secs`（既定 3600 秒、プロバイダー単位の上書きが可能）のあいだ参照のローテーションから外れます。やめてくれと言ったばかりのブロックリストを毎回の要求で叩くのではなく、下がって待つのです。ローテーションは：

- **新しい参照だけ**を飛ばします —— すでにキャッシュされた判定は依然として数えます。「このプロバイダーは新しい問いには答えない」は「すでに与えた答えが間違っていた」ではないからです。
- **ひとりでに切れます**。そのため一時的な割り当て超過は、運用者が何もしなくても治ります。
- `flush-cache` と、あらゆる `set-dnsbl-config` によって**解除されます** —— 設定のやり直しはしばしば拒否の修正そのものだからです（ゾーン名の綴り誤りは `127.255.255.252` の原因であると同時に、いま直しているものでもあります）。
- `get-dnsbl-config` と `rolodex_dns_blocklist_refusals_total{kind}` ／ `rolodex_dns_blocklist_rotated_out` によって**報告されます**。

冷却を `0` にすることは「冷却なし」ではなく「既定を使う」を意味します —— 冷却ゼロは、やめてくれと言ったばかりのプロバイダーへ問い直すことであり、それこそローテーションが防ぐために存在する挙動だからです。

## DNSBL（ドメインブロックリスト）

DNSBL プロバイダーは**ドメイン名**で遮ります：問い合わせる名前のラベルがプロバイダーのゾーンの前に付けられるので、`dbl.spamhaus.org` に対する `googleadservices.com` は `googleadservices.com.dbl.spamhaus.org` として問い合わされます。Spamhaus DBL、SURBL、URIBL はこのように動きます。

DNSBL はブロックリストに**外部 DNS より高い優先度**を与えます。この照会はローカルレコードと管理下／権威のゾーンのあとに走るので、内部のデータは常に勝ちます —— しかし上流の応答キャッシュとあらゆる外部解決よりは**前**です。したがって載っている名前は、以前に転送応答がキャッシュされていたとしても NXDOMAIN を返します。

DNSBL は既定では無効でプロバイダーの一覧は空であり、個々のプロバイダーは独立に有効／無効にできます。有効だが空の DNSBL は何もしません。運用者がふつうに追加する標準的なゾーンは `dbl.spamhaus.org`、`multi.surbl.org`、`multi.uribl.com` です。結果は上記のとおりキャッシュされます（肯定はプロバイダーの TTL、否定は 5 分）。

```bash
rolodex-dns-cli set-dnsbl-config --enabled --providers dbl.spamhaus.org:true
rolodex-dns-cli get-dnsbl-config
```

### ホストを許可リストに載せる

許可リストは偽陽性からの運用者の逃げ道であり、**すべてのリストと両方の関門**を覆います：正引き名の照会（DNSBL プロバイダーとローカルブロックリスト）*と*、逆引き DNS／IP の照会（アドレスを指すローカル項目）です。誤って載せられた IP は、まともに動いているホストの `dig -x` を壊すので、名前にしか届かない逃げ道は逃げ道になりません。

- **名前は接尾辞で照合されます。** 一つの項目がその名前とその配下すべてを覆うので、`example.com` を許可すれば `www.example.com` も免除されます。照合はラベルの境界で行われるので、`notexample.com` は免除されません。
- **アドレスはどちらの書き方でも指せます。** 逆引きのクエリは、`in-addr.arpa`／`ip6.arpa` の名前を指す項目でも、*あるいは*それが符号化している IP リテラルを指す項目でも免除されるので、誰もオクテットを手で逆さにする必要はありません。逆引きの**名前**はほかの DNS 名と同じく接尾辞で照合されます（`1.168.192.in-addr.arpa` を許可すればその /24 全体の遮断が解けます）。IP の**リテラル**は**完全一致**で照合されます。アドレスは上位オクテットから並ぶので —— `1.100` は `192.168.1.100` の親ではなく、親のように扱えば誰も指していないアドレスまで免除してしまうからです。
- **照会そのものを短絡します。** 免除された名前やアドレスは、どのプロバイダーにも照会されず、ブロックリストへの参照を一切発しません。
- 項目は正規化されるので（小文字化、末尾のドット）、どの綴りでも同じ項目を追加・削除します。再起動をまたいで残り、キャッシュを破棄せずとも次のクエリから効きます。

```bash
# あるプロバイダーが偽陽性を出しているホストを免除する
rolodex-dns-cli add-dnsbl-allow --name vendor.example.com --reason "blocklist false positive"

# アドレスを免除する —— どちらの綴りでも効きます
rolodex-dns-cli add-dnsbl-allow --name 192.168.1.100 --reason "our own mail relay"
rolodex-dns-cli add-dnsbl-allow --name 1.168.192.in-addr.arpa --reason "whole /24"

# 許可リストを一覧
rolodex-dns-cli list-dnsbl-allow

# 項目を削除
rolodex-dns-cli remove-dnsbl-allow --name vendor.example.com
```

## ネットワークスコープ

ネットワークスコープはスプリットホライズンの DNS ビューを提供し、クライアントの IP がどのネットワークスコープに結び付いているかによって異なる DNS 応答を返せるようにします。

### 概念

- **ネットワークスコープ**：自前の DNS レコード一式と、予約された `.home` ドメイン（たとえば `office.home.`）を持つ、名前の付いた DNS ビュー。`.home` ドメインは DHCP クライアントの既定の検索ドメインとして使われます。
- **ネットワークの結び付き**：クライアントの IP からスコープへの対応付け。TTL を持ち、定期的に更新しなければなりません。TTL が切れると、その IP はスコープとの結び付きを失い、DNS クエリは拒否されます。
- **スコープ付きレコード**：特定のスコープに属し、そのスコープに結び付いた IP からのみ見える DNS レコード。

### どう動くか

1. ネットワークスコープを作ります（たとえばドメイン `"office.home."` を持つ `"office"`）
2. そのスコープにスコープ付き DNS レコードを追加します
3. クライアントの IP が（TTL 付きで）スコープに結び付いてネットワークに参加します
4. DNS クエリが届いたとき：
   - TLD ごとの**入口リスナー**に届いた場合：どんな名前についても、そのリスナーを所有するスコープの中で提供されます
   - 発信元 IP がスコープに結び付いている場合：まずスコープ付きレコードを調べ、次に全体のレコードへ落ち、次に外部で解決します
   - 発信元 IP が `security.overlay_cidrs` の内側にあり（オーバーレイ／WireGuard のピア）、どのスコープにも参加していない場合：**REFUSED**
   - それ以外の発信元 —— ループバック、LAN、コンテナのブリッジ —— は信頼されます：決して拒否されず、全体の名前空間を解決します
   - スコープが一つも存在しない場合：従来の挙動（すべてのクエリが全体のレコードから提供されます）
5. 検索ドメイン（`GetSearchDomains` 経由）は DHCP との連携のために `.home` ドメインを返します

### 信頼される発信元とオーバーレイのピア

スコープの強制が適用されるのは、`security.overlay_cidrs`（既定 `10.64.0.0/10`、WireGuard のオーバーレイ範囲）の内側にある発信元 IP に**限られます**。そうしたピアはネットワークに参加していなければ拒否され、自分のスコープの分割された TLD しか見えません。それ以外の発信元はすべて信頼され、全体のビューを解決します。

これがスプリットホライズンを実際に役立つものにしています：ある名前が、この機体の LAN 側アドレスを指す全体のレコードと、そのオーバーレイのアドレスを指すスコープ付きレコードの両方を持てて、それぞれの側は実際に経路のあるアドレスを渡されるのです。

### 再帰のアクセス制御

スコープの強制は、ある発信元が*どのビュー*を得るかを決めます。それとは別の軸である `security.recursion_cidrs` は、その発信元がそもそも**上流解決**を得られるかどうかを決めます。

`dns.bind` の既定は `0.0.0.0:53` なので、経路のあるインターフェイスではリスナーがインターネット全体から届き、`overlay_cidrs` の外側の発信元はすべて信頼されたローカルクライアントに分類されます。二つ目の確認が無ければ、それは**オープンな再帰リゾルバー**です —— 送信元を偽った小さなクエリが、偽られた被害者へ向けた大きな応答を返し、外向きの解決トラフィックがあなたの機体に請求される、あの古典的な反射／増幅の資産です。

既定の一覧は、インターネットから経路の無い範囲すべてです —— `127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`100.64.0.0/10`、`::1/128`、`fe80::/10`、`fc00::/7` —— これでループバック、LAN、コンテナのブリッジ、WireGuard のオーバーレイ（`10.64.0.0/10` は `10.0.0.0/8` の内側です）が覆われるので、このサーバーを正当に使っていたものがサービスを失うことはありません。空の一覧は誰に対しても再帰を閉じ、純粋な権威サーバーが残ります。

- **この確認はローカルと外部の境目に置かれます**：このサーバーが持つデータから答えるすべての経路のあと、持たないデータを取りに行くすべての経路の前です。見知らぬ相手も、あなたの権威応答と権威ある NXDOMAIN は依然として受け取れますが —— 再帰を閉じることが、自分のゾーンにとってこの機体をブラックホールに変えてはなりません —— 誰かほかに尋ねに行かせることはできません。
- **応答キャッシュより前に走ります**。キャッシュされた応答は、解決したての応答とまったく同じだけよく増幅しますし、キャッシュを温めることこそ攻撃の仕込みだからです。
- **拒否は応答部が空の REFUSED です**。そのため返信が、それを引き起こした質問より大きくなることはありません。
- **すべてのトランスポートに関門がかかります** —— UDP、TCP、DoT、DoQ、そして DoH（DoH は接続情報とともに提供するので、そのピアのアドレスが分類まで届きます。さもなくば `:443` が `:53` の閉じたものを開け直してしまいます）。

### ネットワーク単位の所有 TLD

暗黙の `.home` ドメインのほかに、スコープはネットワーク間で名前空間を分割する追加の TLD を所有できます。所有される TLD はいずれも一つのスコープにとって**全域で一意**であり、その配下の名前が上流へ転送されることは決してありません —— 一致しない名前は、任意でその TLD の*ピアフォワーダー*（同じネットワークのほかの Rolodex 構成員のオーバーレイアドレス）に尋ねたのち、権威ある NXDOMAIN になります。

- **オーバーレイのピア**にとって、所有 TLD は厳密に分割されています：自分のネットワークの TLD は解決でき、ほかのスコープの TLD には NXDOMAIN が返るので、二つのネットワークの TLD が一つの端点から両方とも解決できることはありません。
- **信頼されたローカルの発信元**（ループバック／LAN）にとっては、*すべての*所有 TLD がそれを所有するスコープから解決するので、すべてのネットワークの TLD が LAN 上で見えます。二つの側に置かれた名前は依然として LAN 向けの全体の値を返し、スコープにしか無い名前だけがスコープから提供されます。

したがってスコープは、オーバーレイを一度も結び付けないまま、TLD を所有するためだけに —— それをピアから分割され、かつ LAN から解決できるものと印を付けるためだけに —— 存在できます。

```bash
# スコープに所有 TLD を登録
rolodex-dns-cli add-scope-tld -s office --tld office.
# その配下の一致しない名前を、ネットワークのほかの Rolodex 構成員へ向ける
rolodex-dns-cli set-scope-tld-forwarders -s office --tld office. -f 10.64.0.2:53
rolodex-dns-cli list-scope-tlds -s office
```

### 入口 DNS リスナー

所有 TLD は、ローカルの**入口 IP**（`add-scope-tld --listen-ip`）、通常はそのネットワーク自身のオーバーレイアドレスとともに登録できます：

```bash
rolodex-dns-cli add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
rolodex-dns-cli list-scope-tld-listeners -s office
```

これは三つのことを行います：

1. **その IP に DNS リスナーを結び付けます**（UDP ＋ TCP）。ポートは `dns.ingress_listen_port`（既定 53）です。リスナーは起動時にデータベースから作り直され、その IP を参照する最後の TLD が削除されたときに畳まれます。結び付けに失敗した場合 —— 起動時、オーバーレイのインターフェイスがまだ存在しないという、よくある場合です —— は、「もう待ち受けている」と覚え込むのではなく、次の再登録で再試行されます。
2. **どんな名前についても、所有するスコープのビューを提供します。** このリスナーはそのネットワーク専用のリゾルバーなので、そこへ届いたクエリは名前が何であれ所有するスコープに属します：所有 TLD は分割されたままで、それ以外はすべて全体の解決と上流の解決へ落ちます —— これがピアにこれを汎用のリゾルバーとして使わせるものです。
3. **登録された名前を入口 IP へ書き換えます。** その TLD の配下で A/AAAA レコードが保存されている名前には、保存された背後の値ではなく入口 IP が返るので、そのネットワークの入口コントローラーがトラフィックを受け取り、Host/SNI で振り分けます。この部分は名前による関門を保ちます：素通しの名前は解決された値をそのまま保ち、同じ名前でも主たる `:53` のリスナー上では保存された値に解決し、レコードの無い名前は依然として NXDOMAIN を返します（ワイルドカードによる合成はありません）。

### 解決順序（スコープ付き）

1. EDNS の OPT レコードを解釈（ペイロードサイズの折衝、DNSSEC のための DO ビット）
2. ローカルブロックリストを照会（逆引き DNS クエリについて）
3. DNS 応答キャッシュを確認
4. クライアントのスコープのスコープ付きレコードを確認
5. スコープ付きの CNAME レコードを確認
6. スコープ付きの DNAME レコードを確認（サブツリーの書き換え）
7. 名前がスコープ付きの管理下ゾーンの配下かを確認（権威ある NXDOMAIN）
8. 全体のデータベースのレコードを確認
9. 全体の CNAME レコードを確認
10. 全体の DNAME レコードを確認（サブツリーの書き換え）
11. ANAME レコードを確認（ゾーン頂点で別名を解決）
12. 名前が全体の管理下ゾーンの配下かを確認（権威ある NXDOMAIN）
13. ワイルドカードレコードを確認（`*.zone.`）
14. ローカルブロックリストと DNSBL プロバイダーを照会（載っている名前は NXDOMAIN。あらゆる外部の応答に優先します）
15. `security.recursion_cidrs` を強制 —— その外側の発信元は、何かが機体の外へ届く前に REFUSED になります
16. `resolution.mode` に従って外部で解決（有効なら QNAME の大小文字ランダム化を伴い、設定されていればプロキシ経由で）、反復経路では DNSSEC を検証
17. DNS64 の合成を適用（有効で、かつ AAAA クエリが空で返り A レコードが存在する場合）
18. 応答をキャッシュ（Bogus な応答は決してキャッシュされません）
19. TTL ドリフトの調整を適用（設定されている場合）
20. 経路の無いアドレスファミリの A/AAAA 応答を落とす（`address_family.mode: auto` の場合）

## DHCP サーバー

Rolodex DNS には、IP アドレス管理と DNS への自動登録を備えた統合 DHCPv4 サーバーが含まれます。設定に `dhcp` 節が無い限り無効です。

- **スコープ単位のプール。** 各プールはネットワークスコープに属し、連続した一つの範囲、ゲートウェイ、サブネットマスク、DNS サーバーを定めます。プールが尽きると割り当ては失敗します —— プールをまたいだ集約はありません。MAC と IP の束縛は粘着します：同じ MAC には常に同じ IP が返ります。
- **DNS への自動登録。** ホスト名（オプション 12）を送るクライアントは `<hostname>.lan.<dhcp.tld>.` の A レコードと、対応する `in-addr.arpa` の PTR を得ます。どちらもそのプールのスコープの中のスコープ付きレコードです。リースはネットワークスコープにも参加させられる（`JoinNetwork`）ので、クライアントはただちにそのネットワークのスプリットホライズンのビューを見ます。どちらのレコードも、リースが解放されるか期限切れになると削除されます。
- **リースの状態。** `active`、`expired`（期間を過ぎた）、`released`（クライアントが解放した）、`reclaimable`（`reclaim_timeout` を過ぎ、その IP を再び配れる）。
- **証明書の配布。** 証明書はサイト固有の DHCP オプション（コード 224–254）を通じてクライアントへ渡せます。スコープ単位で設定します。
- **背景での掃除。** `sweep_interval` 秒ごとに、期限切れのリースが片付けられ（その DNS レコードとスコープとの結び付きが削除されます）、`reclaim_timeout` を過ぎたリースは IP を解放します。

```bash
# "office" スコープのためのプール
rolodex-dns-cli add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1

rolodex-dns-cli list-dhcp-pools -s office
rolodex-dns-cli list-dhcp-leases -s office
```

## Go クライアント

Rolodex DNS の gRPC API へプログラムから触れるための Go クライアントライブラリが `go/` にあります。Go モジュールの依存として取り込めます。

### インストール

```
go get gitea.com/town-os/rolodex-dns/go
```

### 接続

クライアントは二つのトランスポートに対応します：

**TCP**（共有秘密による認証つき）：

```go
client, err := rolodex_dns.Dial(ctx, "localhost:50051",
    rolodex_dns.WithAuthToken("my-secret"),
)
defer client.Close()
```

**Unix ソケット**（サーバー側で認証が迂回されます）：

```go
client, err := rolodex_dns.Dial(ctx, "/var/run/rolodex-dns.sock",
    rolodex_dns.WithUnixSocket(),
)
defer client.Close()
```

### クライアントのオプション

| オプション | 説明 |
|--------|-------------|
| `WithAuthToken(token)` | TCP 認証のために、すべての RPC とともに送る共有秘密を設定します。Unix ソケット接続ではサーバーが無視します。既定：空（サーバーに秘密が設定されていなければ成功します） |
| `WithUnixSocket()` | アドレスを TCP のアドレスではなく Unix ドメインソケットのパスとして印を付けます。サーバーは Unix ソケット接続について認証を迂回します |
| `WithGRPCDialOption(opt)` | 低水準の `grpc.DialOption` を追加します（TLS やインターセプタなどのため） |

### クライアントのメソッド

すべてのメソッドは、取り消しと期限のために `context.Context` を受け取ります。

#### レコード管理

| メソッド | 説明 |
|--------|-------------|
| `AddRecord(ctx, record) error` | DNS レコードを追加 |
| `RemoveRecord(ctx, name, opts) (uint32, error)` | DNS レコードを削除（削除した数を返します） |
| `ListRecords(ctx, opts) ([]*DnsRecord, error)` | DNS レコードを一覧／絞り込み |

#### フォワーダー

| メソッド | 説明 |
|--------|-------------|
| `SetForwarders(ctx, forwarders) error` | 上流 DNS フォワーダーを設定 |
| `SetResolutionMode(ctx, mode) error` | 解決モード（`auto`、`recursive`、`forward`）を実行時に切り替え |
| `GetResolutionMode(ctx) (string, error)` | いま効いているモードを取得 |

#### ブロックリスト

| メソッド | 説明 |
|--------|-------------|
| `SetDnsblConfig(ctx, enabled, providers) error` | DNSBL（ドメインブロックリスト）の設定を変更 |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs) error` | 同じもの。拒否したプロバイダーをローテーションから外す時間を一覧全体について指定します |
| `GetDnsblConfig(ctx) (*DnsblStatus, error)` | 現在の DNSBL 設定、解決された拒否コード、ローテーションから外れたプロバイダーを取得 |
| `FlushCache(ctx) error` | ブロックリストのキャッシュを破棄し、外れたプロバイダーをすべてローテーションへ戻します |
| `AddLocalBlocklistEntry(ctx, entry) error` | ローカルブロックリストに項目を追加 |
| `RemoveLocalBlocklistEntry(ctx, name) error` | ローカルブロックリストの項目を削除 |
| `ListLocalBlocklistEntries(ctx) ([]*LocalBlocklistEntry, error)` | ローカルブロックリストの項目を一覧 |
| `AddDnsblAllowlistEntry(ctx, entry) error` | ある名前（とその配下）をブロックリストの照会から免除 |
| `RemoveDnsblAllowlistEntry(ctx, name) error` | DNSBL 許可リストの項目を削除 |
| `ListDnsblAllowlistEntries(ctx) ([]*DnsblAllowlistEntry, error)` | DNSBL 許可リストの項目を一覧 |

#### ネットワークスコープ

| メソッド | 説明 |
|--------|-------------|
| `CreateNetworkScope(ctx, scope) error` | ネットワークスコープを作成 |
| `DeleteNetworkScope(ctx, name) error` | スコープとそのデータを削除 |
| `ListNetworkScopes(ctx) ([]*NetworkScope, error)` | すべてのスコープを一覧 |
| `JoinNetwork(ctx, ip, scope, ttl) error` | IP をスコープに結び付ける |
| `LeaveNetwork(ctx, ip) error` | IP のスコープとの結び付きを解除 |
| `GetNetworkAssociations(ctx, scope) ([]*NetworkAssociation, error)` | 結び付きを一覧 |
| `AddScopedRecord(ctx, scope, record) error` | スコープ付きの DNS レコードを追加 |
| `RemoveScopedRecord(ctx, scope, name, opts) (uint32, error)` | スコープ付きレコードを削除 |
| `ListScopedRecords(ctx, scope, opts) ([]*DnsRecord, error)` | スコープ付きレコードを一覧 |
| `GetSearchDomains(ctx, ip) ([]string, error)` | ある IP の検索ドメインを取得 |
| `AddScopeTld(ctx, scope, tld) error` | スコープに全域で一意な所有 TLD を登録 |
| `AddScopeTldWithListener(ctx, scope, tld, listenIP) error` | 所有 TLD を登録し、入口 DNS リスナーを結び付ける |
| `RemoveScopeTld(ctx, scope, tld) error` | スコープから所有 TLD を削除 |
| `ListScopeTlds(ctx, scope) ([]string, error)` | スコープが所有する TLD を一覧 |
| `SetScopeTldForwarders(ctx, scope, tld, forwarders) error` | TLD のピアフォワーダーを設定 |
| `ListScopeTldForwarders(ctx, scope, tld) ([]string, error)` | TLD のピアフォワーダーを一覧 |
| `ListScopeTldListeners(ctx, scope) ([]*TldListener, error)` | スコープの入口 DNS リスナーを一覧 |

#### DHCP

| メソッド | 説明 |
|--------|-------------|
| `AddDhcpPool(ctx, pool) (string, error)` | スコープの DHCP アドレスプールを追加 |
| `RemoveDhcpPool(ctx, poolID) error` | DHCP プールを削除 |
| `ListDhcpPools(ctx, scope) ([]*DhcpPool, error)` | DHCP プールを一覧 |
| `ListDhcpLeases(ctx, scope) ([]*DhcpLease, error)` | DHCP リースを一覧 |
| `DeleteDhcpLease(ctx, mac) error` | MAC で DHCP リースを削除 |
| `SetDhcpCertOption(ctx, opt) error` | DHCP オプションで証明書を配る |
| `RemoveDhcpCertOption(ctx, scope, optionCode) error` | DHCP の証明書オプションを削除 |
| `ListDhcpCertOptions(ctx, scope) ([]*DhcpCertOption, error)` | DHCP の証明書オプションを一覧 |

#### 権威ゾーン

| メソッド | 説明 |
|--------|-------------|
| `AddAuthoritativeZone(ctx, zone) error` | ゾーンを権威として宣言 |
| `RemoveAuthoritativeZone(ctx, zone) error` | 権威ゾーンを削除 |
| `ListAuthoritativeZones(ctx) ([]string, error)` | 権威ゾーンを一覧 |

#### キャッシュ

| メソッド | 説明 |
|--------|-------------|
| `GetCacheStats(ctx) (*CacheStats, error)` | キャッシュの統計を取得（項目数、ヒット、ミス） |
| `FlushDnsCache(ctx) error` | DNS 応答キャッシュを破棄 |

#### 暗号化トランスポート

| メソッド | 説明 |
|--------|-------------|
| `SetDotConfig(ctx, config) error` | DNS-over-TLS を設定 |
| `GetDotConfig(ctx) (*DotConfig, error)` | DoT の設定を取得 |
| `SetDohConfig(ctx, config) error` | DNS-over-HTTPS を設定 |
| `GetDohConfig(ctx) (*DohConfig, error)` | DoH の設定を取得 |
| `SetDoqConfig(ctx, config) error` | DNS-over-QUIC を設定 |
| `GetDoqConfig(ctx) (*DoqConfig, error)` | DoQ の設定を取得 |

#### プロキシ

| メソッド | 説明 |
|--------|-------------|
| `SetProxyConfig(ctx, config) error` | HTTP プロキシを設定 |
| `GetProxyConfig(ctx) (*ProxyConfig, error)` | プロキシの設定を取得 |

#### DNSSEC

| メソッド | 説明 |
|--------|-------------|
| `GenerateDnssecKey(ctx, zone, algorithm, keyType) (*DnssecKey, error)` | DNSSEC 鍵ペアを生成 |
| `ListDnssecKeys(ctx, zone) ([]*DnssecKey, error)` | ゾーンの DNSSEC 鍵を一覧 |
| `DeleteDnssecKey(ctx, keyID) error` | DNSSEC 鍵を削除 |
| `GetDsRecords(ctx, zone) ([]string, error)` | レジストラ向けの DS レコードを取得 |
| `SignZone(ctx, zone) error` | ゾーンをその鍵で署名 |

#### DANE / ACME

| メソッド | 説明 |
|--------|-------------|
| `GenerateTlsaRecord(ctx, opts) (string, error)` | 証明書から TLSA レコードを生成 |
| `ListTlsaRecords(ctx, domain) ([]*DnsRecord, error)` | あるドメインの TLSA レコードを一覧 |
| `GenerateDaneRootCa(ctx, name) (string, error)` | 自己署名の DANE ルート CA を生成 |
| `RequestAcmeCert(ctx, domain, providerURL) error` | ACME DNS-01 の証明書を要求 |
| `GetAcmeStatus(ctx, domain) (*AcmeStatus, error)` | ACME 証明書の状態を取得 |
| `EnsureZoneCa(ctx, zone) (*ZoneCa, error)` | ゾーン単位の中間 CA の存在を確かめる |
| `CreateEabCredential(ctx, zone) (*EabCredential, error)` | ゾーンに限定された EAB 資格情報を発行 |
| `RemoveEabCredential(ctx, kid) error` | EAB 資格情報を削除 |
| `ListAcmeAccounts(ctx) ([]*AcmeAccount, error)` | 登録済みの ACME アカウントを一覧 |
| `ListAcmeCertificates(ctx, zone) ([]*AcmeCertificate, error)` | 発行済みの証明書を一覧 |

#### TTL ドリフト

| メソッド | 説明 |
|--------|-------------|
| `SetTtlDriftConfig(ctx, config) error` | TTL ドリフトを設定 |
| `GetTtlDriftConfig(ctx) (*TtlDriftConfig, error)` | TTL ドリフトの設定を取得 |

#### DNS64

| メソッド | 説明 |
|--------|-------------|
| `SetDns64Config(ctx, config) error` | DNS64 の合成を設定 |
| `GetDns64Config(ctx) (*Dns64Config, error)` | DNS64 の設定を取得 |

#### 可観測性

| メソッド | 説明 |
|--------|-------------|
| `GetQueryLatencyStats(ctx) ([]*QueryLatencyStats, error)` | サーバーごとの遅延統計を取得 |
| `SetTrackedTlds(ctx, tlds) ([]string, error)` | 追跡する TLD の一覧を置き換え、実効の集合を返す |
| `ListTrackedTlds(ctx) (*TrackedTlds, error)` | 保存・実効・所有の TLD の集合を取得 |

#### 接続

| メソッド | 説明 |
|--------|-------------|
| `Close() error` | gRPC の接続を閉じる |

### レコード型

| 定数 | 値 | 説明 |
|----------|-------|-------------|
| `RecordTypeA` | 0 | IPv4 アドレス（既定） |
| `RecordTypeAAAA` | 1 | IPv6 アドレス |
| `RecordTypeCNAME` | 2 | 正準名の別名 |
| `RecordTypeMX` | 3 | メール交換（Priority を使います） |
| `RecordTypeTXT` | 4 | テキストレコード |
| `RecordTypeNS` | 5 | ネームサーバー |
| `RecordTypeSOA` | 6 | 権威の開始 |
| `RecordTypeSRV` | 7 | サービスの位置（Priority を使います） |
| `RecordTypePTR` | 8 | 逆引き DNS のためのポインタ |
| `RecordTypeURI` | 9 | URI リソースレコード（RFC 7553） |
| `RecordTypeSSHFP` | 10 | SSH フィンガープリント（RFC 4255） |
| `RecordTypeDNAME` | 11 | 委任名（RFC 6672） |
| `RecordTypeANAME` | 12 | 別名（ゾーン頂点での CNAME の代替） |
| `RecordTypeZONEMD` | 13 | ゾーンメッセージダイジェスト（RFC 9156） |
| `RecordTypeTLSA` | 14 | TLS 証明書の関連付け（RFC 6698） |
| `RecordTypeDNSKEY` | 15 | DNSSEC の公開鍵 |
| `RecordTypeDS` | 16 | DNSSEC の委任署名者 |
| `RecordTypeRRSIG` | 17 | DNSSEC のリソースレコード署名 |
| `RecordTypeNSEC` | 18 | DNSSEC の次のセキュアレコード |
| `RecordTypeNSEC3` | 19 | DNSSEC の次のセキュアレコード v3 |
| `RecordTypeNSEC3PARAM` | 20 | DNSSEC の NSEC3 パラメータ |
| `RecordTypeCERT` | 21 | DNS 内の証明書格納（RFC 4398） |

## RFC への準拠

| RFC | 名称 | 対応 |
|-----|------|---------|
| RFC 1034 / 1035 | ドメイン名 —— 概念と実装 | ルートサーバーからの反復解決、委任の追跡、グルーおよびグルー無しの NS の扱い |
| RFC 2308 | DNS クエリのネガティブキャッシュ | ネガティブ TTL は `min(SOA MINIMUM, SOA TTL)` として取り、公開されたとおりに尊重します |
| RFC 4033 / 4034 / 4035 | DNSSEC のプロトコル、レコード、プロトコルの修正 | ゾーン署名（正準 RRset 上の RRSIG、KSK/ZSK の役割、DS の計算）と上流の検証（ルートからの信頼の連鎖、四つの判定、AD/DO の扱い）。NSEC/NSEC3 は検証しますが決して生成しません |
| RFC 4255 | SSHFP の DNS レコード | 完全（保存、参照、アルゴリズム／フィンガープリント型） |
| RFC 4398 | CERT の DNS レコード | 完全（保存、参照、PKIX の CA 連鎖の配布） |
| RFC 4592 | DNS のワイルドカード | 完全（単一ラベルの置換、完全一致の優先） |
| RFC 5155 | DNSSEC のハッシュ化された認証付き否定（NSEC3） | 検証のみ（最近接包含者、opt-out、RFC 9276 に沿う反復回数の上限）。決して生成しません |
| RFC 5782 | DNSBL | 完全（名前ベースのクエリ形式、ローカル ＋ 外部のプロバイダー、`127.0.0.1` を掲載として読むことは決してありません） |
| RFC 6147 | DNS64 | 完全（A レコードからの AAAA 合成、設定可能なプレフィックス） |
| RFC 6605 / 8080 | DNSSEC のための ECDSA と Ed25519 | 完全（署名と検証。Ed448 は `ring` が対応せず） |
| RFC 6672 | DNAME | 完全（サブツリーの書き換え、所有者名には適用しません） |
| RFC 6698 | DANE TLSA | 完全（TLSA レコードの生成、保存、DNS での解決） |
| RFC 6840 | DNSSEC の明確化 | 対応していないアルゴリズムの応答は Insecure として扱います（§5.11）。AD は求めたクライアントにのみ立てます（§5.7） |
| RFC 6891 | EDNS(0) | 完全（OPT レコード、ペイロードの折衝、DO ビット、BADVERS）。検証時、外向きの反復クエリは 1232 バイトのペイロードとともに DO を運びます |
| RFC 7553 | URI の DNS レコード | 完全（保存と参照） |
| RFC 7766 | TCP 上の DNS トランスポート | 最後の活動から測る待機タイムアウト付きの接続再利用、2 バイトの長さ枠取り、リスナーごとの接続上限 |
| RFC 7858 | DNS-over-TLS | 完全（TLS で包んだ TCP、ポート 853）—— サーバーのリスナーと上流のクライアント |
| RFC 8484 | DNS-over-HTTPS | 完全（GET ＋ POST、application/dns-message、Cache-Control）—— サーバーのリスナーと上流のクライアント |
| RFC 8555 | ACME | サーバー側（組み込みの認証局、dns-01 の自己検証、EAB） |
| RFC 9250 | DNS-over-QUIC | 完全（QUIC トランスポート、双方向ストリーム） |
| RFC 9276 | NSEC3 のパラメータの指針 | 反復回数が 100 を超えるものは、計算するのではなく安全でないものとして扱います |

## アーキテクチャ

```
                                 ┌──────────────┐
                                 │  DNS Clients  │
                                 └──────┬───────┘
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
     ┌──────▼───────┐           ┌──────▼───────┐           ┌──────▼───────┐
     │  DNS Server   │           │   DoT Server  │           │  DoH Server   │
     │  (UDP + TCP)  │           │  (TLS :853)   │           │ (HTTPS :443)  │
     └──────┬───────┘           └──────┬───────┘           └──────┬───────┘
            │                           │                           │
            │    ┌──────────────────────┘          ┌───────────────┘
            │    │    ┌────────────────────────────┘
            │    │    │    ┌──────────────┐
            │    │    │    │  DoQ Server   │
            │    │    │    │ (QUIC :8853)  │
            │    │    │    └──────┬───────┘
            ▼    ▼    ▼          ▼
     ┌────────────────────────────────┐
     │        Resolution Engine       │
     │  (EDNS, Cache, Wildcards,      │
     │   DNAME, ANAME, DNS64)         │
     └──────────────┬─────────────────┘
                    │
       ┌────────────┼────────────┬───────────────┐
       │            │            │               │
 ┌─────▼────┐ ┌────▼────┐ ┌────▼──────────┐ ┌──▼───────┐
 │ Local DB  │ │ DNSBL   │ │   Upstream     │ │  DNSSEC  │
 │ (SQLite)  │ │ Checker │ │   Resolution   │ │ Signing  │
 └──────────┘ └─────────┘ └────┬──────────┘ └──────────┘
       │                        │
       │        ┌───────────────┼───────────┬────────────┐
       │        │               │           │            │
       │  ┌────▼─────┐  ┌──────▼─────┐ ┌──▼──────┐ ┌───▼──────┐
       │  │ Iterative │  │ DoH / DoT  │ │Forwarder│ │  Public  │
       │  │ from roots│  │  upstream  │ │ (Do53)  │ │  (Do53)  │
       │  └────┬─────┘  └────────────┘ └─────────┘ └──────────┘
       │       │  (tier 0)     (tier 1)   (tier 2)    (tier 3)
       │  ┌────▼──────────────┐   ┌────────────────────┐
       │  │ Delegation cache   │   │ DNSSEC validation  │
       │  │ + record cache     │◄──┤ (chain from root)  │
       │  └───────────────────┘   │  + key cache       │
       │                           └────────────────────┘
       │
 ┌─────▼──────┐   ┌────────────┐   ┌─────────────┐   ┌────────────┐
 │ gRPC Mgmt   │   │ HTTP Proxy │   │ DHCPv4 + AF │   │ ACME + CA  │
 │ (TCP/Unix)  │   │ (optional) │   │    probe    │   │  (portal)  │
 └─────────────┘   └────────────┘   └─────────────┘   └────────────┘
```

解決順序（ネットワークスコープが一つも設定されていないとき）：
1. EDNS の OPT レコードを解釈（ペイロードサイズ、DO ビット）
2. ローカルブロックリストを照会（逆引き DNS クエリについて）
3. DNS 応答キャッシュを確認
4. ローカルデータベースを確認（スプリットホライズン。常に優先されます）
5. ローカルデータベースの CNAME レコードを探す
6. DNAME レコードを探す（サブツリーの書き換え）
7. ANAME レコードを確認（ゾーン頂点での別名の解決）
8. 名前が管理下ゾーンの配下にあって見つからなければ、権威ある NXDOMAIN を返す
9. ワイルドカードレコードを確認
10. ローカルブロックリストと DNSBL プロバイダーを照会（載っていれば NXDOMAIN。あらゆる外部の応答より先に）
11. `security.recursion_cidrs` を強制 —— その外側の発信元は、何かが機体の外へ届く前に REFUSED になります
12. `resolution.mode` に従って外部で解決（有効なら QNAME の大小文字をランダム化し、設定されていればプロキシ経由で）、反復経路では DNSSEC を検証
13. DNS64 の AAAA 合成を適用（有効で該当する場合）
14. 応答をキャッシュ（Bogus な応答は決してキャッシュされません）
15. TTL ドリフトの調整を適用（設定されている場合）
16. ホストが経路を持たないアドレスファミリの A/AAAA 応答を落とす（`address_family.mode: auto` の場合）

ネットワークスコープが設定されている場合の拡張された解決順序については、[ネットワークスコープ](#ネットワークスコープ)を参照してください。

## ライセンス

このプロジェクトは GNU Affero General Public License v3.0（AGPL-3.0）でライセンスされています。ライセンス全文は [LICENSE](LICENSE) ファイルを参照してください。
