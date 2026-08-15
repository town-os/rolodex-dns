# Rolodex DNS

一套隱私優先的分割視域（split-horizon）DNS 伺服器與遞迴／轉送解析器，具備加密傳輸、DNSSEC 與 gRPC 管理，以 Rust 撰寫。

> 語言：[English](README.md) ｜ **繁體中文** ｜ [简体中文](README.zh-CN.md) ｜ [Español (España)](README.es-ES.md) ｜ [Español (México)](README.es-MX.md) ｜ [日本語](README.ja.md)

Rolodex DNS 提供 UDP、TCP、TLS（DoT）、HTTPS（DoH）與 QUIC（DoQ）上的 DNS 服務，並具備一個優先於外部解析的本地記錄資料庫。記錄透過 gRPC 遠端管理（TCP 上使用共用密鑰認證，或透過 Unix socket 免認證）。它支援帶網域疊加的 TLD 層級解析，因此內部的 DNS 表述一律優先。內建的 DNS 回應快取可在某筆記錄被見過之後，防止查詢外洩到上游解析器。

非本地的名稱預設會**從根伺服器開始迭代解析**，並依序退回加密（DoH/DoT）與明文上游，因此在會過濾對外 53 埠的網路上解析仍能存活。見[上游解析](#上游解析)。

從根伺服器解析出來的答案預設會對照 IANA 信任錨點進行 **DNSSEC 驗證**；偽造的資料永不提供也永不快取。見 [DNSSEC](#dnssec)。

Rolodex DNS 另外支援用於垃圾郵件／惡意程式過濾的網域封鎖清單（DNSBL）、DNSSEC 區域簽章、DANE TLSA 憑證關聯、內建的 ACME 憑證機構、DNS64 AAAA 合成、逐網路的 DNS 分隔，以及整合的 DHCPv4 伺服器。

第一次接觸？請從 **[設定指南](CONFIGURATION.zh-TW.md)** 開始——那是一份任務導向的逐步說明，從最小可用設定一路走到每個子系統，並為每種部署形態附上實作範例。

## 功能特色

- **隱私優先的 DNS 快取**：本地的 DNS 回應快取可防止查詢外洩到上游。一旦快取，查詢就在本地作答，不會接觸任何轉送器。設定 `forwarders: []` 即可成為純權威伺服器。
- **加密傳輸**：DNS-over-TLS（DoT，853 埠）、DNS-over-HTTPS（DoH，443 埠，支援 GET/POST）、DNS-over-QUIC（DoQ，8853 埠）
- **分割視域 DNS**：本地資料庫記錄一律優先於外部解析出來的結果
- **UDP 與 TCP 上的 DNS**：兩種傳輸層皆完整支援
- **具韌性後備的遞迴解析器**：預設從根伺服器迭代解析，接著是對公用解析器的 DoH/DoT，接著是已設定的轉送器，最後是明文的公用解析器——因此在會過濾 `:53`（以及以 DPI 阻擋 DoT `:853`）的網路上解析仍然可用。黏著的層級避免在死掉的路徑上付出逾時代價，而每一次層級切換都會清空快取
- **尊重 TTL 的解析器快取**：一份持久化的「區域 → 名稱伺服器」委派快取（跨重啟保持預熱）、一份供黏合記錄／無黏合記錄的 NS 查找／CNAME 跳轉使用的記憶體內快取，以及 RFC 2308 的否定快取——全都以其剩餘壽命提供
- **位址族感知**：背景探測會測試真實的 IPv4/IPv6 網際網路可達性，並針對主機無法路由的族抑制 A 或 AAAA 答案，讓用戶端改用另一族而不是卡在死掉的協議堆疊上
- **轉送解析器**：可設定的上游 DNS 轉送器，可透過 `resolution.mode: forward` 專門使用
- **TLD／網域疊加**：可在任意層級（包含 TLD）新增記錄以覆寫公開 DNS
- **DNSSEC 簽章**：Ed25519（首選）與 ECDSA P-256/P-384 的金鑰產生、區域簽章與 DS 記錄計算。RSA/SHA-256 可驗證但無法產生（`ring` 沒有 RSA 金鑰產生功能），而經過認證的否定證明（NSEC/NSEC3）不會被產生
- **DNSSEC 驗證**：迭代解析出來的答案會對照 IANA 根信任錨點驗證，預設開啟（`dnssec.validate`）。信任鏈是由上而下、與委派走訪並行建立的，因此取得一筆 DS 不需要額外查詢；未簽章的委派必須**證明**自己未簽章（已簽章的 NSEC/NSEC3），因此剝除簽章構不成降級。偽造的資料是 SERVFAIL 且永不快取，而 AD 只為真正 Secure 的答案設置
- **DANE TLSA + ACME 簽發者**：從憑證產生 TLSA 記錄、內建的 ACME 憑證機構（逐區域的中繼憑證機構）、自簽根憑證機構產生、ACME DNS-01 挑戰處理（原生提供 `_acme-challenge` TXT 記錄）
- **透過 DNS 散佈憑證機構**：根與逐區域中繼憑證鏈會以 `CERT` 記錄（RFC 4398）發佈，並附有分塊的 `TXT` 後備，因此任何解析得到該區域的用戶端都能取得並信任該憑證機構——不需要存取入口網站（見[散佈與信任憑證機構](#散佈與信任憑證機構)）
- **22 種記錄型別**：A、AAAA、CNAME、MX、TXT、NS、SOA、SRV、PTR、URI、SSHFP、DNAME、ANAME、ZONEMD、TLSA、CERT、DNSKEY、DS、RRSIG、NSEC、NSEC3、NSEC3PARAM。全部 22 種都可儲存與列出；NSEC、NSEC3 與 NSEC3PARAM 永遠不會被產生或提供（見 [DNSSEC](#dnssec)）
- **DNS 萬用字元**：符合 RFC 4592 的萬用字元比對（`*.example.com.` 比對單一標籤替換，精確比對優先）
- **權威 DNS**：對本地區域與明確宣告的權威區域強制設置 AA 位元
- **EDNS（RFC 6891）**：OPT 記錄支援、酬載大小協商、用於 DNSSEC 的 DO 位元、版本大於 0 時回 BADVERS
- **DNS64（RFC 6147）**：從 A 記錄合成 AAAA，前綴可設定（預設 `64:ff9b::/96`）
- **TTL 漂移**：固定模式（加減一段時長，支援 `"1h30m"` 這類複合格式）與實驗性的對數模式（以延遲為基礎）
- **QNAME 大小寫隨機化**：0x20 編碼會把轉送查詢中的 QNAME 大小寫隨機化，作為快取汙染的防禦
- **gRPC 管理**：透過 gRPC 進行遠端記錄管理，使用共用密鑰或 Unix socket 認證
- **封鎖清單支援**：具備記憶體內快取的 DNSBL 供應商檢查，另有供自訂封鎖項目使用的本地封鎖清單資料庫
- **DNSBL 支援**：網域封鎖清單（Spamhaus DBL、SURBL、URIBL）會在任何外部解析之前檢查，因此即使先前已快取了一個轉送答案，被列入的名稱仍會被拒絕
- **封鎖清單拒答處理**：DNSxL 回應「已列入」與「別再查我們」用的是同一種 `A` 記錄，因此拒答碼（`127.255.255.254`、`127.0.0.1` 等）會被辨識為**不是**列入，而該供應商會被移出查詢輪替一段冷卻時間——而不是把每一個對照它檢查的名稱都變成 NXDOMAIN
- **封鎖清單允許清單**：一個涵蓋所有清單與兩道關卡的逃生口——一個項目可讓某個名稱及其子網域豁免於 DNSBL／本地檢查，並讓某個位址（以反向名稱或 IP 字面值指定）豁免於反向查找檢查
- **遞迴存取控制**：`security.recursion_cidrs` 決定誰可以驅動**上游**解析，預設為從網際網路不可路由的範圍，因此預設的 `0.0.0.0:53` 綁定並不是一台開放遞迴解析器。陌生人仍然收得到這台伺服器的權威答案
- **網路範圍劃分**：具備逐範圍記錄與以 IP 為基礎之存取控制的分割視域 DNS。範圍強制僅限於已設定的疊加網路（WireGuard）CIDR；loopback、區域網路與容器來源受到信任且永不被拒絕
- **逐網路的專屬 TLD**：由某個範圍擁有的全域唯一 TLD，在疊加對等節點之間分隔且絕不轉送到上游，並可選擇性地為每個 TLD 設立**入口 DNS 監聽器**，在該網路自己的位址上作答，並把已編程的名稱改寫到它的入口控制器
- **整合的 DHCPv4 伺服器**：逐範圍的位址池、黏著的 MAC 綁定、自動的 A/PTR 註冊、透過站台專用選項交付憑證，以及背景租約清掃
- **自動反向 PTR 記錄**：可選（`dns.auto_ptr`）為透過 gRPC 新增的 A/AAAA 記錄維護對應的 `in-addr.arpa`／`ip6.arpa` PTR
- **代理支援**：透過 HTTP CONNECT、SOCKS5 或 DoH 代理轉送 DNS 查詢
- **Prometheus 指標**：一個選用、預設關閉的 `/metrics` 端點，輸出 77 個具備有界標籤基數的指標系列——包含逐階段的答案歸因與逐 TLD 隔離，讓分割視域管線從外面看得懂。查詢名稱永遠不會成為標籤
- **SQLite 持久化**：DNS 記錄跨重啟保存
- **TLS 熱重載（部分）**：`TlsManager` 可依需求從設定的 PEM 檔重建它的 `rustls::ServerConfig` 並發佈給訂閱者，若重建失敗則保留先前的憑證繼續提供。**尚未接到監聽器上**——DoT/DoH/DoQ/ACME 每一個都在啟動時取一次設定快照，因此更新後的憑證仍需重啟才會被提供
- **效能**：多執行緒 tokio 執行環境、無鎖的封鎖清單與解析器狀態（`AtomicBool` + `ArcSwap` + 原子操作）、範圍／區域／TLD／封鎖項目的開機記憶體內快取、供上游轉送使用的 UDP socket 池，以及全面採用的 DashMap/DashSet 並行快取

## 建置

```
make build
```

## 測試

```
make test
```

會執行 lint（`cargo fmt --check` + `clippy --all-targets -D warnings`）、Go 整合測試與單元測試、Rust 整合測試與單元測試、JavaScript 的 lint／整合／單元測試，以及文件中 PromQL 的執行檢查。Rust 整合層包含以真實 socket 進行的套件：DNSSEC 簽章與驗證（對照一套已簽章的模擬階層，其回應在序列化時才被竄改，因此每個測試都是「一個有效的部署，遭到攻擊」）、封鎖清單的 NXDOMAIN 契約、封鎖清單拒答碼、DoQ、代理、TLS 重載、ZONEMD、ACME 管理，以及逐項安全發現對應的 `security_*` 套件。使用 `make test-log` 可執行同一輪並 tee 進 `/tmp/rolodex-dns/log` 底下帶時間戳的紀錄檔（可用 `LOG_DIR` 覆寫），即使失敗也會在結尾印出路徑。個別層級：`make lint`、`make rust-test`、`make rust-integration-test`、`make go-test`、`make go-integration-test`、`make js-test`、`make js-integration-test`。

`make test` 也會執行 `make prometheus-test`，它會把本檔案中記載的每一條 PromQL 查詢，透過一個抓取實際伺服器的真正 Prometheus 容器執行一遍——藉此抓到一個**作為 PromQL 就格式錯誤**的查詢，而不只是指名了不存在的系列。它需要 podman；沒有 podman 時這項檢查會**大聲跳過**而不是失敗，因此沒有容器執行環境的機器仍能得到綠燈，同時絕不會假裝那些查詢已被驗證。設定 `ROLODEX_PROMETHEUS_REQUIRED=1` 可讓那個跳過變成硬性失敗，而 `ROLODEX_PROMETHEUS_IMAGE` 可指向該映像的鏡像站。

## 開發

啟動一台供測試與開發使用的本地開發伺服器：

```
make dev
```

它會：
1. 以 debug 模式建置專案（`cargo build`）
2. 使用 `dev.yml` 啟動伺服器，設定如下：
   - DNS 監聽器位於 `127.0.0.1:5300` 以及主要對外 IP 的 `5300` 埠（UDP 與 TCP）
   - gRPC Unix socket 位於 `/tmp/rolodex-dns.sock`（沒有 TCP gRPC 監聽器）
   - SQLite 資料庫位於 `/tmp/rolodex-dns-dev.db`
   - 不需要認證
   - 封鎖清單檢查停用
   - 預設的上游轉送器（`8.8.8.8:53`、`8.8.4.4:53`），作為預設 `auto` 解析鏈的 `local` 層級

`make help` 會依區段分組列出每個目標與說明（它也是預設目標，所以直接執行 `make` 就會印出它）。

若要以 release 最佳化的開發伺服器：
```
make dev-release
```

若要把執行檔安裝到你的 Cargo bin 目錄：
```
make install
```

開發伺服器啟動後，你可以用 `rolodex-dns-cli` 執行檔或連到 `/tmp/rolodex-dns.sock` 的 Go 用戶端函式庫來管理它。按 Ctrl+C 停止伺服器。

## 容器映像

Rolodex DNS 會用 `cargo-zigbuild` 在建置主機上交叉編譯它的執行檔，然後組出一個精簡的執行期映像（`debian:bookworm-slim`），其中只包含去除符號的執行檔與一份 CA 憑證包。`Containerfile` 刻意**不含任何 `RUN` 步驟**，這正是讓任何主機都能在不需模擬、不需建置虛擬機的情況下，為任何架構建置映像的原因。

映像以涵蓋 `linux/amd64` 與 `linux/arm64` 的多架構資訊清單列表發佈到 `quay.io/town/rolodex`。

### 多架構建置

建置是**原生的**：每個架構都在該架構的主機上編譯。每個映像都以 `uname -m` 的機器名稱加上架構後綴標記（`-x86_64` 或 `-aarch64`，**不是** OCI 的 `amd64`／`arm64` 名稱），因此部署主機可以直接拉取 `` <tag>-`uname -m` `` 而不需要任何對應轉換。另有一個獨立的資訊清單步驟，把各架構映像組成單一的多架構標籤。

#### 選擇架構：`TARGET`

`TARGET` 為每一個容器目標（`image`、`push-arch`、`push-rc`、`push-release`）選擇架構。它預設為主機架構，並且比照 town-os `install` 儲存庫所使用的 `TARGET=` 模型，因此同一個值可以傳給任一邊：

| `TARGET` | 建置出 |
| -------- | ------ |
| *(未設定)* | 主機架構 |
| `x86_64`、`x86`、`amd64` | amd64 映像，標記 `-x86_64` |
| `aarch64`、`arm64` | arm64 映像，標記 `-aarch64` |
| `rpi` | arm64 映像，標記 `-aarch64` |
| `rg35xxpro`、`rg35xx-pro`、`rg35xx`、`anbernic` | arm64 映像，標記 `-aarch64` |

其他任何值都是錯誤，並會列出可接受的值。開發板風味不會改變映像——rolodex-dns 每個架構只出一個容器映像，而不是每塊板子一個——它們之所以被接受，是為了讓一個在 `install` 中有特定意義的 `TARGET=rg35xxpro`，在這裡也能合理地解析。

**任何主機都能建置任何架構。** 外來的 `TARGET` 是交叉編譯而非模擬，因此沒有任何被拒絕的組合，也不需要建置虛擬機——見下面的「交叉編譯」。

`podman build` 的 RUN 步驟共用主機網路（`--network=host`），好讓它們能使用主機 loopback 上的 DNS 解析器（例如 rolodex 自己）；用 `BUILD_NETWORK=` 覆寫以退出此行為。

發佈多架構映像的端到端流程——每個架構一台主機：

1. 在 amd64 主機上：`make push-release` → 推送 `…:latest-x86_64`（以及日期標籤）。
2. 在 arm64 主機上：`make push-release` → 推送 `…:latest-aarch64`（以及日期標籤）。
3. 在任一主機上（兩者都推送完成後）：`make manifest-release` → 建立並推送多架構的 `…:latest` 資訊清單列表。

拉取 `quay.io/town/rolodex:latest` 的使用者接著就會透明地收到與其架構相符的映像。

#### 交叉編譯

兩種架構都在執行 `make` 的那台主機上交叉編譯，使用 `cargo-zigbuild` 並以 zig 作為 C 交叉編譯器與連結器。`make deps` 會在**不需要 root** 的情況下佈建整套工具鏈：

```bash
make deps        # rustup targets + cargo-zigbuild + zig，以及 JS 開發依賴
make cross-deps  # 只裝 Rust 交叉工具鏈
```

單純的 `rustup target add` 是不夠的：`rusqlite` 會編譯 SQLite 隨附的 C 原始碼，而 `ring` 會編譯 C 與組合語言，所以必須有一套真正的交叉 **C** 工具鏈，否則建置會在 `cc` 那一步失敗。zig 提供了一套，而且不需要任何發行版專屬的套件，並且鏈結到一個釘住的 glibc（`GLIBC_VERSION`，預設 `2.36` 以對應 `debian:bookworm`），因此無論建置主機帶的是哪個版本，產出的執行檔都能在執行期映像上跑。

版本釘選皆可覆寫：`ZIG_VERSION`、`ZIGBUILD_VERSION`、`GLIBC_VERSION`。

```bash
make image TARGET=x86_64         # 交叉編譯 + 組出 amd64 映像
make push-release TARGET=aarch64 # 交叉編譯 + 推送 arm64 映像
make push-release-all            # 從單一主機推送兩種架構 + 資訊清單
```

`make image-amd64`、`push-rc-amd64` 與 `push-release-amd64` 仍保留為 `TARGET=x86_64` 形式的別名。

### 建置映像

為**主機**架構建置 release 映像（標記為 `quay.io/town/rolodex:latest-<arch>`）：

```
make image
```

為特定架構建置：

```
make image TARGET=x86_64
make image TARGET=aarch64
```

以指定標籤建置：

```
make IMAGE_TAG=v1.2.3 image
```

Cargo 的登錄與 git 快取會保存在 `.cache/` 中以加速重建。

### 推送

登入 Quay.io（從環境變數或 `.env` 讀取 `QUAY_USERNAME` 與 `QUAY_PASSWORD`）：

```
make quay-login
```

為 `TARGET` 建置並推送候選發行映像（自動標記 `rc.YYYYMMDD-<arch>` 與 `rc.latest-<arch>`，例如 `rc.latest-x86_64`／`rc.latest-aarch64`）：

```
make push-rc
make push-rc TARGET=x86_64    # 明確指定架構
```

為 `TARGET` 建置並推送正式發行映像（自動標記 `release.YYYYMMDD-<arch>` 與 `latest-<arch>`）：

```
make push-release
make push-release TARGET=aarch64
```

#### 組出多架構資訊清單

在**所有**架構的各架構映像都推送完成後（在每台原生主機上執行 `push-rc`／`push-release`），可從任一主機組出並推送多架構資訊清單列表：

```
make manifest-rc       # 合併 rc.latest-x86_64 + rc.latest-aarch64 → rc.latest（以及 rc.YYYYMMDD 日期標籤）
make manifest-release  # 合併 latest-x86_64 + latest-aarch64 → latest（以及 release.YYYYMMDD 日期標籤）
```

資訊清單是從登錄中既有的映像組出來的（`podman manifest add docker://…`），因此不需要各架構映像存在於本地。

#### 推送指定標籤

使用 `IMAGE_TAG` 可建置並推送一個確切的標籤，取代自動產生的日期標籤。各架構映像仍會套上架構後綴：

```
make IMAGE_TAG=v1.2.3 push-release    # 推送 quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release # 合併 v1.2.3-x86_64 + v1.2.3-aarch64 → v1.2.3
```

同樣的做法適用於 `push-rc`／`manifest-rc`：

```
make IMAGE_TAG=v1.2.3-rc1 push-rc
make IMAGE_TAG=v1.2.3-rc1 manifest-rc
```

若要把已建置好的映像以不同標籤推送而不重新建置：

```
sudo podman tag quay.io/town/rolodex:latest quay.io/town/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:v1.2.3
```

若要推送到完全不同的登錄：

```
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push registry.example.com/myorg/rolodex:v1.2.3
```

### 清理

移除本地容器映像：

```
make clean-containers
```

## 設定

Rolodex DNS 從一個 YAML 檔讀取設定（預設 `rolodex-dns.yml`，可用 `-c`／`--config` 覆寫）。每個區段都是選用的——檔案不存在時，伺服器會以預設值啟動。

若想要一份逐個子系統把設定建立起來、並為每種部署形態附上實作範例的逐步說明，請見 **[設定指南](CONFIGURATION.zh-TW.md)**。下面的參考是完整的欄位清單。

### 綁定位址語法

綁定位址字串（用於 `dns.bind`、`dot.bind`、`doh.bind`、`doq.bind`、`grpc.tcp_bind`、`dhcp.bind`）接受四種寫法：

| 寫法 | 範例 | 說明 |
| ---- | ---- | ---- |
| `ip:port` | `192.168.1.1:53` | 綁定到指定的 IPv4 位址與連接埠 |
| `[ipv6]:port` | `[::1]:53` | 綁定到指定的 IPv6 位址與連接埠（方括號為必要） |
| `primary:port` | `primary:53` | 偵測作業系統預設路由的對外 IP 並綁定到它 |
| `interface:port` | `eth0:53` | 綁定到指定網路介面上的所有 IP |

`primary` 關鍵字會偵測作業系統會使用哪個 IP 位址來連上公開網際網路（透過一次不送出資料、朝向 `8.8.8.8:53` 的 UDP connect），並在該位址上綁定單一個監聽器。這個關鍵字不分大小寫。

介面綁定會解析出指派給該介面的所有 IPv4 與 IPv6 位址，並為每一個建立獨立的監聽器。舉例來說，若 `eth0` 有 `192.168.1.5` 與 `fe80::1`，那麼 `eth0:53` 會在 `192.168.1.5:53` 與 `[fe80::1]:53` 上各建立一個監聽器。

`dns.bind` 欄位是一串「協定／位址」配對。每一項都是一個單鍵映射，鍵為 `udp` 或 `tcp`，值為綁定位址：

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "lo:53"
    - tcp: "eth0:53"
```

### 設定範例

```yaml
# 資料庫檔案路徑
database_path: rolodex-dns.db

# 上游 DNS 轉送器（address:port 格式）。作為 auto 鏈的 "local" 層級使用，
# 或在 resolution.mode 為 "forward" 時作為唯一的上游。
# 設為空清單（並搭配 resolution.mode: forward）即為純權威伺服器
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

# 上游解析策略（所有欄位皆選用；此處顯示預設值）
resolution:
  mode: auto              # "auto"（層級鏈）、"recursive"（只走根伺服器）、"forward"
  root_hints: []          # 覆寫內建的 IANA 根伺服器位址
  secure_upstreams:       # 加密層級，在根遞迴失敗時嘗試
    - transport: https    # "https"（DoH :443，首選）或 "tls"（DoT :853）
      addr: "1.1.1.1:443" # 以 IP 撥接，因此不需要先有 DNS
      hostname: cloudflare-dns.com  # 驗證 SNI／憑證名稱
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  public_fallback:        # 明文 Do53，最後才嘗試
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  switch_grace_failures: 3      # 層級降級生效前需要幾次偏離的查詢
  recovery_probe_secs: 60       # 已降級的鏈多久從最上層重試一次
  delegation_persist_min_ttl: 300  # TTL 高於此值的委派才會持久化
  default_ttl: 300              # 僅在完全沒有任何 TTL 時作為後備

# 對從根伺服器解析出的答案做 DNSSEC 驗證（僅限迭代路徑）
dnssec:
  validate: true          # 偽造的資料會變成 SERVFAIL 且永不快取
  trust_anchors: []       # 空值 = IANA 根金鑰；覆寫是「取代」它們

# 每一項把一個協定（udp/tcp）與一個綁定位址配成一對。
# 綁定位址接受 ip:port、[ipv6]:port、primary:port 或 interface:port。
dns:
  bind:
    - udp: "0.0.0.0:53"     # 或 "eth0:53" 以綁定到特定介面
    - tcp: "0.0.0.0:53"
  auto_ptr: false           # 為透過 gRPC 新增的 A/AAAA 維護反向 PTR
  ingress_listen_port: 53   # 各 TLD 入口監聽器的連接埠（IP 是逐 TLD 指定的）

# DNS-over-TLS（RFC 7858）
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

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
  # TCP gRPC 監聽器（空字串代表停用）
  tcp_bind: "127.0.0.1:50051"
  # Unix socket 路徑（空字串代表停用）
  unix_socket: /var/run/rolodex-dns.sock
  # TCP gRPC 認證用的共用密鑰（Unix socket 不需要）
  shared_secret: your-secret-here

# 網域封鎖清單（依名稱檢查，在任何外部解析之前）
dnsbl:
  # 全域啟用／停用封鎖清單檢查（預設：false）
  enabled: false
  # 拒絕我們查詢的供應商被移出輪替的秒數
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
      # 代表「查詢被拒絕」而非「已列入」的碼。省略即使用內建集合；
      # 單一項目 "none" 會為此供應商停用拒答偵測。
      refusal_codes: []
      # 逐供應商覆寫移出輪替的時長（省略則沿用上層）
      refusal_cooldown_secs: 3600
    - zone: multi.surbl.org
      enabled: true

# 整合的 DHCPv4 伺服器（省略此區段即停用）
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # 必填：主機名稱會註冊為 <host>.lan.<tld>.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60

# ACME 簽發者／憑證機構（省略此區段即停用）
acme:
  bind: "0.0.0.0:8555"                    # 面向用戶端的 ACME HTTPS 監聽器
  portal_bind: "127.0.0.1:8500"           # 受信任網路的註冊入口網站
  directory_url: "https://dns.example.com:8555/acme"  # 對用戶端公告的位址
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  tlsa_port: 443
  tlsa_proto: tcp
  require_eab: true
  issuance_scope: managed_zones           # 或 "any"

# 轉送 DNS 查詢用的 HTTP 代理
proxy:
  url: "http://proxy:8080"
  auth: "user:pass"
  mode: "connect"  # "connect"（HTTP CONNECT 通道）、"socks5"（SOCKS5 代理）或 "doh"（以 DoH 代理查詢）

# TTL 漂移調整
ttl_drift:
  mode: "fixed"          # "fixed" 或 "logarithmic"（實驗性）
  fixed_adjustment: "5m" # 例如 "5m"、"-30s"、"1h30m"、"2d12h"（僅 fixed 模式）
  log_multiplier: 1.0    # 乘數（僅 logarithmic 模式，實驗性）

# DNS64 AAAA 合成
dns64:
  enabled: false
  prefix: "64:ff9b::"    # 預設的眾所周知前綴（64:ff9b::/96）

# 位址族答案偏好
address_family:
  mode: auto              # "auto"（探測並抑制）、"off"、"force4"、"force6"
  probe_interval_secs: 30
  fail_threshold: 2       # 一個位址族被標記為不可用前需要幾輪失敗
  probe_timeout_secs: 2
  targets_v4: ["1.1.1.1:443", "8.8.8.8:443"]
  targets_v6: ["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]

# 安全性設定
security:
  qname_case_randomization: true  # 對轉送查詢做 0x20 編碼
  overlay_cidrs: ["10.64.0.0/10"] # 會被套用網路範圍強制的來源範圍
  # 誰可以驅動「上游」解析。此清單之外的來源仍拿得到這台伺服器具權威的
  # 答案，但任何需要離開本機的請求都會得到 REFUSED。
  # 空清單 = 對所有人都純粹只做權威回答。
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

# Prometheus 抓取端點（省略此區段即不啟動監聽器）
metrics:
  bind: "127.0.0.1:9153"
  # 在逐 TLD 查詢指標上擁有自己 `tld` 標籤的 TLD。專屬 TLD 會自動被追蹤；
  # 所有未被追蹤的都折疊進 `other`。
  tracked_tlds:
    - common
```

### 設定選項

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `database_path` | `"rolodex-dns.db"` | SQLite 資料庫檔案的路徑 |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | 上游 DNS 解析器位址（`auto` 模式下的 `local` 層級；`forward` 模式下唯一的上游） |
| `resolution.mode` | `"auto"` | 上游策略：`"auto"`（層級鏈）、`"recursive"`（只走根伺服器）、`"forward"`（只走轉送器） |
| `resolution.root_hints` | `[]`（內建 IANA 根伺服器） | 覆寫 `recursive`／`auto` 模式所使用的根伺服器提示 |
| `resolution.secure_upstreams` | 以 DoH 連 Cloudflare + Google | `secure` 層級的加密上游：`{transport, addr, hostname, path}` |
| `resolution.public_fallback` | `["1.1.1.1:53", "8.8.8.8:53"]` | 明文的公用解析器，在 `auto` 模式下最後才嘗試 |
| `resolution.switch_grace_failures` | `3` | `auto` 層級降級生效前，連續偏離的查詢次數 |
| `resolution.recovery_probe_secs` | `60` | 已降級的 `auto` 鏈多久從最上層重試一次 |
| `resolution.delegation_persist_min_ttl` | `300` | 一個已學得的委派要被持久化到 SQLite 所需的最低 TTL |
| `resolution.default_ttl` | `300` | 記錄／回應完全沒有自帶 TTL 時的後備 TTL |
| `dnssec.validate` | `true` | 對迭代解析出的答案做 DNSSEC 驗證（`recursive` 模式與 `auto` 的根伺服器層級）。偽造與無法判定的資料會變成 SERVFAIL 且永不快取 |
| `dnssec.trust_anchors` | `[]`（IANA 根金鑰） | 以 DNSKEY 呈現格式表示的錨點，`"<flags> <protocol> <algorithm> <base64 key>"`——也就是 `dig DNSKEY .` 印出的那些 RDATA 欄位。每個欄位都在啟動時驗證，有問題就是硬性失敗。覆寫是**取代**IANA 金鑰而非追加 |
| `dns.bind` | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | DNS 監聽器；由 `{udp: addr}`／`{tcp: addr}` 項目組成的清單 |
| `dns.auto_ptr` | `false` | 為透過 gRPC 新增的 A/AAAA 維護反向 PTR 記錄 |
| `dns.ingress_listen_port` | `53` | 各 TLD 入口監聽器的 UDP/TCP 連接埠（綁定 IP 是逐 TLD 指定的） |
| `dns.udp_shards` | `0`（每核心一個） | 每個 UDP 監聽位址所綁定的 `SO_REUSEPORT` socket 數量。單一 socket 會把監聽器序列化——一個接收迴圈、所有回覆共用一個 socket——使吞吐量遠低於 CPU 飽和點。分片讓核心得以把資料包分散到各核心。設為 `1` 可恢復舊的單一 socket 行為 |
| `dot.bind` | `""`（停用） | DoT 監聽器；支援 interface:port（通常為 853 埠） |
| `dot.tls.cert_path` | `""` | DoT 的 TLS 憑證路徑 |
| `dot.tls.key_path` | `""` | DoT 的 TLS 私鑰路徑 |
| `dot.tls.auto_self_signed` | `true` | 為 DoT 自動產生自簽憑證 |
| `doh.bind` | `""`（停用） | DoH 監聽器；支援 interface:port（通常為 443 埠） |
| `doh.tls.cert_path` | `""` | DoH 的 TLS 憑證路徑 |
| `doh.tls.key_path` | `""` | DoH 的 TLS 私鑰路徑 |
| `doh.tls.auto_self_signed` | `true` | 為 DoH 自動產生自簽憑證 |
| `doh.enable_h3` | `false` | 為 DoH 啟用 HTTP/3（QUIC）傳輸 |
| `doq.bind` | `""`（停用） | DoQ 監聽器；支援 interface:port（通常為 8853 埠） |
| `doq.tls.cert_path` | `""` | DoQ 的 TLS 憑證路徑 |
| `doq.tls.key_path` | `""` | DoQ 的 TLS 私鑰路徑 |
| `doq.tls.auto_self_signed` | `true` | 為 DoQ 自動產生自簽憑證 |
| `grpc.tcp_bind` | `"127.0.0.1:50051"` | TCP gRPC 監聽器；支援 interface:port（空值代表停用） |
| `grpc.unix_socket` | `"/var/run/rolodex-dns.sock"` | Unix socket 路徑（空值代表停用） |
| `grpc.shared_secret` | `""` | TCP gRPC 認證用的共用密鑰（空值 = 不做認證） |
| `dnsbl.enabled` | `false` | 全域啟用網域封鎖清單（DNSBL）檢查 |
| `dnsbl.providers[].zone` | -- | 要查詢的 DNSBL 區域（被查詢的名稱會前置於它） |
| `dnsbl.providers[].enabled` | `true` | 啟用／停用個別 DNSBL 供應商 |
| `dnsbl.providers[].refusal_codes` | `[]`（內建集合） | 代表「查詢被拒絕」而非「已列入」的答案。每一項是一個 IPv4 位址或 `address/prefix`。空值代表內建集合；單一項目 `none` 會為該供應商停用偵測。明確列出的清單是取代預設值而非擴充，而無法剖析的碼會在啟動時被拒絕（見[拒答碼與供應商輪替](#拒答碼與供應商輪替)） |
| `dnsbl.providers[].refusal_cooldown_secs` | （沿用清單預設） | 拒答後逐供應商的移出輪替時長 |
| `dnsbl.refusal_cooldown_secs` | `3600` | 對於未自行設定的供應商，一個拒答中的供應商被移出輪替的秒數。`0` 代表「使用預設值」，而非「不冷卻」 |
| `dhcp.bind` | `"0.0.0.0:67"` | DHCP 監聽器（區段不存在 = DHCP 停用） |
| `dhcp.tld` | -- | 啟用 DHCP 時必填：主機名稱會註冊為 `<host>.lan.<tld>.` |
| `dhcp.default_lease_duration` | `3600` | 預設租約時長（秒） |
| `dhcp.reclaim_timeout` | `86400` | 過期後多久回收一個 IP（秒） |
| `dhcp.sweep_interval` | `60` | 背景租約清掃的間隔（秒） |
| `acme.bind` | `"0.0.0.0:8555"` | 面向用戶端的 ACME HTTPS 監聽器（區段不存在 = ACME 停用） |
| `acme.portal_bind` | `"127.0.0.1:8500"` | 受信任網路的註冊入口網站監聽器 |
| `acme.directory_url` | `"https://localhost:8555/acme"` | 對用戶端公告的外部 ACME 目錄 URL（請務必設定） |
| `acme.root_ca_cn` | `"Rolodex Root CA"` | 開機時建立的根憑證機構通用名稱 |
| `acme.leaf_validity_days` | `90` | 簽發出的終端憑證有效期 |
| `acme.tlsa_port` / `acme.tlsa_proto` | `443` / `"tcp"` | 每個名稱的 DANE-TA TLSA 記錄發佈位置 |
| `acme.require_eab` | `true` | 帳號註冊時要求 External Account Binding |
| `acme.issuance_scope` | `"managed_zones"` | `"managed_zones"`（區域必須有憑證機構）或 `"any"` |
| `proxy.url` | `""`（停用） | 轉送 DNS 查詢用的 HTTP 代理 URL |
| `proxy.auth` | `""` | 代理認證（`"user:pass"`） |
| `proxy.mode` | `"connect"` | 代理模式：`"connect"`（HTTP CONNECT）、`"socks5"`（SOCKS5）或 `"doh"` |
| `ttl_drift.mode` | `"disabled"` | TTL 漂移模式：`"disabled"`、`"fixed"` 或 `"logarithmic"` |
| `ttl_drift.fixed_adjustment` | `""` | 固定的 TTL 調整值。支援簡單（`"5m"`、`"-30s"`、`"1h"`、`"2d"`）與複合時長（`"1h30m"`、`"2d12h"`） |
| `ttl_drift.log_multiplier` | `0.1` | 對數模式的乘數（依上游延遲調整 TTL） |
| `dns64.enabled` | `false` | 啟用 DNS64 AAAA 合成 |
| `dns64.prefix` | `"64:ff9b::"` | DNS64 合成用的 IPv6 前綴 |
| `security.qname_case_randomization` | `true` | 啟用 0x20 QNAME 大小寫隨機化 |
| `security.overlay_cidrs` | `["10.64.0.0/10"]` | 被視為不受信任的疊加對等節點並套用範圍強制的來源範圍；其他所有來源皆受信任 |
| `security.recursion_cidrs` | loopback、RFC 1918、link-local、ULA、CGNAT | 允許驅動**上游**解析的來源範圍。其他來源會被提供本地／權威資料，而任何需要離開本機的請求都會得到 REFUSED；空清單即對所有人關閉遞迴（見[遞迴存取控制](#遞迴存取控制)） |
| `address_family.mode` | `"auto"` | `"auto"`（探測並抑制無法路由的族）、`"off"`、`"force4"`、`"force6"` |
| `address_family.probe_interval_secs` | `30` | `auto` 模式下兩次可路由性探測之間的秒數 |
| `address_family.fail_threshold` | `2` | 一個位址族被標記為不可用前，連續失敗的探測輪數（復原則是立即的） |
| `address_family.probe_timeout_secs` | `2` | 每次探測對每個目標的 TCP connect 逾時 |
| `address_family.targets_v4` / `targets_v6` | `:443` 上的 Cloudflare/Google | 各位址族的探測目標（IP 字面值） |
| `metrics.bind` | `127.0.0.1:9153` | Prometheus `/metrics` HTTP 監聽器；支援 interface:port。此區段為選用且預設省略，省略時不會啟動任何監聽器（見 [Prometheus 指標](#prometheus-指標)） |
| `metrics.tracked_tlds` | `[]` | 在逐 TLD 查詢指標上擁有自己 `tld` 標籤值的 TLD。專屬 TLD 會自動被追蹤；`common` 會展開成內建的常見 TLD 集合；所有未被追蹤的都折疊進 `other` |

## 使用方式

### 伺服器

```
rolodex-dns [OPTIONS]

Options:
  -c, --config <CONFIG>  設定檔路徑 [預設: rolodex-dns.yml]
  -h, --help             印出說明
```

### CLI 用戶端

`rolodex-dns-cli` 是一個命令列用戶端，透過 gRPC 管理介面管理執行中的 Rolodex DNS 伺服器。它同時支援 TCP 與 Unix socket 兩種傳輸方式。

```
rolodex-dns-cli [OPTIONS] <COMMAND>
```

#### 全域選項

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-a, --address <ADDRESS>` | `127.0.0.1:50051` | TCP 連線使用的 gRPC 伺服器位址（host:port）。設定 `--unix-socket` 時會被忽略。 |
| `-u, --unix-socket <PATH>` | -- | Unix domain socket 路徑。會覆蓋 `--address`。Unix socket 連線會跳過認證。 |
| `-t, --auth-token <TOKEN>` | `""` | TCP 連線的認證權杖。伺服器有設定共用密鑰時為必要。Unix socket 連線會忽略它。 |
| `-h, --help` | -- | 印出說明 |
| `-V, --version` | -- | 印出版本 |

#### 指令

| 指令 | 說明 |
|------|------|
| **記錄** | |
| `add-record` | 新增一筆 DNS 記錄到本地資料庫 |
| `remove-record` | 從本地資料庫移除 DNS 記錄 |
| `list-records` | 列出 DNS 記錄，可加篩選條件 |
| **轉送器** | |
| `set-forwarders` | 在執行期設定上游 DNS 轉送器 |
| **封鎖清單** | |
| `set-dnsbl-config` | 在執行期設定網域封鎖清單（DNSBL） |
| `get-dnsbl-config` | 取得目前的 DNSBL 設定 |
| `flush-cache` | 清空封鎖清單的結果快取 |
| `add-local-blocklist` | 新增一筆本地封鎖項目 |
| `remove-local-blocklist` | 移除一筆本地封鎖項目 |
| `list-local-blocklist` | 列出所有本地封鎖項目 |
| `add-dnsbl-allow` | 讓某個名稱（及其子網域）豁免於封鎖清單檢查 |
| `remove-dnsbl-allow` | 移除一筆 DNSBL 允許清單項目 |
| `list-dnsbl-allow` | 列出所有 DNSBL 允許清單項目 |
| **網路範圍劃分** | |
| `create-scope` | 建立一個新的網路範圍 |
| `delete-scope` | 刪除一個網路範圍及其所有資料 |
| `list-scopes` | 列出所有已設定的網路範圍 |
| `join-network` | 把一個 IP 關聯到某個範圍 |
| `leave-network` | 移除某個 IP 的範圍關聯 |
| `list-associations` | 列出 IP 對範圍的關聯 |
| `add-scoped-record` | 在某個範圍內新增一筆 DNS 記錄 |
| `remove-scoped-record` | 從某個範圍移除 DNS 記錄 |
| `list-scoped-records` | 列出某個範圍內的 DNS 記錄 |
| `get-search-domains` | 取得某個 IP 的搜尋網域 |
| **專屬 TLD／入口** | |
| `add-scope-tld` | 為某個範圍註冊一個全域唯一的專屬 TLD（可選的 `--listen-ip` 會啟動入口監聽器） |
| `remove-scope-tld` | 從某個範圍移除一個專屬 TLD |
| `list-scope-tlds` | 列出某個範圍所擁有的 TLD |
| `set-scope-tld-forwarders` | 設定某個範圍之 TLD 的對等轉送器 |
| `list-scope-tld-forwarders` | 列出某個範圍之 TLD 的對等轉送器 |
| `list-scope-tld-listeners` | 列出綁定到某個範圍各 TLD 的入口 DNS 監聽器 |
| **權威區域** | |
| `add-auth-zone` | 宣告某個區域為權威 |
| `remove-auth-zone` | 從權威清單中移除某個區域 |
| `list-auth-zones` | 列出所有權威區域 |
| **快取** | |
| `cache-stats` | 顯示 DNS 快取的命中／未命中統計 |
| `flush-dns-cache` | 清空 DNS 回應快取 |
| **DHCP** | |
| `add-dhcp-pool` / `remove-dhcp-pool` / `list-dhcp-pools` | 管理各範圍的 DHCP 位址池 |
| `list-dhcp-leases` / `delete-dhcp-lease` | 檢視與刪除 DHCP 租約 |
| `set-dhcp-cert` / `remove-dhcp-cert` / `list-dhcp-certs` | 管理透過 DHCP 選項交付的憑證 |
| **DNSSEC** | |
| `generate-dnssec-key` | 產生一組 DNSSEC 金鑰對（KSK 或 ZSK） |
| `list-dnssec-keys` | 列出某個區域的 DNSSEC 金鑰 |
| `sign-zone` | 用區域的 DNSSEC 金鑰為它簽章 |
| **DANE / ACME** | |
| `generate-tlsa` | 從憑證產生一筆 TLSA 記錄 |
| `request-acme-cert` | 透過 ACME DNS-01 請求憑證 |
| `acme-status` | 檢查 ACME 憑證狀態 |
| `ensure-zone-ca` | 確保逐區域的中繼憑證機構存在；印出根 + 中繼 PEM 並把憑證鏈發佈進 DNS |
| `create-eab` / `remove-eab` | 鑄造或移除一份限定於某區域的 EAB 憑據 |
| `list-acme-accounts` | 列出已註冊的 ACME 帳號 |
| `list-acme-certs` | 列出已簽發的憑證 |
| **TTL 漂移** | |
| `set-ttl-drift` / `get-ttl-drift` | 設定／取得 TTL 漂移設定 |
| **DNS64** | |
| `set-dns64` / `get-dns64` | 設定／取得 DNS64 設定 |
| **可觀測性** | |
| `latency-stats` | 顯示逐伺服器的上游查詢延遲 |

傳輸（DoT/DoH/DoQ）、代理，以及少數 DNSSEC/DANE 操作可透過 gRPC 使用，但沒有對應的 CLI 子指令——見[其他 gRPC 方法](#其他-grpc-方法)。完整的指令旗標請執行 `rolodex-dns-cli <COMMAND> --help`。

##### `add-record`

新增一筆 DNS 記錄到本地資料庫。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/AddRecord`

```
rolodex-dns-cli add-record -n <NAME> -v <VALUE> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 完整網域名稱（例如 `"example.com."`——建議帶結尾的點） |
| `-r, --record-type <TYPE>` | `a` | DNS 記錄型別（見記錄型別表） |
| `-v, --value <VALUE>` | -- | 記錄資料。格式視記錄型別而定（見「記錄型別」一節） |
| `--ttl <TTL>` | `300` | 存活時間（秒）。設為 0 時伺服器會預設為 300 |
| `-p, --priority <PRIORITY>` | `0` | MX 與 SRV 記錄的優先權。數值越小優先權越高。其他型別會忽略 |

範例：
```bash
# 透過 TCP 新增一筆 A 記錄
rolodex-dns-cli -a 127.0.0.1:50051 -t my-secret add-record \
  -n example.com. -r a -v 10.0.0.1 --ttl 600

# 透過 Unix socket 新增一筆 MX 記錄
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  -n example.com. -r mx -v mail.example.com. -p 10

# 新增一筆 CNAME 記錄
rolodex-dns-cli add-record -n www.example.com. -r cname -v example.com.

# 新增一筆 SRV 記錄
rolodex-dns-cli add-record -n _sip._tcp.example.com. -r srv \
  -v "5 5060 sip.example.com." -p 10

# 新增一筆 URI 記錄
rolodex-dns-cli add-record -n example.com. -r uri \
  -v "10 1 \"https://example.com/\"" -p 10

# 新增一筆 SSHFP 記錄
rolodex-dns-cli add-record -n host.example.com. -r sshfp \
  -v "2 1 123456789abcdef..."

# 新增一筆萬用字元記錄
rolodex-dns-cli add-record -n "*.example.com." -r a -v 10.0.0.99
```

##### `remove-record`

從本地資料庫移除 DNS 記錄。依名稱移除，並可加上型別與值的篩選條件。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/RemoveRecord`

```
rolodex-dns-cli remove-record -n <NAME> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 要移除之記錄的完整網域名稱 |
| `-r, --record-type <TYPE>` | -- | 指定時只移除此型別的記錄。省略時移除該名稱的所有型別 |
| `-v, --value <VALUE>` | -- | 指定時只移除值與之完全相同的那筆記錄 |

範例：
```bash
# 移除某個名稱的所有記錄
rolodex-dns-cli remove-record -n old.example.com.

# 只移除某個名稱的 A 記錄
rolodex-dns-cli remove-record -n example.com. -r a

# 依值移除指定的一筆記錄
rolodex-dns-cli remove-record -n example.com. -r a -v 10.0.0.1
```

##### `list-records`

從本地資料庫列出 DNS 記錄，可加篩選條件。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/ListRecords`

```
rolodex-dns-cli list-records [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 依網域名稱篩選。支援 `"*."` 萬用字元前綴以比對所有子網域（例如 `"*.example.com."`） |
| `-r, --record-type <TYPE>` | -- | 依記錄型別篩選。省略時回傳所有記錄型別 |

範例：
```bash
# 列出所有記錄
rolodex-dns-cli list-records

# 列出指定名稱的記錄
rolodex-dns-cli list-records -n example.com.

# 列出所有子網域
rolodex-dns-cli list-records -n "*.example.com."

# 只列出 AAAA 記錄
rolodex-dns-cli list-records -r aaaa
```

##### `set-forwarders`

在執行期設定上游 DNS 轉送器。會取代整份轉送器清單。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/SetForwarders`

```
rolodex-dns-cli set-forwarders -f <ADDR>...
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-f, --forwarders <ADDR>...` | -- | 上游 DNS 伺服器位址，格式為 `"host:port"`。多個位址以空白分隔 |

範例：
```bash
# 設定 Google 與 Cloudflare DNS
rolodex-dns-cli set-forwarders -f 8.8.8.8:53 1.1.1.1:53

# 設定單一轉送器
rolodex-dns-cli set-forwarders -f 9.9.9.9:53

# 移除所有轉送器（純權威模式）
rolodex-dns-cli set-forwarders -f ""
```

##### `flush-cache`

清空封鎖清單結果快取。強制後續查詢重新查找。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/FlushCache`

```
rolodex-dns-cli flush-cache
```

##### `create-scope`

建立一個帶有保留 `.home` 網域的新網路範圍。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

```
rolodex-dns-cli create-scope -n <NAME> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 網路範圍的唯一名稱（例如 `"office"`、`"lab"`） |
| `-d, --home-domain <DOMAIN>` | `"<name>.home."` | 此範圍保留的 `.home` 網域。省略時預設為 `"<name>.home."` |

範例：
```bash
# 以預設 home 網域建立範圍
rolodex-dns-cli create-scope -n office
# 建立名為 "office" 的範圍，home 網域為 "office.home."

# 以自訂 home 網域建立範圍
rolodex-dns-cli create-scope -n lab -d lab.internal.
```

##### `delete-scope`

刪除一個網路範圍及其所有記錄與關聯。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

```
rolodex-dns-cli delete-scope -n <NAME>
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 要刪除的範圍名稱 |

##### `list-scopes`

列出所有已設定的網路範圍。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

```
rolodex-dns-cli list-scopes
```

##### `join-network`

把一個 IP 位址關聯到某個網路範圍。這個關聯帶有 TTL，必須定期更新。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/JoinNetwork`

```
rolodex-dns-cli join-network -i <IP> -s <SCOPE> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-i, --ip <IP>` | -- | 要關聯的用戶端 IP 位址（例如 `"192.168.1.100"`） |
| `-s, --scope <SCOPE>` | -- | 要加入的網路範圍名稱 |
| `--ttl <TTL>` | `300` | 關聯的 TTL（秒）。必須在到期前更新。為 0 時預設為 300 |

範例：
```bash
# 以預設 TTL 加入
rolodex-dns-cli join-network -i 192.168.1.100 -s office

# 以自訂 TTL 加入
rolodex-dns-cli join-network -i 10.0.0.5 -s lab --ttl 600
```

##### `leave-network`

移除某個 IP 位址與其網路範圍的關聯。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

```
rolodex-dns-cli leave-network -i <IP>
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-i, --ip <IP>` | -- | 要解除關聯的用戶端 IP 位址 |

##### `list-associations`

列出 IP 對範圍的關聯，可依範圍篩選。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

```
rolodex-dns-cli list-associations [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 依範圍名稱篩選。省略時列出所有關聯 |

##### `add-scoped-record`

在指定的網路範圍內新增一筆 DNS 記錄。範圍內記錄只對關聯到該範圍的 IP 可見。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

```
rolodex-dns-cli add-scoped-record -s <SCOPE> -n <NAME> -v <VALUE> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 要新增記錄的網路範圍 |
| `-n, --name <NAME>` | -- | 完整網域名稱 |
| `-r, --record-type <TYPE>` | `a` | DNS 記錄型別 |
| `-v, --value <VALUE>` | -- | 記錄資料 |
| `--ttl <TTL>` | `300` | 存活時間（秒） |
| `-p, --priority <PRIORITY>` | `0` | MX 與 SRV 記錄的優先權 |

範例：
```bash
# 新增一筆範圍內的 A 記錄
rolodex-dns-cli add-scoped-record -s office -n printer.office.home. -v 192.168.1.50

# 新增一筆範圍內的 CNAME
rolodex-dns-cli add-scoped-record -s lab -n app.lab.home. -r cname -v server.lab.home.
```

##### `remove-scoped-record`

從指定的網路範圍移除 DNS 記錄。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

```
rolodex-dns-cli remove-scoped-record -s <SCOPE> -n <NAME> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 要移除記錄的網路範圍 |
| `-n, --name <NAME>` | -- | 完整網域名稱 |
| `-r, --record-type <TYPE>` | -- | 依記錄型別篩選 |
| `-v, --value <VALUE>` | -- | 依完全相同的值篩選 |

##### `list-scoped-records`

列出某個網路範圍內的 DNS 記錄。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

```
rolodex-dns-cli list-scoped-records -s <SCOPE> [OPTIONS]
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 要查詢的網路範圍 |
| `-n, --name <NAME>` | -- | 依網域名稱篩選（支援 `"*."` 萬用字元前綴） |
| `-r, --record-type <TYPE>` | -- | 依記錄型別篩選 |

##### `get-search-domains`

取得某個用戶端 IP 位址的搜尋網域。
**gRPC 路徑：** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

```
rolodex-dns-cli get-search-domains -i <IP>
```

| 選項 | 預設值 | 說明 |
|------|--------|------|
| `-i, --ip <IP>` | -- | 要查詢的用戶端 IP 位址 |

## gRPC API

管理 API 定義在 `proto/rolodex_dns.proto` 中。所有方法都接受一個 `auth_token` 欄位，供透過 TCP 連線時的共用密鑰認證使用。Unix socket 連線會跳過認證。

完整的 API 參考請見 proto 檔。這個服務定義了 77 個 RPC 方法，涵蓋記錄管理、網路範圍劃分、專屬 TLD 與入口、封鎖清單、DHCP、加密傳輸、DNSSEC、DANE/ACME、快取、DNS64、指標與可觀測性。

### 服務：`rolodex_dns.RolodexDnsService`

#### `AddRecord`

**路徑：** `/rolodex_dns.RolodexDnsService/AddRecord`

新增一筆 DNS 記錄到本地資料庫。

**參數：**
- `record`（DnsRecord，必填）：要新增的 DNS 記錄
  - `name`（string）：完整網域名稱（例如 `"example.com."`）
  - `record_type`（RecordType）：DNS 記錄型別（見下方「記錄型別」）
  - `value`（string）：記錄資料（例如 IP 位址、主機名稱）
  - `ttl`（uint32）：存活時間（秒）。設為 0 時預設為 300
  - `priority`（uint32）：MX/SRV 記錄的優先權（其他型別會忽略）。預設：0
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `RemoveRecord`

**路徑：** `/rolodex_dns.RolodexDnsService/RemoveRecord`

從本地資料庫移除 DNS 記錄。

**參數：**
- `name`（string，必填）：完整網域名稱
- `record_type`（RecordType）：有設定時只移除此型別的記錄。未設定（A/0）時移除該名稱的所有記錄
- `value`（string）：非空時只移除值與之完全相同的那筆記錄
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `removed_count`（uint32）：被移除的記錄筆數
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `ListRecords`

**路徑：** `/rolodex_dns.RolodexDnsService/ListRecords`

以選用的篩選條件查詢本地 DNS 資料庫。

**參數：**
- `name_filter`（string）：依網域名稱篩選。支援 `"*."` 萬用字元前綴以比對所有子網域（例如 `"*.example.com."`）
- `record_type_filter`（RecordType）：依記錄型別篩選（僅在 `filter_by_type` 為 true 時套用）
- `filter_by_type`（bool）：是否套用 `record_type_filter`。預設：false
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `records`（repeated DnsRecord）：符合條件的 DNS 記錄

#### `SetForwarders`

**路徑：** `/rolodex_dns.RolodexDnsService/SetForwarders`

在執行期設定上游 DNS 轉送器。

**參數：**
- `forwarders`（repeated string）：上游 DNS 伺服器位址清單，格式為 `"host:port"`（例如 `"8.8.8.8:53"`）
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `FlushCache`

**路徑：** `/rolodex_dns.RolodexDnsService/FlushCache`

清空封鎖清單查找快取。

**參數：**
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `CreateNetworkScope`

**路徑：** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

建立一個帶有保留 `.home` 網域的新網路範圍。

**參數：**
- `scope`（NetworkScope，必填）：要建立的範圍
  - `name`（string）：範圍的唯一名稱（例如 `"office"`、`"lab"`）
  - `home_domain`（string）：保留的 `.home` 網域。為空時預設為 `"<name>.home."`
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `DeleteNetworkScope`

**路徑：** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

刪除一個網路範圍及其所有記錄與關聯。

**參數：**
- `name`（string，必填）：要刪除的範圍名稱
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `ListNetworkScopes`

**路徑：** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

取得所有已設定的網路範圍。

**參數：**
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `scopes`（repeated NetworkScope）：所有已設定的範圍

#### `JoinNetwork`

**路徑：** `/rolodex_dns.RolodexDnsService/JoinNetwork`

把一個用戶端 IP 位址關聯到某個網路範圍。這個關聯帶有 TTL，必須定期更新才能維持 DNS 解析。

**參數：**
- `ip_address`（string，必填）：要關聯的用戶端 IP（例如 `"192.168.1.100"`）
- `scope_name`（string，必填）：要加入的網路範圍名稱
- `ttl_seconds`（uint64）：TTL（秒）。設為 0 時預設為 300。必須在到期前更新。
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `LeaveNetwork`

**路徑：** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

移除某個 IP 位址與其網路範圍的關聯。

**參數：**
- `ip_address`（string，必填）：要解除關聯的用戶端 IP
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `GetNetworkAssociations`

**路徑：** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

取得 IP 對範圍的關聯。

**參數：**
- `scope_name`（string）：依範圍名稱篩選。為空時回傳所有關聯。
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `associations`（repeated NetworkAssociation）：符合條件的關聯
  - `ip_address`（string）：被關聯的 IP
  - `scope_name`（string）：範圍名稱
  - `ttl_seconds`（uint64）：該關聯的 TTL

#### `AddScopedRecord`

**路徑：** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

在指定的網路範圍內新增一筆 DNS 記錄。範圍內記錄只對關聯到該範圍的 IP 可見。

**參數：**
- `scope_name`（string，必填）：要新增記錄的範圍
- `record`（DnsRecord，必填）：要新增的 DNS 記錄
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `RemoveScopedRecord`

**路徑：** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

從指定的網路範圍移除 DNS 記錄。

**參數：**
- `scope_name`（string，必填）：要移除記錄的範圍
- `name`（string，必填）：要移除記錄的完整網域名稱
- `record_type`（RecordType）：選用的型別篩選
- `value`（string）：選用的完全相同值篩選
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `success`（bool）：操作是否成功
- `removed_count`（uint32）：被移除的記錄筆數
- `message`（string）：`success` 為 false 時的錯誤訊息

#### `ListScopedRecords`

**路徑：** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

查詢某個網路範圍內的 DNS 記錄。

**參數：**
- `scope_name`（string，必填）：要查詢的範圍
- `name_filter`（string）：依網域名稱篩選（支援 `"*."` 萬用字元前綴）
- `record_type_filter`（RecordType）：依記錄型別篩選（僅在 `filter_by_type` 為 true 時套用）
- `filter_by_type`（bool）：是否套用 `record_type_filter`。預設：false
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `records`（repeated DnsRecord）：符合條件的範圍內記錄

#### `GetSearchDomains`

**路徑：** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

取得某個用戶端 IP 位址的搜尋網域。回傳該 IP 所關聯範圍的 `.home` 網域。

**參數：**
- `ip_address`（string，必填）：要查詢的用戶端 IP
- `auth_token`（string）：認證用的共用密鑰

**回應：**
- `search_domains`（repeated string）：該 IP 的搜尋網域（通常是範圍的 `.home` 網域）

#### 其他 gRPC 方法

以下方法同樣可用。完整的請求／回應定義請見 `proto/rolodex_dns.proto`。

| 方法 | 說明 |
|------|------|
| `AddAuthoritativeZone` | 宣告某個區域為權威（設 AA 位元、不轉送到上游） |
| `RemoveAuthoritativeZone` | 從權威清單中移除某個區域 |
| `ListAuthoritativeZones` | 列出所有權威區域 |
| `GetCacheStats` | 取得 DNS 快取統計（項目數、命中、未命中） |
| `FlushDnsCache` | 清空 DNS 回應快取 |
| `SetTtlDriftConfig` | 設定 TTL 漂移調整（固定或對數模式） |
| `GetTtlDriftConfig` | 取得 TTL 漂移設定 |
| `GetQueryLatencyStats` | 取得逐伺服器的上游查詢延遲統計 |
| `AddLocalBlocklistEntry` | 新增一筆本地封鎖項目 |
| `RemoveLocalBlocklistEntry` | 移除一筆本地封鎖項目 |
| `ListLocalBlocklistEntries` | 列出所有本地封鎖項目 |
| `SetDnsblConfig` / `GetDnsblConfig` | 設定／取得網域封鎖清單（DNSBL）設定 |
| `AddDnsblAllowlistEntry` | 讓某個名稱（及其子網域）豁免於封鎖清單檢查 |
| `RemoveDnsblAllowlistEntry` | 移除一筆 DNSBL 允許清單項目 |
| `ListDnsblAllowlistEntries` | 列出所有 DNSBL 允許清單項目 |
| `AddScopeTld` | 為某個範圍註冊一個全域唯一的專屬 TLD；可選的 `listen_ip` 會同時啟動一個入口 DNS 監聽器 |
| `RemoveScopeTld` | 移除一個專屬 TLD（以及在無人使用後移除其入口監聽器） |
| `ListScopeTlds` | 列出某個範圍所擁有的 TLD |
| `SetScopeTldForwarders` / `ListScopeTldForwarders` | 管理某個 TLD 的對等轉送器 |
| `ListScopeTldListeners` | 列出綁定到某個範圍各 TLD 的入口 DNS 監聽器 |
| `AddDhcpPool` / `RemoveDhcpPool` / `ListDhcpPools` | 管理各範圍的 DHCP 位址池 |
| `ListDhcpLeases` / `DeleteDhcpLease` | 檢視與刪除 DHCP 租約 |
| `SetDhcpCertOption` / `RemoveDhcpCertOption` / `ListDhcpCertOptions` | 管理透過 DHCP 選項交付的憑證 |
| `EnsureZoneCa` | 若不存在則建立逐區域的中繼憑證機構；回傳根 + 中繼 PEM |
| `CreateEabCredential` / `RemoveEabCredential` | 鑄造或移除一份限定於某區域的 EAB 憑據 |
| `ListAcmeAccounts` / `ListAcmeCertificates` | 列出 ACME 帳號與已簽發的憑證 |
| `SetDotConfig` / `GetDotConfig` | 設定／取得 DNS-over-TLS 設定 |
| `SetDohConfig` / `GetDohConfig` | 設定／取得 DNS-over-HTTPS 設定 |
| `SetDoqConfig` / `GetDoqConfig` | 設定／取得 DNS-over-QUIC 設定 |
| `SetProxyConfig` / `GetProxyConfig` | 設定／取得 HTTP 代理設定 |
| `GenerateDnssecKey` | 為某個區域產生一組 DNSSEC 金鑰對 |
| `ListDnssecKeys` | 列出某個區域的 DNSSEC 金鑰 |
| `DeleteDnssecKey` | 刪除一把 DNSSEC 金鑰 |
| `GetDsRecords` | 取得供父區域委派使用的 DS 記錄 |
| `SignZone` | 用區域的 DNSSEC 金鑰為它簽章（或重新簽章） |
| `GenerateTlsaRecord` | 從一張 PEM 憑證產生一筆 TLSA 記錄 |
| `ListTlsaRecords` | 列出某個網域的 TLSA 記錄 |
| `GenerateDaneRootCa` | 產生一張自簽的 DANE 根憑證機構憑證 |
| `RequestAcmeCert` | 透過 ACME DNS-01 挑戰請求憑證 |
| `GetAcmeStatus` | 取得某個網域的 ACME 憑證狀態 |
| `SetDns64Config` / `GetDns64Config` | 設定／取得 DNS64 合成設定 |

### 記錄型別

| 列舉值 | 名稱 | 說明 |
|--------|------|------|
| 0 | `A` | IPv4 位址對應。值：IPv4 位址（例如 `"192.168.1.1"`） |
| 1 | `AAAA` | IPv6 位址對應。值：IPv6 位址（例如 `"::1"`） |
| 2 | `CNAME` | 正式名稱別名。值：目標完整網域名稱（例如 `"target.example.com."`） |
| 3 | `MX` | 郵件交換。值：郵件伺服器完整網域名稱。使用 `priority` 欄位 |
| 4 | `TXT` | 文字記錄。值：文字內容 |
| 5 | `NS` | 名稱伺服器。值：名稱伺服器的完整網域名稱 |
| 6 | `SOA` | 授權起始。值：`"mname rname serial refresh retry expire minimum"`（以空白分隔） |
| 7 | `SRV` | 服務定位。值：`"weight port target"`（以空白分隔）。使用 `priority` 欄位 |
| 8 | `PTR` | 反向 DNS 指標。值：目標完整網域名稱 |
| 9 | `URI` | URI 資源記錄（RFC 7553）。值：`"priority weight \"uri\""` |
| 10 | `SSHFP` | SSH 指紋（RFC 4255）。值：`"algorithm fp_type fingerprint"` |
| 11 | `DNAME` | 委派名稱（RFC 6672）。值：目標完整網域名稱（改寫整棵子樹） |
| 12 | `ANAME` | 別名（草案）。值：目標完整網域名稱（查詢時才解析，可用於區域頂點） |
| 13 | `ZONEMD` | 區域訊息摘要（RFC 9156）。值：`"serial scheme hash_algorithm digest"` |
| 14 | `TLSA` | TLS 憑證關聯（RFC 6698）。值：`"usage selector matching_type cert_data"` |
| 15 | `DNSKEY` | DNSSEC 公鑰。由 DNSSEC 金鑰產生流程自動管理 |
| 16 | `DS` | 委派簽署者。由 DNSSEC 自動管理 |
| 17 | `RRSIG` | DNSSEC 資源記錄簽章。由區域簽章自動管理 |
| 18 | `NSEC` | 下一個安全記錄（DNSSEC）。由區域簽章自動管理 |
| 19 | `NSEC3` | 下一個安全記錄 v3（DNSSEC）。由區域簽章自動管理 |
| 20 | `NSEC3PARAM` | NSEC3 參數（DNSSEC）。由區域簽章自動管理 |
| 21 | `CERT` | 在 DNS 中儲存憑證（RFC 4398）。值：`"cert_type key_tag algorithm base64_cert_data"`。用於散佈憑證鏈 |

## 隱私優先的快取

Rolodex DNS 會在本地快取 DNS 回應，因此對同一個名稱的重複查詢無需接觸任何上游轉送器即可作答。這可防止 DNS 查詢外洩——一旦某筆記錄被快取，外部觀察者就再也看不到這個查詢又被發出過。

快取區分兩種項目：

- **本地記錄**（來自 SQLite 資料庫）：以穩定的 TTL 快取在記憶體中（不衰減）。這些項目不會被持久化到快取的後端儲存，因為它們本來就存在資料庫裡。只要記錄透過 gRPC 被新增、移除或修改，記憶體內的 DNS 快取就會自動失效，因此變更會立即生效。
- **轉送回來的回應**（來自上游解析器）：以會衰減的 TTL 快取，並持久化到一張以 SQLite 為後端的快取表。重啟時已持久化的項目會被重新載入，因此快取立刻就是預熱的。

否定答案（權威的 NXDOMAIN/NODATA）另外分開快取，時長為區域所發佈的 RFC 2308 否定 TTL（`min(SOA MINIMUM, SOA TTL)`）。為某個名稱新增本地記錄會丟掉它先前被快取的否定結果，因此新加入的名稱會立即解析，而不必等否定 TTL 走完。

快取統計可透過 `GetCacheStats` 取得，快取可透過 `FlushDnsCache` 清空。

若要達到最高的隱私程度，請設定 `resolution.mode: forward` 搭配 `forwarders: []`，讓 Rolodex DNS 以純權威伺服器的形式執行，完全不做任何外部解析。所有答案都會來自本地資料庫。

## 上游解析

無法在本地滿足的名稱會依 `resolution.mode` 解析：

| 模式 | 行為 |
| ---- | ---- |
| `auto`（預設） | 下面的分層後備鏈 |
| `recursive` | 只從根伺服器迭代解析；絕不接觸任何上游解析器 |
| `forward` | 只轉送到已設定的 `forwarders` |

### `auto` 後備鏈

各層級依「最受偏好（最受信任）優先」的順序嘗試：

| 層級 | 路徑 | 理由 |
| ---- | ---- | ---- |
| 0 | 從根伺服器迭代解析 | 沒有第三方看得到你的查詢 |
| 1 | 對 `resolution.secure_upstreams` 使用 DoH（`:443`）或 DoT（`:853`） | 已加密，且使用的連接埠能撐過 `:53` 過濾 |
| 2 | 對 `forwarders` 使用明文 Do53 | 本地／由 DHCP 提供的解析器 |
| 3 | 對 `resolution.public_fallback` 使用明文 Do53 | 最後手段 |

DoH 優先於 DoT，因為 `:443` 看起來就像普通的 HTTPS，能撐過那種「讓 DoT 連線建立起來、卻把它的 TLS 工作階段丟掉」的深度封包檢測。安全上游是**以 IP** 撥接，並用設定的 `hostname` 驗證憑證，因此這個層級啟動時不需要任何先行的 DNS。

一個層級只有在傳輸成功且 rcode 為 NoError 或 NXDOMAIN 時才算「勝出」；SERVFAIL、REFUSED 與無法剖析的回應會往下落。勝出的層級是**黏著的**，因此查詢不會每次都在一條死掉的路徑上付出逾時代價。復原到更受偏好的層級是立即發生的；降級到較差的層級則要在連續 `resolution.switch_grace_failures` 次偏離的查詢之後才提交，因此一次不穩的查詢無法把解析器搞得來回震盪。**用戶端查詢絕不會被拿去探測**：起始層級一律就是已提交的層級。一個背景任務會每隔 `resolution.recovery_probe_secs` 以自己的拋棄式探針重新測試位於其上的那些層級，而要取回第 0 層需要根區域自身 `DNSKEY` 的一個通過 DNSSEC 驗證的答案——光靠「連得上」，會讓任何劫持 `:53` 的中介設備把自己安裝成最受信任的層級。每一次已提交的層級切換都會清空 DNS 快取，因此某個層級的答案不會在切換到另一個層級後還殘留著。

### 迭代解析器

解析器會從根伺服器往下走訪委派鏈——根 → TLD → 權威——並清除 recursion-desired 位元，以交易 ID 與問題名稱驗證回應以抵禦路徑外偽冒，走 UDP 並在被截斷時自動退回 TCP。

- **根伺服器提示與預熱。** 那 13 個 IANA 根位址（僅 IPv4，因此純 v4 主機絕不會卡在 v6 的根上）是一個啟動引導：Rolodex 會在啟動時去問根伺服器「根伺服器有哪些」，並以真正的 TTL 快取實際的 `.` NS 集合。預熱絕不會在查詢路徑上執行，而在它失敗時，那些提示仍是後備。可用 `resolution.root_hints` 覆寫。
- **負載分散到各伺服器。** 名稱伺服器是依最低的 `hits × 平均延遲` 選出的，這會把查詢分配成 `hits ∝ 1/latency`：快的伺服器承擔較多，但每一台健康的伺服器都承擔一些。這是刻意避免把每一次冷查詢都釘在同一台根伺服器上（無論是「第一台」還是「最快的那台」），因為那會招來速率限制，並把每次查找都變成一次逾時與故障轉移。
- **失敗退避。** 一台失敗的伺服器會被暫停 2 秒，每次連續失敗加倍，最高 300 秒，並在它首次成功時清除。處於退避中的伺服器排在最後，但絕不會被丟棄，因此即使所有東西都在失敗，解析仍會繼續。
- **有界的工作量。** 每台名稱伺服器 1.5 秒逾時、30 次轉介、16 次 CNAME 跳轉、深度 16、每個無黏合記錄的委派最多嘗試 4 台名稱伺服器，以及每次用戶端查找最多 64 次上游查詢的硬上限——各軸向的限制是相乘的，所以總量被直接封頂。

### 解析器快取

有兩份尊重 TTL 的快取位於答案快取之下，保留遞迴過程中一路學到的東西：

- **委派快取**——「區域 → 名稱伺服器位址」，從每一次轉介中學得。一次預熱過的 `.com` 查找會完全跳過根那一跳。TTL 超過 `resolution.delegation_persist_min_ttl`（預設 300 秒）的委派會被持久化到 SQLite 並在開機時重新載入，因此重啟後回來時是預熱的；根與 TLD 的 NS 集合帶有數天的 TTL，所以恰好是值得保留的那些項目存活了下來。
- **記錄快取**——黏合記錄、無黏合記錄的 NS 名稱查找，以及 CNAME 跳轉，以 `(name, type)` 為鍵，並以它們**剩餘的**壽命提供。

兩者都能撐過記錄變更（新增一筆記錄絕不該把全世界的名稱都送回根伺服器），只有在 `auto` 模式的層級切換時才會被清空。

TTL 一律照發佈的原樣採用——包括區域 SOA 的否定 TTL，它從不被夾限。`resolution.default_ttl` 只在完全沒有任何可用 TTL 的情況下才套用。

## 位址族過濾

網路經常會公告一條 IPv6 預設路由，然後把所有 v6 流量默默丟掉（在純 v4 的 NAT 上則會發生鏡像的情況）。一個拿到自己主機無法路由之位址族的用戶端，會卡在那個死掉的族上而不是改用另一族——這正是在 v6 壞掉的連線上讓容器映像拉取卡死的那個故障。

在 `address_family.mode: auto`（預設值）下，背景探測會以 TCP 連到公用任播解析器的 `:443`——那是真實流量所使用的連接埠，也是能撐過某些網路強加的 `:53`／`:853` 過濾的連接埠——以測試**實際的**各位址族可達性。屬於不可達族的 A/AAAA 記錄接著會從答案中被丟掉（變成 NODATA），讓用戶端改用可用的協議堆疊。

第一次探測會在啟動時同步執行且具決定性，因此開機到一條死掉位址族的連線上時，從第一次查詢起就會抑制該族。之後，一個原本正常的族只有在連續 `address_family.fail_threshold` 輪探測都失敗後才會被標記為不可用，而復原則在首次成功時就生效。設定 `mode: off` 可一律兩族都回答，或用 `force4`／`force6` 不做探測直接釘住一族。

## 加密傳輸

Rolodex DNS 支援三種加密的 DNS 傳輸協定，用以防止 DNS 查詢被竊聽：

**DNS-over-TLS（DoT）**——RFC 7858，預設連接埠 853。標準的、以 TLS 封裝的 TCP 上 DNS。以 YAML 中的 `dot` 區段或透過 gRPC 的 `SetDotConfig` 設定。

**DNS-over-HTTPS（DoH）**——RFC 8484，預設連接埠 443。HTTPS 上的 DNS 查詢，同時支援 GET（`/dns-query?dns=<base64>`）與 POST（`application/dns-message`）兩種方法。可選擇性地透過 QUIC 支援 HTTP/3（`enable_h3: true`）。以 YAML 中的 `doh` 區段或透過 gRPC 的 `SetDohConfig` 設定。

**DNS-over-QUIC（DoQ）**——RFC 9250，預設連接埠 8853。以 QUIC 傳輸進行 DNS 查詢，達成低延遲的加密解析。以 YAML 中的 `doq` 區段或透過 gRPC 的 `SetDoqConfig` 設定。

這三種協定都需要 TLS 憑證。你可以提供自己的憑證與私鑰，或設定 `auto_self_signed: true` 讓 Rolodex DNS 自動產生一張自簽憑證。

## DNSSEC

Rolodex DNS 有兩個彼此獨立的 DNSSEC 半邊：它為自己的區域**簽章**，也**驗證**它從上游解析回來的答案。兩者不共用任何程式碼——簽章者處理的是我們自己寫入的資料庫資料列，每一個位元組都在掌控之中；驗證器處理的是來自「其誠實與否正是待證問題」的一方所送來的東西，而這兩者必須有能力彼此不同意。

### 區域簽章

簽章支援下列演算法：

- **Ed25519**（首選）——金鑰與簽章都精簡，簽章速度快
- **ECDSA P-256/SHA-256** 與 **ECDSA P-384/SHA-384**

**RSA/SHA-256（演算法 8）無法產生**，且 `generate-dnssec-key` 會拒絕它：`ring` 沒有 RSA 金鑰產生功能。它仍然**可被剖析**——一筆歸檔在該演算法下的既有金鑰仍可被列出——而來自上游區域的 RSA 簽章也是可驗證的，但這裡的任何東西都不會用它來簽。一個無法端到端被貫徹的演算法會在產生金鑰時就被拒絕，而不是被悄悄替換掉，因為一個宣稱某演算法卻承載另一種金鑰材料的 DNSKEY，會產出彼此都對不上的 DS、DNSKEY 與一整組 RRSIG，而那個失敗會在某個做驗證的解析器上浮現，而不是在本地。

由於 ring 密碼學 crate 的限制，不支援 Ed448。

#### 簽章流程

1. 為你的區域產生一把金鑰簽署金鑰（KSK）與一把區域簽署金鑰（ZSK）：
   ```bash
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
   ```

2. 為區域簽章：
   ```bash
   rolodex-dns-cli sign-zone --zone example.com.
   ```

3. 取得要交給註冊商的 DS 記錄。這件事沒有對應的 CLI 子指令——請呼叫 `GetDsRecords` gRPC 方法（例如透過 Go 用戶端的 `GetDsRecords(ctx, zone)`），或用任何 DNS 用戶端從該區域查詢 DS 記錄。

簽章會重新發佈頂點的 DNSKEY RRset，並為每個 RRset 產生一筆 RRSIG。新增或修改記錄後請重新執行 `sign-zone`；既有的 RRSIG 是被取代而不是累積。

**不會產生經過認證的否定證明。** NSEC、NSEC3 與 NSEC3PARAM 是可儲存、可列出的記錄型別，但 `sign-zone` 既不產生也不提供它們，因此在這裡簽出來的區域只證明「存在什麼」，不證明「不存在什麼」。

DNSKEY、DS 與 RRSIG 以它們自己的型別碼提供，RDATA 由簽章者拿去做雜湊的同一個正規編碼器產生——送上線路的東西與被簽的東西逐位元組相同。

### 上游驗證

**迭代**解析出來的答案會對照 IANA 根信任錨點驗證。這預設是開啟的：

```yaml
dnssec:
  validate: true        # 預設值
  trust_anchors: []     # 空值 = IANA 根金鑰
```

它只適用於迭代路徑——`recursive` 模式，以及 `auto` 的根伺服器層級。轉送回來的回應是別人的遞迴結論摘要，要驗證它就意味著我們自己把整條鏈重新解析一遍，而那恰恰就是根伺服器層級本身。因此一條已降到第 0 層以下的 `auto` 鏈是未經驗證的，而它會以「不設定 AD」如實表明。

RFC 4033 §5 的四種判定被清楚區分：

| 判定 | 意義 | 是否提供？ |
| ---- | ---- | ---------- |
| `Secure` | 簽章鏈接到信任錨點 | 是，並為有詢問的用戶端設置 AD |
| `Insecure` | 信任鏈**可證明地**中止了——路徑上某個委派沒有 DS，而這個「不存在」本身是被簽章過的 | 是，AD 不設置 |
| `Bogus` | 資料宣稱自己已被簽章，而這個宣稱站不住腳 | **絕不。** SERVFAIL |
| `Indeterminate` | 我們拿不到做出判斷所需要的東西 | **絕不。** SERVFAIL |

承載安全性的區分是「非安全 vs 偽造」。「沒有簽章」**不等於**非安全——路徑上攻擊者能從任何回應中剝掉簽章。只有當一份已簽章的 NSEC/NSEC3 證明了上層委派處確實沒有 DS 時，它才是非安全，而攻擊者沒有父區域的金鑰就偽造不出這種證明。那份證明正是 NSEC/NSEC3 機制存在的理由；少了它，驗證器就是一個會被攻擊者降級成完全不存在的驗證器。

它實際上的行為：

- **信任鏈是由上而下建立的**，與解析器本來就在執行的委派走訪並行，因此 DS 就搭在轉介裡、不花額外代價。已驗證的金鑰集合（以及已被證明為非安全的委派）會逐區域快取，因此一個已預熱的區域不需要重新推導。
- **偽造的答案永不快取**，無論正面或負面——一筆被快取的偽造否定回應會在其整個 TTL 期間壓住真正的名稱。在 `auto` 模式下，驗證失敗是一個**確定性**答案而非層級失敗，所以一個壞掉的簽章不可能被拿去經由某個不做驗證的上游洗白。
- **AD 只在 `Secure` 時設置**，且只對設了 DO 或 AD 的用戶端設置。以本地資料建構的答案永遠不會設置 AD。
- **對沒有設定 DO 的用戶端會剝除 RRSIG/NSEC/NSEC3**（RFC 4035 §3.2.1），除非它明確按名稱要求該型別——一筆已簽章的 A 記錄體積大約會變成三倍，而「小問題換大答案」正是 `security.recursion_cidrs` 存在要堵住的那種放大形狀。
- **不支援的演算法是非安全而非偽造**（RFC 6840 §5.11）：我們缺少某個演算法，不是那個區域的故障。RSA/SHA-1/256/512、兩種 ECDSA 曲線與 Ed25519 都可驗證。NSEC3 迭代次數超過 100 時會被視為非安全而不去計算（RFC 9276）。
- **驗證大約會讓路徑上每個區域多花一次查詢**，因此啟用驗證時，每次查找的查詢額度會在基礎的 64 之上再加 32。

設定 `dnssec.validate: false` 的解析行為與先前完全相同：對外不設 DO 位元、不建立信任鏈、偽造資料也不會變成 SERVFAIL。

**信任錨點。** `dnssec.trust_anchors` 採用 DNSKEY 呈現格式——`"<flags> <protocol> <algorithm> <base64 key>"`，也就是 `dig DNSKEY .` 印出的那四個 RDATA 欄位。覆寫是**取代**IANA 金鑰而非追加，因此一個私有根只錨定到它自己的金鑰、別無其他。每個欄位都在啟動時驗證，而格式錯誤的錨點是硬性失敗，不是悄悄退回——一個無法對上任何真實 DNSKEY 的錨點，會讓每個已簽章的區域都失敗，而且沒有任何線索指向錨點才是原因。

判定可透過 Prometheus 的 `rolodex_dns_dnssec_verdicts_total{verdict}` 觀察，另有 `dnssec_servfail_total` 與 `key_cache_entries`。

## 散佈與信任憑證機構

Rolodex DNS 自己就是一個 ACME 憑證機構：一張自簽的**根憑證機構**簽署**逐區域的中繼憑證機構**，而每張中繼憑證簽發透過 ACME 端點所核發的終端憑證。用戶端要信任那些憑證，就必須信任根憑證機構。Rolodex 以三種方式散佈憑證鏈。

### 透過 DNS 散佈憑證機構（CERT 記錄，並以 TXT 為後備）

每當一個逐區域的中繼憑證機構被建立時，Rolodex 就會把根憑證與中繼憑證發佈**到 DNS 本身**，因此任何解析得到該區域的用戶端，都能在完全不接觸註冊入口網站的情況下取得並信任該憑證機構：

- **`CERT` 記錄（RFC 4398）**位於 `_ca.<zone>.`——每張憑證一筆記錄，RDATA 為 `"1 0 0 <base64 DER>"`（型別 1 = PKIX/X.509，key tag 與演算法皆為 0）。根憑證是以「自簽憑證」這個特徵辨識出來的。任何 DNS 用戶端都可以用：
  ```bash
  dig CERT _ca.example.com
  ```
- **`TXT` 記錄**位於 `_rolodex-ca.<zone>.`——同樣的 base64 DER 被切成不超過 255 位元組的區塊，框成 `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>`。獨特的 `rolodex-ca:` 前綴把這些區塊與無關的 TXT 資料區分開來，而明確的序號讓用戶端無論答案順序如何都能重新組裝。這是給那些無法查詢 `CERT` 的解析器堆疊使用的後備。

發佈是冪等的（記錄是被取代而不是重複新增），且會發生在每一個確保區域憑證機構存在的時點：入口網站註冊、`EnsureZoneCa`／`CreateEabCredential` RPC，以及 ACME 的帳號建立與 finalize。使用端應優先採用 `CERT`，並在必要時退回 `TXT`。

### 瀏覽器擴充功能

位於 [`extension/`](extension/) 的瀏覽器擴充功能有一個獨立於入口網站的 **CA via DNS** 面板：給它一個 DoH URL（例如 `https://dns.example.com/dns-query`）與一個區域，它就會透過 DNS-over-HTTPS 取得憑證鏈（優先 `CERT`，並退回 `TXT`）、分辨出哪張是根、哪張是中繼、可選地對照已發佈的 DANE-TA `TLSA` 記錄驗證中繼憑證，並提供根／中繼／整條鏈的 PEM 下載。DNS 邏輯位於 `extension/ca_dns.js`，那是一個不依賴任何外部套件的瀏覽器模組，JavaScript 測試套件也重複使用它。

### 入口網站與 CLI

在受信任的網路上，註冊入口網站（`acme.portal_bind`，預設 `https://<host>:8500`）會在 `GET /api/ca` 提供根憑證機構，而管理 CLI 會印出完整的鏈：

```bash
# 印出某個區域的根 + 中繼 PEM
rolodex-dns-cli ensure-zone-ca --zone example.com

# 或從入口網站下載根憑證機構
curl -k https://<host>:8500/api/ca -o rolodex-root-ca.pem
```

取得根憑證機構的 PEM 之後，請把它加入每台裝置的信任存放區（例如 Fedora/RHEL 上的 `update-ca-trust`、Debian/Ubuntu 上的 `update-ca-certificates`、macOS 上的鑰匙圈存取，或 Firefox 自己的憑證管理員）。透過 ACME 端點簽發憑證的伺服器會提供一條 `終端憑證 + 中繼憑證` 的鏈，它能對照這個根通過驗證；支援 DANE 的用戶端還可以額外透過 Rolodex 在簽發時自動發佈的 `TLSA` 記錄來釘選中繼憑證。

## DNS64

DNS64（RFC 6147）會為需要連到純 IPv4 主機的純 IPv6 用戶端，從 A 記錄合成 AAAA 記錄。當用戶端查詢 AAAA 記錄而該記錄不存在、但存在 A 記錄時，Rolodex DNS 會把該 IPv4 位址嵌入設定好的 IPv6 前綴，建構出一筆合成的 AAAA。

預設前綴是 `64:ff9b::/96`（眾所周知的 NAT64 前綴）。舉例來說，一筆 `192.0.2.1` 的 A 記錄會被合成為 `64:ff9b::192.0.2.1`（`64:ff9b::c000:201`）。

透過 YAML 設定：
```yaml
dns64:
  enabled: true
  prefix: "64:ff9b::"
```

或在執行期透過 gRPC：`SetDns64Config` / `GetDns64Config`。

## Prometheus 指標

一個選用的 `metrics` 區段會在 `/metrics` 啟動一個純 HTTP 的抓取端點。這個區段**預設不存在**，因此不會啟動任何監聽器，升級也不會開出新的連接埠。

```yaml
metrics:
  bind: "127.0.0.1:9153"
  # 會拿到自己 `tld` 標籤的 TLD。專屬 TLD 會自動被追蹤。
  tracked_tlds:
    - common          # 展開成內建的常見 TLD 集合
    - lab.internal    # 其他你想隔離出來的，逐一指名
```

這個端點不做認證，且只承載彙總計數——沒有查詢名稱、沒有記錄值、沒有憑證材料。請把它綁在私有位址上；預設是 loopback。這裡刻意不提供 TLS，因為那會意味著要把一張自簽憑證發給每一個抓取端，而這個端點本來就不該對外可達。

輸出 77 個指標系列，全部以 `rolodex_dns_` 為前綴，涵蓋查詢、回應快取、封鎖清單（包含拒答與被移出輪替的供應商）、上游層級、迭代解析器、DNSSEC 判定、分割視域狀態、DHCP、ACME 與 gRPC。

其中最值得認識的是 `rolodex_dns_answers_total{source}`，它回報解析順序中的哪個階段產生了每個答案——`cache`、`local`、`scoped`、`scope_fallback`、`tld_peer`、`blocklist`、`reverse_blocklist`、`dns64`、`upstream`、`authoritative_nxdomain`、`refused`、`error`。它的總數等於查詢總數，而這正是讓分割視域管線從外面看得懂的關鍵：

```
curl -s http://127.0.0.1:9153/metrics | grep answers_total
```

### 基數

有界的基數是一項設計約束，因為一個陌生人能無限撐大的指標端點，就是一個披著監控外衣的記憶體耗盡缺陷。每個標籤要嘛是固定列舉，要嘛由設定所限制。**用戶端**原本可能撐大的那兩個維度，都被折疊進兜底值：

| 維度 | 界限 | 兜底值 |
|------|------|--------|
| `qtype` | 23 種已知記錄型別 | `OTHER`——一場 `TYPE4242` 查詢的洪水什麼都產生不出來 |
| `tld` | 專屬 TLD，加上 `metrics.tracked_tlds` | `other`——一台掃描垃圾 TLD 的掃描器什麼都產生不出來 |

**查詢名稱永遠不會成為標籤。** 只有 TLD 後綴，而且只在維運人員已經主動納入那個後綴時才有。

### 逐 TLD 隔離

`rolodex_dns_queries_by_tld_total{tld}` 把查詢流依 TLD 拆開，這正是讓分割視域部署中的各個網路，彼此之間、以及與公開網際網路之間得以分離的關鍵。有三個來源餵入這個被追蹤的集合：

1. **專屬 TLD，自動納入。** 每個網路範圍所擁有的 TLD——包含各範圍隱含的 `.home` 網域——都不需要被指名就會被追蹤。一個網路自己的命名空間是最值得隔離的東西，而要求它被寫兩次（一次是擁有它、一次是追蹤它）是個坑，且它會以「某個系列悄悄不見」的形式浮現。
2. **設定清單。** YAML 中的 `metrics.tracked_tlds`。項目 `common` 會展開成內建的常見 TLD 集合（`com.`、`net.`、`org.`、`io.`、`dev.` 等），因此常見的公開 TLD 是一行而不是二十行。設定中的項目是被釘住的：它們撐得過重啟，且無法透過 API 移除。
3. **儲存清單。** 在執行期管理，不需要重啟：

```bash
# 追蹤常見集合，再加上一個特例 TLD
rolodex-dns-cli set-tracked-tlds --tld common --tld lab.internal

# 顯示儲存清單、專屬清單與生效集合
rolodex-dns-cli list-tracked-tlds

# 清空儲存清單（專屬 TLD 與設定檔釘住的不受影響）
rolodex-dns-cli set-tracked-tlds
```

**生效**集合是三者的聯集，而它才是真正產生系列的東西——這也是為什麼兩個指令都會把它印出來。光看儲存清單並不能告訴你哪些系列會出現。

### DNS 與 DHCP 是可分別選取的

DNS 與 DHCP 是兩個剛好共用同一個行程的獨立服務，它們的系列是刻意被分開的：

- DHCP 的系列把它們的維度命名為 **`message_type`** 與 **`lease_state`**，而不是通用的 `type` 與 `state`。通用的標籤名稱，正是讓橫跨兩個子系統的彙總——例如某條記錄規則裡的 `sum by (type) (...)`——悄悄把 DHCP 的 ACK 計數混進 DNS 計數的原因。
- DNS 的彙總指標（`queries_total`、`traffic_bytes_total`、`records_served_total`、`queries_by_tld_total`）**只計 DNS**。`:67` 上的 DHCP 封包從不被算成 DNS 流量，而一個由 DHCP 註冊的名稱，只有在真的有人去解析它時才會對 DNS 指標有所貢獻。

> **升級提醒：** `rolodex_dns_dhcp_messages_total{type}` 改為 `{message_type}`，而 `rolodex_dns_dhcp_leases{state}` 改為 `{lease_state}`。選用舊標籤名稱的儀表板與告警需要更新。

### 常用查詢

```promql
# 依傳輸方式的查詢速率
sum by (proto) (rate(rolodex_dns_queries_total[5m]))

# 解析順序中的哪個階段正在作答
sum by (source) (rate(rolodex_dns_answers_total[5m]))

# NXDOMAIN 佔所有答案的比例
sum(rate(rolodex_dns_queries_total{rcode="NXDOMAIN"}[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# 回應快取命中率
sum(rate(rolodex_dns_cache_hits_total[5m]))
  / (sum(rate(rolodex_dns_cache_hits_total[5m])) + sum(rate(rolodex_dns_cache_misses_total[5m])))

# 各傳輸方式的 p99 查詢延遲
histogram_quantile(0.99, sum by (le, proto) (rate(rolodex_dns_query_duration_seconds_bucket[5m])))
```

流量體積，以及其中有多少是真正的記錄而非否定答案：

```promql
# 進出的線路位元組數
sum by (direction) (rate(rolodex_dns_traffic_bytes_total[5m]))

# 放大倍數：每收到一位元組所送出的位元組數。在一個對外可達的監聽器上，
# 這個數值持續攀升就是反射攻擊的形狀。
sum(rate(rolodex_dns_traffic_bytes_total{direction="tx"}[5m]))
  / sum(rate(rolodex_dns_traffic_bytes_total{direction="rx"}[5m]))

# 每次查詢回傳的記錄數——一百萬次 NXDOMAIN 與一百萬次有內容的答案，
# 查詢數相同，工作量卻天差地別。
sum(rate(rolodex_dns_records_served_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))
```

封鎖清單——真正重要的是「封鎖數」與「拒答數」這一對，因為若只盯著封鎖計數器，一份已經停止回答的清單看起來會跟一份乾淨的清單一模一樣：

```promql
# 依實際命中的是哪份清單來分的封鎖數
sum by (kind) (rate(rolodex_dns_blocklist_blocks_total[5m]))

# 被封鎖的部分佔所有流量的比例
sum(rate(rolodex_dns_blocklist_blocks_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# 依命中路徑分的允許清單活動。這裡持續攀升，代表維運人員正在
# 不斷替一份誤判中的清單打補丁。
sum by (kind) (rate(rolodex_dns_blocklist_allowlisted_total[5m]))

# 某個供應商已開始拒答我們，而不是在回報信譽
sum by (kind) (rate(rolodex_dns_blocklist_refusals_total[5m])) > 0

# 目前被移出輪替的供應商
rolodex_dns_blocklist_rotated_out > 0
```

逐 TLD、上游健康狀況與 DNSSEC：

```promql
# 每個被追蹤 TLD 的查詢速率，忽略未追蹤的兜底值
sum by (tld) (rate(rolodex_dns_queries_by_tld_total{tld!="other"}[5m]))

# 有多少比例的流量是你並未追蹤的名稱
sum(rate(rolodex_dns_queries_by_tld_total{tld="other"}[5m]))
  / sum(rate(rolodex_dns_queries_by_tld_total[5m]))

# 已從迭代層級降級（0=根伺服器、1=安全、2=本地、3=公用）
rolodex_dns_upstream_active_tier > 0

# 層級抖動
sum by (direction) (rate(rolodex_dns_upstream_tier_switches_total[5m]))

# 驗證失敗的已簽章資料：可能是攻擊，也可能是某個區域自己把簽章弄壞了。
# 這與 `indeterminate` 不同，後者是網路故障。
sum(rate(rolodex_dns_dnssec_verdicts_total{verdict="bogus"}[5m])) > 0

# 因為委派超出作答區域而被丟棄的轉介
rate(rolodex_dns_resolver_out_of_bailiwick_total[5m]) > 0

# 被逐次查找的查詢額度終止掉的查找
rate(rolodex_dns_resolver_budget_exhausted_total[5m]) > 0
```

DHCP，使用隔離過的標籤名稱：

```promql
# 依狀態分類的租約
rolodex_dns_dhcp_leases{lease_state="active"}

# 依型別分類的 DHCP 訊息速率
sum by (message_type) (rate(rolodex_dns_dhcp_messages_total[5m]))

# 位址池耗盡
rate(rolodex_dns_dhcp_allocation_failures_total[5m]) > 0
```

控制平面與主機可達性：

```promql
# 有人正在猜測 gRPC 共用密鑰
rate(rolodex_dns_grpc_auth_failures_total[5m]) > 0

# 一個主機無法路由的位址族，因此它的記錄正在被抑制
rolodex_dns_address_family_reachable{family="ipv6"} == 0
```

上面每一條查詢都有測試涵蓋，會把它的指標名稱與標籤比對條件對照實際輸出解析，因此文件中的查詢不可能引用到不存在的系列。

## 封鎖清單

Rolodex DNS 以兩種方式封鎖名稱，被封鎖的查詢都會得到 `NXDOMAIN`：

- **DNSBL 供應商** —— 以名稱查詢的第三方區域，見下文 [DNSBL（網域封鎖清單）](#dnsbl網域封鎖清單)。
- **本地清單** —— 一份由維運人員手工封鎖的名稱與位址，存放在資料庫中。

兩者預設皆為停用／為空：在加入供應商之前，不會發出任何外部查詢，也不會把任何名稱交給封鎖清單營運方。

### 本地封鎖清單資料庫

本地項目是維運人員自己的清單，會在詢問任何供應商之前先行檢查，並透過 `AddLocalBlocklistEntry`、`RemoveLocalBlocklistEntry` 與 `ListLocalBlocklistEntries` 管理。

一條項目可以指名一個**網域名稱**（在正向名稱這一道關卡比對），也可以指名一個**位址**（在反向查找時比對）。位址兩種寫法皆可——IP 字面值，或 `dig -x` 印出的 `in-addr.arpa`／`ip6.arpa` 名稱——兩種寫法都會封鎖。位址永遠只由這份清單封鎖：供應商被問及的是正在解析的那個名稱，而在反向查找中，那是一個沒有人會為其發布信譽資料的名稱。

```bash
# 以一個理由封鎖特定 IP
rolodex-dns-cli add-local-blocklist --name 10.0.0.5 --reason "known spam source"

# 列出本地項目
rolodex-dns-cli list-local-blocklist

# 移除一條項目
rolodex-dns-cli remove-local-blocklist --name 10.0.0.5
```

### 快取

- 正面結果（名稱已列入）依供應商回傳的 TTL 快取
- 負面結果（未列入）快取 5 分鐘
- 查找錯誤不快取，並被視為未列入，以避免誤判
- 拒答同樣不快取，並會把該供應商移出輪替——見下文
- 快取可透過 `FlushCache` gRPC 方法清空，該方法同時會把每一個被移出輪替的供應商放回輪替

### 拒答碼與供應商輪替

一份 DNSxL 回應「已列入」與抱怨**你**用的是同一種方式：`127.0.0.0/8` 之下的一筆 `A` 記錄。`zen.spamhaus.org` 用 `127.0.0.2` 說「已列入」，用 `127.255.255.254` 說「你正透過公用解析器發問」，而**唯一能區分兩者的就是位址本身**。把任何 `A` 記錄都讀成「已列入」，就等於在封鎖清單決定不再回答你的那一刻，把**每一個**對照該供應商檢查過的名稱都變成 NXDOMAIN——而這會在你的查詢量越過該供應商門檻時開始發生，可能是一次看起來一切正常的部署之後好幾小時或好幾週。Spamhaus 講得很直接：那些碼「不應被解讀為任何形式的信譽評價」。

因此每個供應商都帶有一組拒答碼。符合的答案是 **`Refused`**：不是列入、不是否定、什麼都不快取——對被查詢的名稱什麼都沒學到。同一個回應中，任何位置的拒答都勝過同一個回應中的列入，因為一個正在抱怨的供應商不會同時在回報信譽，而往這個方向犯錯會**失效放行**，反過來的順序則會在每一個名稱上失效阻斷。

供應商未自行設定時所使用的內建集合：

| 碼 | 意義 |
| -- | ---- |
| `127.255.255.0/24` | Spamhaus 錯誤範圍：`.252` 區域名稱打錯、`.254` 透過公用／開放解析器查詢、`.255` 查詢過量。之所以取整個範圍而不是那三個碼，是因為 Spamhaus 保留了它並會往裡面新增 |
| `127.0.1.255` | Spamhaus DBL 回應一個 IP 查詢——「不支援 IP 查詢」 |
| `127.0.2.255` | Spamhaus ZRD 回應一個 IP 查詢——同上 |
| `127.0.0.1` | URIBL/SURBL 的「查詢已被封鎖」。RFC 5782 §5 同時禁止 DNSxL 列入 `127.0.0.1`，因此它絕不可能是一個正當的列入 |
| `127.0.0.255` | URIBL 的「查詢已被封鎖」（超出配額） |

每一項是一個 IPv4 位址或 `address/prefix`。**空值代表內建集合**——它不可能代表「沒有任何碼」，因為在這項功能存在之前寫的每一份設定都是空的。單一項目 `none` 可為那些真實列入值恰好與上述之一相撞的私有封鎖清單停用偵測。明確列出的清單就只是那份清單；預設值不會被合併進來，所以把它寫出來的維運人員也可以藉此縮小範圍。無法剖析的碼會被拒絕——在啟動時，或由 RPC 回以 `InvalidArgument`——而不是被跳過，因為一個悄悄失效的碼，就是一個會被讀成「已列入」的拒答。

**輪替。** 一次拒答會把該供應商移出查詢輪替 `refusal_cooldown_secs`（預設 3600 秒，可逐供應商覆寫），因此一份剛剛叫你別再問的封鎖清單會被退避，而不是每次請求都再去問一遍。輪替：

- 只跳過**新的查找**——已快取的判定仍然算數，因為「這個供應商不會回答新問題」不等於「它先前給的答案是錯的」；
- 會**自行失效**，因此短暫的超額配額期不需要維運人員動手就會自癒；
- 會被 `flush-cache` 以及任何 `set-dnsbl-config` **清除**——重新設定往往正是那次拒答的修正動作（區域名稱打錯既是 `127.255.255.252` 的成因，也正是被修正的那個東西）；
- 會被 `get-dnsbl-config` 以及 `rolodex_dns_blocklist_refusals_total{kind}` / `rolodex_dns_blocklist_rotated_out` **回報出來**。

把冷卻設為 `0` 代表「使用預設值」，而不是「不冷卻」——零冷卻等於去重問那個剛剛叫你別問了的供應商，而那正是輪替存在要防止的行為。

## DNSBL（網域封鎖清單）

RBL 供應商是以 **IP 位址**封鎖（在反向 DNS 查找時以反轉的 IP 查詢），而 DNSBL 供應商是以**網域名稱**封鎖：被查詢名稱的標籤會前置到供應商的區域之前，因此 `googleadservices.com` 對照 `dbl.spamhaus.org` 會被查詢成 `googleadservices.com.dbl.spamhaus.org`。Spamhaus DBL、SURBL 與 URIBL 都是這樣運作的。

DNSBL 讓封鎖清單**優先於外部 DNS**。這道檢查在本地記錄與受管／權威區域之後執行——因此內部資料一律勝出——但在上游回應快取與任何外部解析**之前**。因此即使先前已為某個被列入的名稱快取了一個轉送答案，它仍然會回 NXDOMAIN。

與 RBL 一樣，DNSBL 預設為停用且供應商清單為空，個別供應商也可獨立啟用或停用。一個已啟用但為空的 DNSBL 是空操作。維運人員通常會加入的標準區域是 `dbl.spamhaus.org`、`multi.surbl.org` 與 `multi.uribl.com`。DNSBL 的結果與 RBL 共用同一份結果快取（正面結果依供應商 TTL，負面結果 5 分鐘）。

```bash
rolodex-dns-cli set-dnsbl-config --enabled --providers dbl.spamhaus.org:true
rolodex-dns-cli get-dnsbl-config
```

### 為某台主機加入允許清單

允許清單是維運人員面對誤判時的逃生口，而且它涵蓋**所有清單與兩道關卡**：正向名稱檢查（DNSBL 供應商與本地封鎖清單）**以及**反向 DNS／IP 檢查（指名某個位址的本地項目）。一個被錯誤列入的 IP 會讓一台運作正常的主機 `dig -x` 失敗，所以一個只構得到名稱的逃生口根本稱不上逃生口。

- **名稱是後綴比對的。** 一個項目涵蓋該名稱以及它底下的每一個名稱，因此把 `example.com` 加進允許清單也會豁免 `www.example.com`；比對是在標籤邊界上進行的，所以 `notexample.com` 不會被豁免。
- **一個位址可以用兩種寫法指名。** 一個反向查詢會被指名 `in-addr.arpa`／`ip6.arpa` 名稱**或**它所編碼之 IP 字面值的項目所豁免，因此沒有人需要手動反轉八位元組。反向**名稱**像任何 DNS 名稱一樣以後綴比對（把 `1.168.192.in-addr.arpa` 加進允許清單會解除整個 /24 的封鎖）；而 IP **字面值**是**精確**比對，因為位址是最高位八位元組在前——`1.100` 不是 `192.168.1.100` 的父節點，把它當成父節點會豁免掉沒有人指名過的位址。
- **它會整個短路掉這道檢查。** 一個被豁免的名稱或位址不會對照任何供應商檢查，也完全不會發出任何封鎖清單查找。
- 項目是正規化過的（小寫、結尾帶點），因此任何寫法都會新增或移除同一個項目；它們會跨重啟保存，且在下一次查詢時就生效，不需要清空快取。

```bash
# 豁免某台被供應商誤判的主機
rolodex-dns-cli add-dnsbl-allow --name vendor.example.com --reason "blocklist false positive"

# 豁免某個位址——兩種寫法都可以
rolodex-dns-cli add-dnsbl-allow --name 192.168.1.100 --reason "our own mail relay"
rolodex-dns-cli add-dnsbl-allow --name 1.168.192.in-addr.arpa --reason "whole /24"

# 列出允許清單
rolodex-dns-cli list-dnsbl-allow

# 移除一筆項目
rolodex-dns-cli remove-dnsbl-allow --name vendor.example.com
```

## 網路範圍劃分

網路範圍劃分提供分割視域的 DNS 視圖，讓 DNS 回應可以依用戶端 IP 所關聯的網路範圍而不同。

### 概念

- **網路範圍**：一個具名的 DNS 視圖，擁有自己的一組 DNS 記錄與一個保留的 `.home` 網域（例如 `office.home.`）。這個 `.home` 網域會被當作 DHCP 用戶端的預設搜尋網域。
- **網路關聯**：一個從用戶端 IP 到某個範圍的對應，帶有必須定期更新的 TTL。TTL 到期時，該 IP 會失去它的範圍關聯，DNS 查詢也會被拒絕。
- **範圍內記錄**：屬於某個特定範圍的 DNS 記錄，只對關聯到該範圍的 IP 可見。

### 運作方式

1. 建立一個網路範圍（例如名為 `"office"`、網域為 `"office.home."`）
2. 為該範圍新增範圍內的 DNS 記錄
3. 用戶端 IP 透過關聯到某個範圍來加入網路（帶有 TTL）
4. 當一個 DNS 查詢抵達時：
   - 若它是抵達某個逐 TLD 的**入口監聽器**：無論名稱是什麼，都在該監聽器的擁有範圍內作答
   - 若來源 IP 已關聯到某個範圍：先檢查範圍內記錄，接著落到全域記錄，然後才向外解析
   - 若來源 IP 位於 `security.overlay_cidrs` 之內（一個疊加網路／WireGuard 對等節點）卻未加入任何範圍：**REFUSED**
   - 其他任何來源——loopback、區域網路、容器橋接——都受信任：它永遠不會被拒絕，並解析全域命名空間
   - 若根本沒有任何範圍存在：沿用舊行為（所有查詢都從全域記錄作答）
5. 搜尋網域（透過 `GetSearchDomains`）會回傳供 DHCP 整合使用的 `.home` 網域

### 受信任來源 vs. 疊加對等節點

範圍強制**只**套用於位於 `security.overlay_cidrs`（預設 `10.64.0.0/10`，即 WireGuard 疊加網路範圍）之內的來源 IP。這樣的對等節點必須已加入某個網路，否則就會被拒絕，而且它只看得到自己範圍所分隔出來的 TLD。其他所有來源都受信任，並解析全域視圖。

這正是讓分割視域在實務上真正好用的地方：一個名稱可以同時帶有一筆指向這台機器區網位址的全域記錄，與一筆指向其疊加位址的範圍內記錄，而每一邊拿到的都是它真的路由得到的位址。

### 遞迴存取控制

範圍強制決定的是某個來源拿到**哪個視圖**。另一個獨立的軸向 `security.recursion_cidrs`，決定的則是某個來源究竟能不能取得**上游解析**。

`dns.bind` 預設為 `0.0.0.0:53`，因此在可路由的介面上，這個監聽器對整個網際網路都是可達的，而 `overlay_cidrs` 之外的每一個來源都會被歸類為受信任的本地用戶端。少了第二道檢查，那就是一台**開放遞迴解析器**——經典的反射／放大攻擊資產：一個小的偽冒查詢會回傳一個大的答案打向被偽冒的受害者，而對外的解析流量算在你的機器頭上。

預設清單是每一個從網際網路不可路由的範圍——`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`100.64.0.0/10`、`::1/128`、`fe80::/10`、`fc00::/7`——它涵蓋了 loopback、區域網路、容器橋接與 WireGuard 疊加網路（`10.64.0.0/10` 位於 `10.0.0.0/8` 之內），因此任何正當使用這台伺服器的東西都不會失去服務。空清單會對所有人關閉遞迴，留下一台純權威伺服器。

- **這道檢查位於本地／遠端的邊界上**：在所有「從這台伺服器持有的資料作答」的路徑之後，在所有「去取得它沒有的資料」的路徑之前。一個陌生人仍然收得到你的權威答案與權威 NXDOMAIN——關閉遞迴絕不該把這台機器變成它自己區域的黑洞——但沒辦法讓它去問別人。
- **它在回應快取之前執行**，因為一個被快取的答案放大效果跟新鮮的一樣好，而把快取預熱正是這種攻擊的準備手法。
- **拒絕的形式是 REFUSED 搭配空的答案段**，因此回覆永遠不會比引發它的問題更大。
- **每一種傳輸方式都受此把關**——UDP、TCP、DoT、DoQ，以及 DoH（它會帶著連線資訊提供服務，好讓對端位址能進到分類邏輯；否則 `:443` 會把 `:53` 關上的東西重新打開）。

### 逐網路的專屬 TLD

除了隱含的 `.home` 網域之外，一個範圍還可以擁有額外的 TLD，用來把命名空間在各網路之間分隔開來。每個專屬 TLD 對單一範圍而言是**全域唯一**的，而它底下的名稱絕不會被轉送到上游——比對不到的名稱會產生一個權威 NXDOMAIN，並可在此之前選擇性地諮詢該 TLD 的**對等轉送器**（同一網路中其他 Rolodex 成員的疊加位址）。

- 對一個**疊加對等節點**而言，專屬 TLD 是嚴格分隔的：它解析得到自己網路的 TLD，而對任何其他範圍的 TLD 得到 NXDOMAIN，因此兩個網路的 TLD 絕不會在同一個端點上都解析得到。
- 對一個**受信任的本機來源**（loopback／區域網路）而言，**每一個**專屬 TLD 都能從它的擁有範圍解析出來，因此所有網路 TLD 在區域網路上都看得到。雙棲名稱仍然回傳它們面向區域網路的全域值；只有僅存在於範圍中的名稱才會從該範圍提供。

因此一個範圍可以純粹為了擁有某個 TLD 而存在——把它標記為「與對等節點分隔、可從區域網路解析」——而完全不需要為它綁定任何疊加網路。

```bash
# 為某個範圍註冊一個專屬 TLD
rolodex-dns-cli add-scope-tld -s office --tld office.
# 把它底下比對不到的名稱指向該網路中其他的 Rolodex 成員
rolodex-dns-cli set-scope-tld-forwarders -s office --tld office. -f 10.64.0.2:53
rolodex-dns-cli list-scope-tlds -s office
```

### 入口 DNS 監聽器

一個專屬 TLD 可以在註冊時附上一個本地的**入口 IP**（`add-scope-tld --listen-ip`），通常是該網路自己的疊加位址：

```bash
rolodex-dns-cli add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
rolodex-dns-cli list-scope-tld-listeners -s office
```

這會做三件事：

1. **在該 IP 上綁定一個 DNS 監聽器**（UDP + TCP），連接埠為 `dns.ingress_listen_port`（預設 53）。監聽器會在開機時從資料庫重新建立，並在最後一個引用該 IP 的 TLD 被移除時拆除。一次失敗的綁定——這是開機時的常見情況，因為那時疊加網路的介面還不存在——會在下一次重新註冊時重試，而不是被記成「已經在監聽了」。
2. **對每一個名稱都提供擁有範圍的視圖。** 這個監聽器是該網路的專用解析器，因此抵達它的查詢無論名稱是什麼都屬於擁有範圍：專屬 TLD 保持分隔，其他一切則落到全域解析與上游解析——這正是讓對等節點可以把它當作通用解析器使用的原因。
3. **把已編程的名稱改寫成入口 IP。** 一個位於該 TLD 之下、且有儲存 A/AAAA 記錄的名稱，會以入口 IP 而不是它儲存的後端值作答，好讓該網路的入口控制器收到流量並依 Host/SNI 路由。這一部分仍然是依名稱把關的：一個穿透過去的名稱會保留它解析出來的值，同一個名稱在主要的 `:53` 監聽器上會解析出它儲存的值，而一個沒有記錄的名稱仍然回傳 NXDOMAIN（不做萬用字元合成）。

### 解析順序（含範圍）

1. 剖析 EDNS OPT 記錄（酬載大小協商、供 DNSSEC 用的 DO 位元）
2. 檢查本地封鎖清單（針對反向 DNS 查詢）
3. 檢查 DNS 回應快取
4. 檢查用戶端所屬範圍的範圍內記錄
5. 檢查範圍內的 CNAME 記錄
6. 檢查範圍內的 DNAME 記錄（子樹改寫）
7. 檢查名稱是否位於某個範圍內的受管區域之下（權威 NXDOMAIN）
8. 檢查全域資料庫記錄
9. 檢查全域 CNAME 記錄
10. 檢查全域 DNAME 記錄（子樹改寫）
11. 檢查 ANAME 記錄（在區域頂點解析別名）
12. 檢查名稱是否位於某個全域受管區域之下（權威 NXDOMAIN）
13. 檢查萬用字元記錄（`*.zone.`）
14. 檢查本地封鎖清單與 DNSBL 供應商（被列入的名稱是 NXDOMAIN，優先於任何外部答案）
15. 強制執行 `security.recursion_cidrs`——不在其中的來源會在任何東西離開本機之前就被 REFUSED
16. 依 `resolution.mode` 向外解析（若已啟用則使用 QNAME 大小寫隨機化，若有設定則經由代理），並在迭代路徑上驗證 DNSSEC
17. 套用 DNS64 合成（若已啟用，且 AAAA 查詢回傳為空但存在 A 記錄）
18. 快取回應（偽造的答案永不快取）
19. 套用 TTL 漂移調整（若有設定）
20. 丟棄屬於不可路由位址族的 A/AAAA 答案（若 `address_family.mode: auto`）

## DHCP 伺服器

Rolodex DNS 內含一台整合的 DHCPv4 伺服器，具備 IP 位址管理與自動 DNS 註冊功能。除非設定中出現 `dhcp` 區段，否則它是停用的。

- **逐範圍的位址池。** 每個位址池屬於某個網路範圍，並定義單一連續範圍、閘道、子網路遮罩與 DNS 伺服器。位址池用盡時配置即失敗——不會跨池聚合。MAC 對 IP 的綁定是黏著的：同一個 MAC 一律會拿回同一個 IP。
- **自動 DNS 註冊。** 一個送出主機名稱（選項 12）的用戶端，會在 `<hostname>.lan.<dhcp.tld>.` 取得一筆 A 記錄，以及一筆對應的 `in-addr.arpa` PTR，兩者都是該位址池所屬範圍中的範圍內記錄。這份租約同時會被加入該網路範圍（`JoinNetwork`），因此該用戶端會立刻看到那個網路的分割視域視圖。租約被釋放或到期時，這兩筆記錄都會被移除。
- **租約狀態。** `active`、`expired`（超過其時長）、`released`（用戶端已釋放）與 `reclaimable`（超過 `reclaim_timeout`，因此該 IP 可以再次發出）。
- **憑證交付。** 憑證可以透過站台專用的 DHCP 選項（代碼 224–254）交給用戶端，逐範圍設定。
- **背景清掃。** 每隔 `sweep_interval` 秒，過期的租約會被退役（移除其 DNS 記錄與範圍關聯），而超過 `reclaim_timeout` 的租約會釋放它們的 IP。

```bash
# 給 "office" 範圍的一個位址池
rolodex-dns-cli add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1

rolodex-dns-cli list-dhcp-pools -s office
rolodex-dns-cli list-dhcp-leases -s office
```

## Go 用戶端

`go/` 底下附有一個 Go 用戶端函式庫，供以程式方式存取 Rolodex DNS 的 gRPC API。它可以作為 Go 模組依賴匯入。

### 安裝

```
go get gitea.com/town-os/rolodex-dns/go
```

### 連線

這個用戶端支援兩種傳輸方式：

**TCP**（搭配共用密鑰認證）：

```go
client, err := rolodex_dns.Dial(ctx, "localhost:50051",
    rolodex_dns.WithAuthToken("my-secret"),
)
defer client.Close()
```

**Unix socket**（伺服器端跳過認證）：

```go
client, err := rolodex_dns.Dial(ctx, "/var/run/rolodex-dns.sock",
    rolodex_dns.WithUnixSocket(),
)
defer client.Close()
```

### 用戶端選項

| 選項 | 說明 |
|------|------|
| `WithAuthToken(token)` | 設定每次 RPC 都會送出、供 TCP 認證使用的共用密鑰。Unix socket 連線時伺服器會忽略它。預設：空值（若伺服器未設定密鑰則成功） |
| `WithUnixSocket()` | 把該位址標記為 Unix domain socket 路徑而非 TCP 位址。Unix socket 連線時伺服器會跳過認證 |
| `WithGRPCDialOption(opt)` | 附加一個底層的 `grpc.DialOption`（例如供 TLS 或攔截器使用） |

### 用戶端方法

所有方法都接受一個 `context.Context`，供取消與期限使用。

#### 記錄管理

| 方法 | 說明 |
|------|------|
| `AddRecord(ctx, record) error` | 新增一筆 DNS 記錄 |
| `RemoveRecord(ctx, name, opts) (uint32, error)` | 移除 DNS 記錄（回傳被移除的筆數） |
| `ListRecords(ctx, opts) ([]*DnsRecord, error)` | 列出／篩選 DNS 記錄 |

#### 轉送器

| 方法 | 說明 |
|------|------|
| `SetForwarders(ctx, forwarders) error` | 設定上游 DNS 轉送器 |

#### 封鎖清單

| 方法 | 說明 |
|------|------|
| `SetDnsblConfig(ctx, enabled, providers) error` | 設定 DNSBL（網域封鎖清單） |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs) error` | 同上，並附帶 DNSBL 的移出輪替時長 |
| `GetDnsblConfig(ctx) (*DnsblStatus, error)` | 取得目前的 DNSBL 設定 |
| `FlushCache(ctx) error` | 清空封鎖清單快取，並把每一個被移出輪替的供應商放回輪替 |
| `AddLocalBlocklistEntry(ctx, entry) error` | 新增一筆本地封鎖項目 |
| `RemoveLocalBlocklistEntry(ctx, name) error` | 移除一筆本地封鎖項目 |
| `ListLocalBlocklistEntries(ctx) ([]*LocalBlocklistEntry, error)` | 列出本地封鎖項目 |
| `AddDnsblAllowlistEntry(ctx, entry) error` | 讓某個名稱（及其子網域）豁免於封鎖清單檢查 |
| `RemoveDnsblAllowlistEntry(ctx, name) error` | 移除一筆 DNSBL 允許清單項目 |
| `ListDnsblAllowlistEntries(ctx) ([]*DnsblAllowlistEntry, error)` | 列出 DNSBL 允許清單項目 |

#### 網路範圍劃分

| 方法 | 說明 |
|------|------|
| `CreateNetworkScope(ctx, scope) error` | 建立一個網路範圍 |
| `DeleteNetworkScope(ctx, name) error` | 刪除一個範圍及其資料 |
| `ListNetworkScopes(ctx) ([]*NetworkScope, error)` | 列出所有範圍 |
| `JoinNetwork(ctx, ip, scope, ttl) error` | 把一個 IP 關聯到某個範圍 |
| `LeaveNetwork(ctx, ip) error` | 移除某個 IP 的範圍關聯 |
| `GetNetworkAssociations(ctx, scope) ([]*NetworkAssociation, error)` | 列出關聯 |
| `AddScopedRecord(ctx, scope, record) error` | 新增一筆範圍內的 DNS 記錄 |
| `RemoveScopedRecord(ctx, scope, name, opts) (uint32, error)` | 移除範圍內記錄 |
| `ListScopedRecords(ctx, scope, opts) ([]*DnsRecord, error)` | 列出範圍內記錄 |
| `GetSearchDomains(ctx, ip) ([]string, error)` | 取得某個 IP 的搜尋網域 |
| `AddScopeTld(ctx, scope, tld) error` | 為某個範圍註冊一個全域唯一的專屬 TLD |
| `AddScopeTldWithListener(ctx, scope, tld, listenIP) error` | 註冊一個專屬 TLD 並綁定一個入口 DNS 監聽器 |
| `RemoveScopeTld(ctx, scope, tld) error` | 從某個範圍移除一個專屬 TLD |
| `ListScopeTlds(ctx, scope) ([]string, error)` | 列出某個範圍所擁有的 TLD |
| `SetScopeTldForwarders(ctx, scope, tld, forwarders) error` | 設定某個 TLD 的對等轉送器 |
| `ListScopeTldForwarders(ctx, scope, tld) ([]string, error)` | 列出某個 TLD 的對等轉送器 |
| `ListScopeTldListeners(ctx, scope) ([]*TldListener, error)` | 列出某個範圍的入口 DNS 監聽器 |

#### DHCP

| 方法 | 說明 |
|------|------|
| `AddDhcpPool(ctx, pool) (string, error)` | 為某個範圍新增一個 DHCP 位址池 |
| `RemoveDhcpPool(ctx, poolID) error` | 移除一個 DHCP 位址池 |
| `ListDhcpPools(ctx, scope) ([]*DhcpPool, error)` | 列出 DHCP 位址池 |
| `ListDhcpLeases(ctx, scope) ([]*DhcpLease, error)` | 列出 DHCP 租約 |
| `DeleteDhcpLease(ctx, mac) error` | 依 MAC 刪除一筆 DHCP 租約 |
| `SetDhcpCertOption(ctx, opt) error` | 透過 DHCP 選項交付一張憑證 |
| `RemoveDhcpCertOption(ctx, scope, optionCode) error` | 移除一個 DHCP 憑證選項 |
| `ListDhcpCertOptions(ctx, scope) ([]*DhcpCertOption, error)` | 列出 DHCP 憑證選項 |

#### 權威區域

| 方法 | 說明 |
|------|------|
| `AddAuthoritativeZone(ctx, zone) error` | 宣告某個區域為權威 |
| `RemoveAuthoritativeZone(ctx, zone) error` | 移除一個權威區域 |
| `ListAuthoritativeZones(ctx) ([]string, error)` | 列出權威區域 |

#### 快取

| 方法 | 說明 |
|------|------|
| `GetCacheStats(ctx) (*CacheStats, error)` | 取得快取統計（項目數、命中、未命中） |
| `FlushDnsCache(ctx) error` | 清空 DNS 回應快取 |

#### 加密傳輸

| 方法 | 說明 |
|------|------|
| `SetDotConfig(ctx, config) error` | 設定 DNS-over-TLS |
| `GetDotConfig(ctx) (*DotConfig, error)` | 取得 DoT 設定 |
| `SetDohConfig(ctx, config) error` | 設定 DNS-over-HTTPS |
| `GetDohConfig(ctx) (*DohConfig, error)` | 取得 DoH 設定 |
| `SetDoqConfig(ctx, config) error` | 設定 DNS-over-QUIC |
| `GetDoqConfig(ctx) (*DoqConfig, error)` | 取得 DoQ 設定 |

#### 代理

| 方法 | 說明 |
|------|------|
| `SetProxyConfig(ctx, config) error` | 設定 HTTP 代理 |
| `GetProxyConfig(ctx) (*ProxyConfig, error)` | 取得代理設定 |

#### DNSSEC

| 方法 | 說明 |
|------|------|
| `GenerateDnssecKey(ctx, zone, algorithm, keyType) (*DnssecKey, error)` | 產生一組 DNSSEC 金鑰對 |
| `ListDnssecKeys(ctx, zone) ([]*DnssecKey, error)` | 列出某個區域的 DNSSEC 金鑰 |
| `DeleteDnssecKey(ctx, keyID) error` | 刪除一把 DNSSEC 金鑰 |
| `GetDsRecords(ctx, zone) ([]string, error)` | 取得要交給註冊商的 DS 記錄 |
| `SignZone(ctx, zone) error` | 用區域的金鑰為它簽章 |

#### DANE / ACME

| 方法 | 說明 |
|------|------|
| `GenerateTlsaRecord(ctx, opts) (string, error)` | 從一張憑證產生一筆 TLSA 記錄 |
| `ListTlsaRecords(ctx, domain) ([]*DnsRecord, error)` | 列出某個網域的 TLSA 記錄 |
| `GenerateDaneRootCa(ctx, name) (string, error)` | 產生一張自簽的 DANE 根憑證機構憑證 |
| `RequestAcmeCert(ctx, domain, providerURL) error` | 請求一張 ACME DNS-01 憑證 |
| `GetAcmeStatus(ctx, domain) (*AcmeStatus, error)` | 取得 ACME 憑證狀態 |
| `EnsureZoneCa(ctx, zone) (*ZoneCa, error)` | 確保逐區域的中繼憑證機構存在 |
| `CreateEabCredential(ctx, zone) (*EabCredential, error)` | 鑄造一份限定於某區域的 EAB 憑據 |
| `RemoveEabCredential(ctx, kid) error` | 移除一份 EAB 憑據 |
| `ListAcmeAccounts(ctx) ([]*AcmeAccount, error)` | 列出已註冊的 ACME 帳號 |
| `ListAcmeCertificates(ctx, zone) ([]*AcmeCertificate, error)` | 列出已簽發的憑證 |

#### TTL 漂移

| 方法 | 說明 |
|------|------|
| `SetTtlDriftConfig(ctx, config) error` | 設定 TTL 漂移 |
| `GetTtlDriftConfig(ctx) (*TtlDriftConfig, error)` | 取得 TTL 漂移設定 |

#### DNS64

| 方法 | 說明 |
|------|------|
| `SetDns64Config(ctx, config) error` | 設定 DNS64 合成 |
| `GetDns64Config(ctx) (*Dns64Config, error)` | 取得 DNS64 設定 |

#### 可觀測性

| 方法 | 說明 |
|------|------|
| `GetQueryLatencyStats(ctx) ([]*QueryLatencyStats, error)` | 取得逐伺服器的延遲統計 |

#### 連線

| 方法 | 說明 |
|------|------|
| `Close() error` | 關閉 gRPC 連線 |

### 記錄型別

| 常數 | 值 | 說明 |
|------|----|------|
| `RecordTypeA` | 0 | IPv4 位址（預設） |
| `RecordTypeAAAA` | 1 | IPv6 位址 |
| `RecordTypeCNAME` | 2 | 正式名稱別名 |
| `RecordTypeMX` | 3 | 郵件交換（使用 Priority） |
| `RecordTypeTXT` | 4 | 文字記錄 |
| `RecordTypeNS` | 5 | 名稱伺服器 |
| `RecordTypeSOA` | 6 | 授權起始 |
| `RecordTypeSRV` | 7 | 服務定位（使用 Priority） |
| `RecordTypePTR` | 8 | 反向 DNS 指標 |
| `RecordTypeURI` | 9 | URI 資源記錄（RFC 7553） |
| `RecordTypeSSHFP` | 10 | SSH 指紋（RFC 4255） |
| `RecordTypeDNAME` | 11 | 委派名稱（RFC 6672） |
| `RecordTypeANAME` | 12 | 別名（區域頂點 CNAME 的替代方案） |
| `RecordTypeZONEMD` | 13 | 區域訊息摘要（RFC 9156） |
| `RecordTypeTLSA` | 14 | TLS 憑證關聯（RFC 6698） |
| `RecordTypeDNSKEY` | 15 | DNSSEC 公鑰 |
| `RecordTypeDS` | 16 | DNSSEC 委派簽署者 |
| `RecordTypeRRSIG` | 17 | DNSSEC 資源記錄簽章 |
| `RecordTypeNSEC` | 18 | DNSSEC 下一個安全記錄 |
| `RecordTypeNSEC3` | 19 | DNSSEC 下一個安全記錄 v3 |
| `RecordTypeNSEC3PARAM` | 20 | DNSSEC NSEC3 參數 |
| `RecordTypeCERT` | 21 | 在 DNS 中儲存憑證（RFC 4398） |

## RFC 相容性

| RFC | 名稱 | 支援程度 |
|-----|------|----------|
| RFC 1034 / 1035 | 網域名稱——概念與實作 | 從根伺服器開始的迭代解析、委派跟隨、黏合與無黏合記錄的 NS 處理 |
| RFC 2308 | DNS 查詢的否定快取 | 否定 TTL 取 `min(SOA MINIMUM, SOA TTL)`，並照發佈的原樣採用 |
| RFC 4033 / 4034 / 4035 | DNSSEC 協定、記錄與協定修改 | 區域簽章（對正規化 RRset 的 RRSIG、KSK/ZSK 角色、DS 計算）與上游驗證（自根起的信任鏈、四種判定、AD/DO 處理）。NSEC/NSEC3 只驗證、絕不產生 |
| RFC 4255 | SSHFP DNS 記錄 | 完整（儲存、查找、演算法／指紋型別） |
| RFC 4398 | CERT DNS 記錄 | 完整（儲存、查找、PKIX 憑證鏈散佈） |
| RFC 4592 | DNS 中的萬用字元 | 完整（單一標籤替換、精確比對優先） |
| RFC 5155 | DNSSEC 雜湊式認證否定（NSEC3） | 僅驗證（最近封閉者、opt-out、依 RFC 9276 的迭代次數上限）；絕不產生 |
| RFC 5782 | DNSBL | 完整（以名稱為基礎的查詢格式、本地 + 外部供應商、`127.0.0.1` 絕不被讀成列入） |
| RFC 6147 | DNS64 | 完整（從 A 記錄合成 AAAA、前綴可設定） |
| RFC 6605 / 8080 | DNSSEC 的 ECDSA 與 Ed25519 | 完整（簽章與驗證；`ring` 不支援 Ed448） |
| RFC 6672 | DNAME | 完整（子樹改寫，不作用於擁有者名稱本身） |
| RFC 6698 | DANE TLSA | 完整（TLSA 記錄產生、儲存、DNS 解析） |
| RFC 6840 | DNSSEC 澄清 | 只能以不支援演算法驗證的答案視為 Insecure（§5.11）；AD 只為有詢問的用戶端設置（§5.7） |
| RFC 6891 | EDNS(0) | 完整（OPT 記錄、酬載協商、DO 位元、BADVERS）。啟用驗證時，對外的迭代查詢會帶著 DO 與 1232 位元組的酬載 |
| RFC 7553 | URI DNS 記錄 | 完整（儲存與查找） |
| RFC 7766 | TCP 上的 DNS 傳輸 | 連線重用，閒置逾時從最後一次活動起算、2 位元組長度框架、逐監聽器的連線上限 |
| RFC 7858 | DNS-over-TLS | 完整（以 TLS 封裝的 TCP，853 埠）——伺服器監聽器與上游用戶端 |
| RFC 8484 | DNS-over-HTTPS | 完整（GET + POST、application/dns-message、Cache-Control）——伺服器監聽器與上游用戶端 |
| RFC 8555 | ACME | 伺服器端（內建憑證機構、dns-01 自我驗證、EAB） |
| RFC 9250 | DNS-over-QUIC | 完整（QUIC 傳輸、雙向串流） |
| RFC 9276 | NSEC3 參數指引 | 迭代次數超過 100 時視為非安全而不去計算 |

## 架構

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

解析順序（未設定任何網路範圍時）：
1. 剖析 EDNS OPT 記錄（酬載大小、DO 位元）
2. 檢查本地封鎖清單（針對反向 DNS 查詢）
3. 檢查 DNS 回應快取
4. 檢查本地資料庫（分割視域，一律優先）
5. 檢查本地資料庫中的 CNAME 記錄
6. 檢查 DNAME 記錄（子樹改寫）
7. 檢查 ANAME 記錄（在區域頂點解析別名）
8. 若名稱位於某個受管區域之下卻找不到，回傳權威 NXDOMAIN
9. 檢查萬用字元記錄
10. 檢查本地封鎖清單與 DNSBL 供應商（已列入則 NXDOMAIN，優先於任何外部答案）
11. 強制執行 `security.recursion_cidrs`——不在其中的來源會在任何東西離開本機之前就被 REFUSED
12. 依 `resolution.mode` 向外解析（若已啟用則隨機化 QNAME 大小寫，若有設定則經由代理），並在迭代路徑上驗證 DNSSEC
13. 套用 DNS64 AAAA 合成（若已啟用且適用）
14. 快取回應（偽造的答案永不快取）
15. 套用 TTL 漂移調整（若有設定）
16. 丟棄屬於主機無法路由之位址族的 A/AAAA 答案（若 `address_family.mode: auto`）

若有設定網路範圍，延伸的解析順序請見[網路範圍劃分](#網路範圍劃分)。

## 授權

本專案以 GNU Affero General Public License v3.0（AGPL-3.0）授權。完整授權條款請見 [LICENSE](LICENSE) 檔案。
