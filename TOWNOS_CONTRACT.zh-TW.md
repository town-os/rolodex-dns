# Town OS 契約

> 語言：[English](TOWNOS_CONTRACT.md) | **繁體中文** | [简体中文](TOWNOS_CONTRACT.zh-CN.md) | [Español (España)](TOWNOS_CONTRACT.es-ES.md) | [Español (México)](TOWNOS_CONTRACT.es-MX.md) | [日本語](TOWNOS_CONTRACT.ja-JP.md)

這是 rolodex 與 Town OS 之間、雙向跨越邊界的所有事物的權威清單。

**方向與 gfeh 相反。** gfeh 是 Town OS 的用戶端；rolodex 則是被 Town OS 驅動的東西。Town OS 的 systemcontroller 是 rolodex 的 gRPC 用戶端，`../install` 映像檔負責寫出 rolodex 的啟動設定檔，而 ttyforce 則寫出決定 rolodex 能發現什麼的網路設定。因此接下來的內容大多是**那三方對 rolodex 可以做出的假設**，以及一小段 rolodex 反過來要求的東西。

**這裡沒有任何東西被釘在某個修訂版上。** `make check-townos-sync` 在執行的當下解析這台機器上實際存在的檢出。一個沒有任何腳本會讀的已記錄修訂版，是一個沒有人在維護的主張；而釘住版本會在那些根本沒改到 rolodex 所依賴之處的 Town OS 提交上大聲失敗——兩邊最糟的那一面。

| 指令 | 檢查對象 | 會略過嗎？ |
|---|---|---|
| `make check-townos-sync` | 本機檢出（`TOWNOS_DIR=`、`INSTALL_DIR=`） | 會，若不存在 |

它會作為 `make lint` 的一部分執行，因此日常開發免費得到這道檢查，而且在一台只有這個儲存庫的機器上仍然可用。

### 這道檢查實際驗證了什麼

光有名稱是不夠的——一個仍然存在但位置移動了的常數，正是那種在這裡保持綠燈、卻在機器上壞掉的失敗。這道檢查比對：

- **Town OS 的 `Client` 介面所宣告的每一個方法，都存在於 rolodex 自己的 Go 用戶端（`go/client.go`）上。** 那個——而不是 proto——才是 Town OS 綁定的介面：它自己的 `client` 結構直接委派給這個儲存庫的 Go 套件。其中有些方法是便利包裝而非獨立的 rpc（`AddScopeTldWithListener` 就是設了 `listen_ip` 的 `AddScopeTld`），所以只看 proto 的檢查會回報不存在的偏移，同時漏掉被移除的包裝，而後者才是真正的偏移。
- **兩個剖析器裡的轉發器 scheme 集合完全相同**——這裡的 `src/forwarder.rs` 與那裡的 `src/rolodex/forwarder.go`。在兩個彼此看不見的儲存庫裡，用手寫的兩個剖析器去剖析同一套文法，是這份文件裡最新、也最沒有防護的東西。
- **三個儲存庫裡的固定位址彼此一致**：DoH 後端、metrics 監聽器、rolodex 綁定的 loopback，以及 TLS 目錄，分別作為一個 Go 常數、安裝腳本裡的一個字面值，以及這裡的一個預設值。

## 範圍

三個對口，而且它們並不能互換：

1. **Town OS（`../town-os`）**——systemcontroller。透過 gRPC 程式設定 rolodex 的*設定*，並抓取它的 metrics。它不寫任何設定檔。
2. **安裝映像檔（`../install`）**——`scripts/rolodex-config.sh` 寫出 `rolodex.yml`，除此之外沒有別的寫入者。它只承載那些無法在執行中的 rolodex 上設定的東西。
3. **ttyforce（`~/src/github.com/erikh/ttyforce`）**——寫出 networkd 單元。它出現在這裡，只是因為它的某個選擇（`UseDNS=no`）決定了 Town OS 的轉發器發現能找到什麼，而這件事從任何一邊看都不明顯。

沒有別的東西跨越這道邊界。尤其是：

- **rolodex 從不呼叫 Town OS。** 沒有 HTTP 用戶端、沒有帳號查詢、沒有儲存呼叫。所有東西都是流進來的。
- **rolodex 不寫任何 Town OS 會讀的檔案。** 它的資料庫是它自己的；gRPC socket 與 metrics 端點就是全部的對外表面。

## `rolodex.yml` 只用於啟動，而且兩個儲存庫必須一起移動

`../install` 裡的 `scripts/rolodex-config.sh` 是唯一的寫入者。它只承載那些無法在執行中的伺服器上設定的東西：

| 鍵 | 為何無法被程式設定 |
|---|---|
| `dns.bind` | 監聽器必須在任何 API 呼叫能夠抵達之前就存在 |
| `metrics.bind` | rolodex 只在啟動時依該節的存在把那個監聽器打開一次 |
| `doh` / `dot` / `doq` | 依各節的存在，在啟動時只打開一次 |
| `database_path`、`grpc` | 在伺服器存在之前就被讀取 |
| `forwarders`、`resolution.mode` | 只是啟動**預設值**——systemcontroller 會透過 gRPC 程式設定操作者真正的選擇 |

**serde 會直接拒絕未知或缺少的欄位。** 一個在該映像檔修訂版上是必需、卻不存在於檔案裡的欄位——或者存在於檔案裡、但該映像檔不認得的欄位——都會在啟動時變成一個硬性的 `failed to parse config file`，而在 `Restart=always` 之下那就是一個崩潰迴圈，且整台機器上的所有東西都沒有 DNS。這已經發生過一次，就在 `rbl` → `dnsbl` 的更名上。

由此得出的規則：**安裝儲存庫的 `rolodex-config.sh` 與已發佈的 rolodex 映像檔必須一起移動。** 在這裡改了一個設定鍵的名字、而那裡沒有對應的變更，得到的是一台壞掉的機器，而不是一個失敗的測試。Town OS 裡的 `TestRolodexDohBackendMatchesTheInstallScript` 只抓得到其中一個方向，而且只在 `../install` 有被檢出時才抓。

## 設定只存在於記憶體中

rolodex **不會**持久化任何透過 gRPC 設定的東西。它在啟動時從 `rolodex.yml` 取得種子，其餘全部留在記憶體裡，所以在 `Restart=always` 之下的一次崩潰、一次讓該單元重啟的 DHCP 租約變更，或是操作者手動重啟，都會讓 Town OS 推送過的每一項設定退回啟動預設值。

因此 Town OS 的義務是：**每次重啟之後都要重新推送。** `ProgramRolodex` 以 15 秒為週期執行，並透過 `Manager.Generation`——也就是 rolodex 在啟動時綁定的那個 gRPC socket 的識別（裝置、inode、修改時間）——察覺重啟。rolodex 裡沒有任何東西會宣告自己重啟了；socket 的識別就是那個訊號。

有兩個後果值得明講：

- **一次完全相同的重新推送必須是免費的。** `SetForwarders` 與封鎖清單的設定器都是單純的存放——沒有快取清空、沒有上游重新連線——正是為了讓那個週期可以無條件推送而不必比對差異。`SetResolutionMode` 就*不是*免費的（切換進 `auto` 會重啟層級探索），這也是為什麼 Town OS 會把它對照 `GetResolutionMode` 做差異比對，只在真的改變時才推送。
- **逐轉發器的健康狀態必須撐過那個週期。** 一個由被推送的清單所擁有的斷路器，會每 15 秒就被重設一次——比三次失敗能夠讓它跳脫還要快——所以 `forwarder::carry_health` 會依標籤把健康狀態移到替換後的清單上。這完全是由 Town OS 的推送節奏所造成的、rolodex 這一側的義務，也是為什麼轉發器的標籤是穩定的而不是裝飾性的。

## 轉發器規格文法

**兩個手寫的剖析器、一套文法，而且它們之間沒有任何產生出來的程式碼。** 這裡的 `src/forwarder.rs` 與 Town OS 裡的 `src/rolodex/forwarder.go` 接受相同的字串；這兩個儲存庫彼此看不見，而且在建置期沒有任何東西把它們綁在一起。`make check-townos-sync` 會比對 scheme 集合，而兩邊的單元測試也刻意釘住相同的案例。請把那當成僅有的防護。

`SetForwarders` 取用的仍然是 `repeated string`，沒有改變，所以這套文法是搭在既有的線路型別上：

| 規格 | 傳輸 |
|---|---|
| `8.8.8.8:53` | 明文 UDP（Do53） |
| `tcp://8.8.8.8:53` | 明文 TCP（RFC 7766） |
| `tls://cloudflare-dns.com@1.1.1.1:853` | DoT（RFC 7858） |
| `https://cloudflare-dns.com@1.1.1.1/dns-query` | DoH（RFC 8484） |
| `quic://dns.adguard.com@94.140.14.14:853` | DoQ（RFC 9250） |

Town OS 那一側精確依賴的性質：

- **裸的 `ip:port` 就是明文 UDP。** 每一個在傳輸尚不可命名之前寫下的呼叫端都能繼續運作，而 scheme 是呼叫端為了要求別的東西才加上去的。`udp://` 與裸寫形式會剖析成同一個轉發器，並帶有相同的 metrics 標籤。
- **位址永遠是字面值，絕不是主機名稱。** `name@ip` 在單一字串裡同時攜帶了要撥接的位址，以及要用來驗證憑證的名稱。這就是那個開機自舉的性質：一個必須先被解析才能用的加密上游，不可能成為那個修好一台沒有可用 DNS 的機器的東西。
- **轉發器落在哪一層是 rolodex 的決定，不是 Town OS 的。** 它是從轉發器本身推導出來的——先加密，然後明文私有，然後明文公開——所以 Town OS 不可以用排序這份清單來表達偏好，也不可以假設它送出的順序就是被嘗試的順序。
- **驗證是全有或全無。** `SetForwarders` 會替換整份清單，所以 rolodex 會在套用其中任何一項之前先剖析每一項，而 Town OS 則在推送之前先驗證。一份被接受、但其中一項被丟掉的清單，會讓解析器持有某個沒有人要求過的東西。

**加密上游只能透過這份清單被程式設定。** `rolodex.yml` 裡的 `resolution.secure_upstreams` 沒有 gRPC 設定器，而且只在啟動時被讀取一次。在這份清單被型別化之前，那意味著在一個過濾對外 `:53` 的網路上唯一能運作的層級，同時也是那個不重啟整台機器唯一的解析器就無法重新設定的層級——而那個*可以*被程式設定的層級，卻只能承載這種網路正好會丟掉的明文位址。

## 固定位址

以下每一項都被寫在不只一個儲存庫裡，而且每一對都至少錯過一次：

| 值 | rolodex | Town OS | `../install` |
|---|---|---|---|
| `127.0.0.2` | `dns.bind` 的第一項 | `rolodex.DNSLoopback` | `add_bind 127.0.0.2` |
| `127.0.0.2:9153` | `metrics.bind` | `rolodex.DefaultMetricsPort` | `metrics.bind` 字面值 |
| `127.0.0.2:4443` | `doh.bind` | `systemcontroller.RolodexDohBackend` | `doh.bind` 字面值 |
| `/data/tls/dot` | `dot`／`doq` 的 `cert_path` | `systemcontroller.RolodexTLSSubdir` | `ENC_CERT` / `ENC_KEY` |
| `/data/rolodex.sock` | `grpc.unix_socket` | `Config.UnixSocketPath` | `unix_socket` 字面值 |

用 `4443` 而不是 `443` 是有承重作用的：ingress 發佈在 `0.0.0.0:443` 上，而 rolodex 以 `--net host` 執行，所以在同一個命名空間裡同時有一個萬用的 `:443` 與一個特定的 `127.0.0.2:443`，對後綁定的那一個來說就是 `EADDRINUSE`——DNS 或 ingress 會有一個掛掉，取決於開機順序。

用 `127.0.0.2` 而不是 `127.0.0.1`，可以避開 systemd-resolved 在 `127.0.0.53` 上的 stub 以及 `127.0.0.1` 上的任何其他東西；它同時也是 `bootstrap-dns.sh` 把 resolved 指向的位址，因此它是這台機器自身的解析少了就無法運作的那一個綁定。

### DoH 後端掛掉時，ingress 會端出什麼

Town OS 把 `127.0.0.2:4443` 當成一個普通 ingress vhost 上的 path backend 擺在前面，而那個 ingress 現在會對一個連不上、或是回傳了 `5xx` 的後端給出它自己的重試頁面：一個說明服務不可用、並每五秒自行重新載入的 `503`，而不是 Caddy 光禿禿的 `502`。rolodex 重新啟動的那幾秒，正是它上場的時候。

**它以請求為閘門，而 DoH 客戶端永遠不會命中這道閘門。** 該頁面只提供給 `Accept` 中帶有 `text/html` 的 `GET`／`HEAD` 請求。RFC 8484 的客戶端送出的是 `application/dns-message`，而且十有八九用的是 `POST`，因此：

- rolodex 回傳的 `5xx` 會原樣抵達客戶端——狀態碼、內文與回應標頭都被照抄過去；
- 沒有在監聽的 rolodex，會由 ingress 給出帶 `Retry-After` 的 `503`，而不是 `502`。

後者是這條路徑上唯一可觀測的變化，而且是 rolodex 從自己這一側看不到的變化——因為它發生在 rolodex 沒有運行的時候。之所以記在這裡，是因為「解析器重新啟動期間 DoH 客戶端拿到什麼」是一個 Town OS 的決定，而它浮現出來的形態是一份 rolodex 的問題回報。

**具有契約性質的是那道閘門，而不是它後面的頁面**：Town OS 那側若有改動丟掉了 `Accept` 判斷，`/dns-query` 就會開始以 HTML 頁面作答，而這台機器上的每一個 DoH 客戶端都會去解析一份從未送給它的 DNS 封包。

## Metrics

rolodex 在 `127.0.0.2:9153` 上提供 Prometheus 文字輸出，依 `metrics` 這一節的存在，在啟動時只打開一次。Town OS 是從 `rolodex.Manager.MetricsAddr()` 設定抓取目標，而不是從某個預設值重新組出來，因此目標與綁定不可能漂移。

Town OS 的監控所依賴的兩個性質：

- **每個標籤維度都是有界的。** 一個固定的列舉，或者由設定加以限界。任何由用戶端控制的東西都會折進一個總括值（查詢型別用 `OTHER`，TLD 用 `other`）。**查詢名稱永遠不會成為標籤。** `upstream_queries_total{server}` 與 `upstream_skipped_total{server}` 由已設定的轉發器清單加以限界。
- **新的標籤值只會被附加，絕不插入。** 那些 `BLOCK_*` 形式的常數是預先配置陣列裡的位置；一次插入會悄悄地把每一個既有的計數器都重新貼上標籤。

新增或更名一個 metric，就意味著要更新 `README.md` 與 `DESIGN.md` 裡的系列數量以及受影響的查詢——`tests/promql_docs_test.rs` 會把文件中記載的數量釘在登錄表實際輸出的東西上。

## Town OS 必須做到：不要重新排序，也不要假設是 Do53

有兩件事是 Town OS *不可以*做的，而這兩件事過去都是安全的：

- **不要為了表達偏好而排序或重排轉發器清單。** 一個層級內的順序是被尊重的——那是 rolodex 嘗試的次序——但層級本身是推導出來的。一份被 Town OS 依「加密優先」排過的清單，最好的情況是多餘，而如果那個排序與 rolodex 的推導不一致，就會在日誌裡造成誤導。
- **不要假設一個轉發器就是 `ip:port`。** `Manager.Forwarders` 可能回傳一個帶 scheme 的規格。任何用 `:` 去切開一個轉發器以取回主機與埠的做法，對 `tls://name@ip:853` 是錯的，對 IPv6 字面值則是災難性的錯誤。

## Town OS 必須做到：DHCP 解析器無法從 resolv.conf 被發現

這是唯一一處，Town OS／ttyforce 的某個選擇會悄悄地讓一個面向 rolodex 的功能失效；記錄在這裡，是因為單獨看任何一邊都沒有錯。

- ttyforce 在它的 networkd 單元上寫下 `[DHCPv4] UseDNS=no`（以及 v6 的對應項），因此 DHCP 提供的解析器永遠不會變成一個會蓋過 rolodex 的逐鏈路解析器。
- `../install` 裡的 `bootstrap-dns.sh` 只要 rolodex 是活著的，就會把 systemd-resolved 指向 `127.0.0.2`。
- `/etc/resolv.conf` 是 resolved 自己的 `127.0.0.53` stub。

這三者全都是 loopback 或根本不存在，而且三者都正確地被當成查詢迴圈丟棄。所以 Town OS 的 `HostResolversFrom` 在一台執行中的機器上什麼也**找不到**，而它的本地轉發器發現必須去讀 `/proc/net/route` 裡的**預設閘道**才能找到任何東西。閘道之所以倖存，是因為它來自 DHCP 租約的 *router* 選項，而不是它的 DNS 選項。

任何改動那三個選擇之一的事情，都會改變發現能找到什麼。要嘛一起改，要嘛都別改。

## 已知的分歧

記錄下來，免得有人是靠除錯才發現：

- **rolodex 的 gRPC 表面遠大於 Town OS 所使用的部分。** proto 宣告了完整的管理 API；Town OS 的 `Client` 介面只是其中的一個子集。這道檢查驗證的是 Town OS 宣告的每一項都存在於這裡，而不是反過來——一個沒有任何 Town OS 用戶端會呼叫的 rpc 並不算偏移。
- **`shared_secret` 是空的，而認證靠的是檔案系統權限。** 安裝腳本寫下 `grpc.tcp_bind: ""` 與一個 Unix socket，所以那個 socket 的模式就是全部的存取控制。一個 TCP 綁定會需要那個祕密，而 Town OS 裡沒有任何東西會設定它。
- **`GetForwarders` 並不存在。** Town OS 是無條件推送的，無法讀回 rolodex 實際持有的東西。這正是為什麼 `GET /dns/status` 回報的是 Town OS *將會*程式設定的東西，而不是 rolodex 已經擁有的東西。
- **Scope／TLD 轉發器是另一份清單。** `SetScopeTldForwarders` 是逐範圍的對等轉發，並不是全域的轉發器清單；它是單純的 `ip:port`，不接受上面那套傳輸文法。

## 保持同步

Town OS 是以逐架構的容器映像檔發佈的，沒有語意化版本，因此一個提交修訂版是唯一精確的同步單位——而且這裡刻意**沒有釘住版本**。

**每當有變更觸及 gRPC 表面、轉發器文法，或任何一個固定位址時：**

1. 在 `TOWNOS_DIR` 與 `INSTALL_DIR` 指向那些檢出的情況下執行 `make check-townos-sync`。
2. 任何失敗都要藉由同時更新另一側**與**這份文件來調和——絕不只更新其中一邊。
3. 如果該變更更名或移除了一個 `rolodex.yml` 的鍵，那麼安裝腳本與已發佈的映像檔必須一起出貨。沒有任何版本交握能抓到這件事。
