# Rolodex DNS 設定指南

這是一份任務導向的逐步說明：先讓伺服器跑起來，再逐一開啟各子系統，並說明你為什麼會想開它。完整的欄位清單請見 README 的[設定選項](README.zh-TW.md#設定選項)。

> 語言：[English](CONFIGURATION.md) ｜ **繁體中文** ｜ [简体中文](CONFIGURATION.zh-CN.md) ｜ [Español (España)](CONFIGURATION.es-ES.md) ｜ [Español (México)](CONFIGURATION.es-MX.md) ｜ [日本語](CONFIGURATION.ja-JP.md)

- [設定如何載入](#設定如何載入)
- [最小可用設定](#最小可用設定)
- [綁定位址](#綁定位址)
- [部署形態](#部署形態) — 四個實作範例
- [子系統](#子系統) — 每個一節
- [執行期變更與需要重啟者](#執行期變更與需要重啟者)
- [伺服器拒絕啟動的情況](#伺服器拒絕啟動的情況)
- [疑難排解](#疑難排解)

## 設定如何載入

伺服器讀取一個 YAML 檔，預設為 `rolodex-dns.yml`：

```bash
rolodex-dns                        # 讀取 ./rolodex-dns.yml
rolodex-dns -c /etc/rolodex-dns/config.yml
```

**檔案不存在並不是錯誤。** 伺服器會記錄 `No config file found, using defaults` 並以內建預設值啟動——那是一組真正可用的設定：DNS 監聽 `0.0.0.0:53`、從根伺服器開始的迭代解析並啟用 DNSSEC 驗證、gRPC 監聽 loopback 與一個 Unix socket、封鎖清單關閉、加密傳輸關閉。

每個區段都是選用的，區段中每個欄位都有預設值，所以設定檔只需要寫出你要更改的部分。那些以「是否出現」作為開關的區段——`dot`、`doh`、`doq`、`proxy`、`dhcp`、`acme`、`metrics`——省略時就什麼都不會啟動。

日誌由 `RUST_LOG` 環境變數控制，不在設定檔內：

```bash
RUST_LOG=rolodex_dns=debug rolodex-dns -c /etc/rolodex-dns/config.yml
```

## 最小可用設定

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""          # 只透過 socket 管理
```

這就是一台具備本地記錄資料庫、會做驗證的遞迴解析器。透過 socket 新增記錄：

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  --name nas.example.com --record-type a --value 192.168.1.10
```

連接埠 53 需要特權。開發時請用高位連接埠——`make dev` 會依 `dev.yml` 跑在 `127.0.0.1:5300`——正式環境請給執行檔 `CAP_NET_BIND_SERVICE`，或透過你的服務管理器代為綁定，而不要以 root 執行。

## 綁定位址

所有接受位址的地方（`dns.bind`、`dot.bind`、`doh.bind`、`doq.bind`、`grpc.tcp_bind`、`dhcp.bind`、`acme.bind`、`acme.portal_bind`、`metrics.bind`）都接受四種寫法：

（`dns.bind` 收的是一串「協定／位址」配對，而 `dot.bind`、`doh.bind` 與 `doq.bind` 既收**單個位址也收一個清單**——清單是一個監聽器同時涵蓋兩個位址族的辦法，因為 `0.0.0.0` 只管 IPv4，而 `[::]` 的通訊端會在同一個埠上與它相撞。其餘的都只收單個位址。）

| 寫法 | 範例 | 結果 |
| ---- | ---- | ---- |
| `ip:port` | `192.168.1.1:53` | 在該位址上建立一個監聽器 |
| `[ipv6]:port` | `[::1]:53` | 一個監聽器；方括號為必要 |
| `primary:port` | `primary:53` | 作業系統預設路由的出向 IP，於啟動時偵測 |
| `interface:port` | `eth0:53` | **該介面上每個 IP 各建一個監聽器** |

`primary` 是以一次不送出資料的 UDP connect 朝 `8.8.8.8:53` 解出來的——它只是向路由表詢問會用哪個來源位址，實際不送出任何封包。`interface:port` 會展開成該介面上被指派的每一個位址，所以在雙協議堆疊主機上 `eth0:53` 會建立兩個監聽器。

`dns.bind` 是一串單鍵映射，因為一個監聽器同時是協定**與**位址：

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - tcp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "127.0.0.1:53"
```

以介面為基礎的綁定是在**啟動時**解析的，之後不會重新解析。開機後才取得位址的介面（例如稍後才拉起的 WireGuard 通道）在重啟前不會被納入——這正是為什麼各 TLD 的入口監聽器可以在執行期重新註冊，見[專屬 TLD 與入口](#專屬-tld-與入口)。

## 部署形態

### 1. 家用／小型辦公室解析器

會做驗證、封鎖廣告與惡意程式、提供少量本地名稱，且僅限區域網路可達。

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  auto_ptr: true                # 讓反向 PTR 與 A/AAAA 記錄保持同步

resolution:
  mode: auto                    # 先走根伺服器，再走加密上游，最後才是 ISP 的解析器

dnssec:
  validate: true                # 這是預設值；寫在這裡是因為它很重要

dnsbl:
  enabled: true
  providers:
    - zone: dbl.spamhaus.org
      enabled: true

security:
  # 預設值已涵蓋 RFC 1918；若你的區網只是其中一部分，可以再縮小
  recursion_cidrs: ["127.0.0.0/8", "192.168.0.0/16", "::1/128"]

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""

metrics:
  bind: "127.0.0.1:9153"
```

關於這些選擇的說明：`resolution.mode: auto` 表示只要根伺服器可達，就沒有第三方看得到你的查詢，而在會過濾 `:53` 的網路上解析仍能存活。`recursion_cidrs` 是讓 `0.0.0.0:53` 綁定不至於變成開放解析器的關鍵——預設清單本身已經安全，把它縮小到你自己的網段是一種精修，而非必要。

### 2. 純權威伺服器

完全不做上游解析：每個答案都來自本地資料庫，找不到的一律回權威 NXDOMAIN。

```yaml
database_path: /var/lib/rolodex-dns/auth.db

forwarders: []
resolution:
  mode: forward                 # forward 模式且沒有轉送器 = 沒有上游

dnssec:
  validate: false               # 沒有任何東西是從上游解析來的，也就沒有東西要驗證

security:
  recursion_cidrs: []           # 雙重保險：對所有人關閉遞迴

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
```

`forwarders: []` 搭配 `mode: forward` 就是那個開關。`recursion_cidrs: []` 與它重複，但它把意圖寫了出來，同時也關掉封鎖清單供應商查詢與快取預熱這兩條路徑。

宣告你擁有權威的區域，讓區域內找不到的名稱回 NXDOMAIN，而不是變成一次無處可去的查找：

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-auth-zone --zone example.com.
```

（任何**已經有**記錄的區域會自動被視為權威——見[受管區域與權威區域](#受管區域與權威區域)。）

### 3. 分割視域疊加節點（Town OS 形態）

這台機器同時位於區域網路與 WireGuard 疊加網路上。疊加網路的對等節點被分隔進各個網路範圍；區域網路則看得到全部。

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  ingress_listen_port: 53

security:
  overlay_cidrs: ["10.64.0.0/10"]     # 這些來源會被強制套用範圍
  recursion_cidrs:                    # 這些來源可以做上游解析
    - "127.0.0.0/8"
    - "10.0.0.0/8"                    # 包含疊加網路
    - "192.168.0.0/16"
    - "::1/128"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""
```

這兩份 CIDR 清單回答的是**不同的問題**，也應該各自獨立設定：

- `overlay_cidrs`——「誰會被強制套用範圍？」清單內的來源必須已加入某個網路（`JoinNetwork`），否則就是 REFUSED，而且它只看得到自己範圍的 TLD。
- `recursion_cidrs`——「誰可以讓這台伺服器去問別人？」清單外的來源仍然拿得到你的權威資料，只是不能驅動上游查找。

接著在執行期建立這些範圍，而不是寫在設定檔裡——它們存在資料庫中：

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI create-scope --name office                       # 隱含 office.home.
$CLI add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
$CLI add-scoped-record -s office --name git.office. --record-type a --value 10.64.0.5
$CLI join-network --ip 10.64.0.7 --scope office --ttl 300
```

### 4. 位於敵意／受過濾網路上的解析器

有些網路會丟棄對外的 `:53`，並以 DPI 攔截 `:853` 的 DoT 交握。`auto` 鏈就是為此而生，唯一值得調整的是它使用哪些加密上游：

```yaml
resolution:
  mode: auto
  secure_upstreams:
    - transport: https            # :443 上的 DoH——看起來就像普通 HTTPS
      addr: "1.1.1.1:443"         # 以 IP 撥接，因此不需要先有 DNS
      hostname: cloudflare-dns.com
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  switch_grace_failures: 3        # 降級生效前需要幾次偏離的查詢
  recovery_probe_secs: 60         # 已降級的鏈多久重試一次上層
```

安全上游是以 **IP** 撥接，並用 `hostname` 驗證憑證，所以這個層級啟動時不需要自己先做 DNS。請注意，一條已降到第 0 層以下的 `auto` 鏈**不會**經過 DNSSEC 驗證（轉送來的答案是別人的結論摘要），而它會以「不設定 AD 位元」如實表明這一點。

## 子系統

### 上游解析

```yaml
forwarders:                       # 即 "local" 層級，也是 forward 模式下唯一的上游
  - "8.8.8.8:53"
  - "8.8.4.4:53"

resolution:
  mode: auto                      # auto | recursive | forward
  root_hints: []                  # 覆寫內建的 IANA 根伺服器
  public_fallback: ["1.1.1.1:53", "8.8.8.8:53"]
  delegation_persist_min_ttl: 300 # TTL 高於此值的已學得委派才會持久化
  default_ttl: 300                # 「僅」在完全沒有任何 TTL 可用時才使用
```

| 模式 | 使用時機 |
| ---- | -------- |
| `auto`（預設） | 你以隱私為先，但解析必須能在受過濾的網路上存活 |
| `recursive` | 要嘛走根伺服器要嘛不解析——絕不接觸任何上游解析器 |
| `forward` | 你要的是單純的轉送器（或搭配 `forwarders: []`，完全不要上游） |

**這裡的 `mode` 是啟動時的種子，而不是正在生效的那個設定。** 它只在啟動時
讀一次；
從那以後，模式就是 `SetResolutionMode` 最後一次設定的那個，而 `GetResolutionMode`
回報的是真正在解析查詢的那個——所以兩者可能不一致，而以正在執行的伺服器為準。
`rolodex-dns-cli set-resolution-mode -m <mode>` /
`get-resolution-mode` 就是這兩個呼叫在命令列上的寫法。改檔案再重啟當然也行，
但重啟一台機器唯一的解析器，就是讓它上面的一切都斷一次 DNS——這正是那個 RPC
存在的全部理由。與檔案不同，該 RPC 會**拒絕**無法辨識的模式，而不是發出警告
再退回 `auto`。

`default_ttl` 是**後備值，不是下限**。存在的 TTL 一律照原樣採用，包括區域 SOA 的否定 TTL。如果你想縮短或延長實際的 TTL，那是 [TTL 漂移](#dns64ttl-漂移與位址族)，不是這個。

### DNSSEC

兩個彼此獨立的部分。**驗證**預設開啟且不需要任何設定：

```yaml
dnssec:
  validate: true
  trust_anchors: []        # 空值 = IANA 根金鑰
```

它只作用於迭代路徑（`recursive` 模式，以及 `auto` 的根伺服器層級），所以在 `forward` 模式下完全不起作用。偽造的資料會變成 SERVFAIL，且永不快取。只有在你有具體理由時才關掉它——例如一個你無法修復的壞掉的上游，或一套你還沒設定信任錨點的私有階層。

`trust_anchors` 採用 DNSKEY 的呈現格式，也就是 `dig DNSKEY .` 印出的那四個 RDATA 欄位；而且覆寫是**取代**IANA 金鑰，不是追加：

```yaml
dnssec:
  trust_anchors:
    - "257 3 15 <base64 key>"     # 一個私有根；IANA 將「不再」被信任
```

格式錯誤的錨點會導致啟動失敗，而不是退回 IANA——一個無法對上任何真實 DNSKEY 的錨點，會讓每個已簽章的區域都失敗，而且沒有任何線索指向錨點才是原因。

**簽章**完全不在 YAML 中設定；它是針對某個區域的執行期操作：

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
$CLI sign-zone --zone example.com.
```

變更記錄後請重新執行 `sign-zone`。簽章是被取代，而不是累積。RSA（演算法 8）在產生金鑰時就會被拒絕——`ring` 無法產生 RSA 金鑰——而經過認證的否定證明（NSEC/NSEC3）只會被驗證，永遠不會被產生。

### 安全性：兩份 CIDR 清單

```yaml
security:
  qname_case_randomization: true      # 對轉送查詢做 0x20 編碼
  overlay_cidrs: ["10.64.0.0/10"]     # 會被強制套用範圍的來源
  recursion_cidrs: [ ... ]            # 允許做上游解析的來源
```

把這兩者搞混是最常見的設定錯誤，所以直說：

| | `overlay_cidrs` | `recursion_cidrs` |
| --- | --- | --- |
| 問題 | 這個來源會拿到哪個**視域**？ | 這個來源可以讓我們去問上游嗎？ |
| 在清單內 | 必須已加入某個網路，否則 REFUSED；只看得到自己的範圍 | 可以驅動上游解析 |
| 在清單外 | 受信任的本機來源；使用全域命名空間 | 仍拿得到本地／權威答案；任何需要離開本機的都 REFUSED |
| 預設值 | `10.64.0.0/10` | loopback、RFC 1918、link-local、ULA、CGNAT |

除非你是要**縮小**它，否則不要動 `recursion_cidrs`。把它往公開網際網路放寬，等於把這台機器變成開放解析器，那就是一項反射／放大攻擊的資產，無論當下有沒有人正在濫用它。

`qname_case_randomization` 應該保持開啟。只有當某個上游會把它回送的問題名稱大小寫正規化時，才需要關掉它——否則這種解析器會讓每一次查詢都失敗，因為大小寫比對正是讓 0x20 真正具有防護力的機制。

### 封鎖清單（DNSBL）

**DNSBL 以名稱封鎖**，在任何外部解析之前檢查。它預設為停用且供應商清單為空，所以在你加入供應商之前，不會發出任何查詢，也不會把任何名稱交給封鎖清單營運方。

```yaml
dnsbl:
  enabled: true
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
```

位址是由**本地清單**封鎖的，而不是由供應商封鎖：供應商被問及的是正在解析的那個名稱，而在反向查找中，那是一個沒有人會為其發布信譽資料的名稱。見下面的本地項目。

開啟它們之前有三件事值得知道：

1. **本地記錄一律優先。** 封鎖清單在本地記錄與受管區域之後才執行，所以第三方的列入永遠不可能弄掉一個內部服務。它在回應快取與解析器**之前**執行，所以即使某個名稱先前已被快取，列入仍會生效。
2. **封鎖是逐一針對被查詢的名稱，而非針對後綴。** `doubleclick.net` 被列入並不會封鎖 `stats.g.doubleclick.net`——供應商必須把它也列進去。允許清單**則是**以後綴比對的，因為一個漏掉子網域的逃生口根本稱不上逃生口。
3. **量大時拒答碼很重要。** 封鎖清單告訴你「你超出配額了」時，用的是跟「已列入」同一種 `A` 記錄。拒答處理預設就會啟用，並帶有一組內建碼；唯一需要設定 `refusal_codes` 的理由，是某個私有封鎖清單的真實列入值恰好與其中之一相撞（`refusal_codes: ["none"]`），或你想縮小這組碼。見[拒答碼與供應商輪替](README.zh-TW.md#拒答碼與供應商輪替)。

本地項目與允許清單屬於執行期狀態，不是設定：

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI add-local-blocklist --name 10.0.0.5 --reason "known spam source"
$CLI add-dnsbl-allow --name vendor.example.com --reason "false positive"
$CLI add-dnsbl-allow --name 192.168.1.100 --reason "our own relay"   # IP 也可以
```

### 受管區域與權威區域

設定檔裡沒有區域清單。一個區域會透過以下兩種方式之一成為權威：

- **隱含地**，因為它有記錄。區域內任何位置的任何一筆記錄，都會讓這台伺服器對「整個區域」具權威——所以把 `foo.example.com` 加成本地覆寫，就意味著 `www.example.com` 會回 NXDOMAIN，而不是從網際網路解析。這就是分割視域的取捨，也值得刻意為之：只有在你真的打算擁有某個公開網域時，才去覆寫它。
- **顯式地**，用 `add-auth-zone`，這是你用來宣告一個尚無記錄的區域，或一個反向區域的方式（隱含規則刻意跳過 `in-addr.arpa`／`ip6.arpa`，因為那套啟發式在那裡會宣告整棵全球反向樹）。

### 加密傳輸

各區段是否出現就是開關，且每一個都需要 TLS 材料：

```yaml
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

doh:
  bind: "0.0.0.0:443"
  tls: { cert_path: /etc/rolodex-dns/cert.pem, key_path: /etc/rolodex-dns/key.pem, auto_self_signed: false }
  enable_h3: false

doq:
  bind: "0.0.0.0:8853"
  tls:
    auto_self_signed: true            # 在受信任網路上沒問題
    self_signed_sans:                 # 區網用戶端撥接這台機器所用的名稱
      - dns.home
      - town-os.local
```

`auto_self_signed: true`（預設值）會在沒有設定憑證時於啟動階段產生一張，這在受信任網路上很方便。

**更新後的憑證不需要重啟。** 一個以 `cert_path`／`key_path` 設定的監聽器每 30 秒重讀那些檔案，並在那個時間窗內開始提供新的一對——已經開啟的連線會在它交握時所用的憑證下走完，而下一條抵達的連線拿到新的。沒有東西要發訊號，也不需要和寫檔案的那一方協調：一次落在 ACME 用戶端兩次寫入之間的輪詢，會看到一把與憑證不相符的金鑰，拒絕它，繼續提供舊的那一對，並在下一個節拍重試。產生式（`auto_self_signed`）憑證不會被輪詢——它背後沒有檔案，而照計時器重新產生，等於每分鐘兩次遞給每個用戶端一張不同的憑證。

**可以指名一份尚未簽發的憑證。** 只有在 `auto_self_signed` 關閉時，把 `cert_path`／`key_path` 指向一個並不存在的檔案才是硬性失敗。開啟它之後，監聽器會先用產生的材料起步，而上面那次輪詢會在真正的那一對落地的當下把它接過去。正是這一點，讓這兩個路徑可以在簽發憑證的那個東西還沒跑之前就寫下去——在一台 CA 是在解析器啟動之後才被建立的機器上，那本來就是常態，而另一條路是等檔案出現之後再重啟這台機器唯一的解析器。

**DoT、DoH 與 DoQ 都可以在執行期重新設定**，經由 `SetDotConfig`／`SetDohConfig`／`SetDoqConfig`。綁定位址、憑證路徑與 SAN 清單都可以在一台執行中的伺服器上改動，而 `Get*Config` 回報的是實際綁定的內容。下面的 YAML 是啟動設定；它不是唯一的入口，伺服器起來之後它也不再是權威。

**HTTP/3 是第二個監聽器，而且預設關閉。** `doh.enable_h3` 會在 DoH 的位址與連接埠上以 UDP 開啟一個，並共用 TCP 監聽器的憑證。連接埠相同，是因為兩種探索機制都說它在那裡：對已經連線的用戶端，是每個 DoH 回應上的 `Alt-Svc` 標頭；對完全還沒連線過的用戶端，則是 DDR 指定記錄中的 `alpn=h2,h3`。失敗的 QUIC 綁定會讓整個傳輸失敗，而不是單獨留下 h2——一個承諾了 HTTP/3 卻提供 h2 的監聽器，是沒有任何用戶端看得見的失敗。

**如果一個 DoT 用戶端回報憑證名稱不符，那就是這個設定。** 一張產生出來的憑證涵蓋 `localhost`、`127.0.0.1`、`::1`，以及該監聽器自己的綁定位址——所以一個綁在 `192.168.1.5:853` 的監聽器，對一個撥接該位址的用戶端來說本來就能用，什麼都不必設定。它涵蓋不了的是這台機器回應的其他任何身分：它的主機名稱、它的 mDNS `.local` 名稱、區網用來稱呼它的某個 CNAME，或是某個 NAT 對外公布它的位址。那些寫進 `self_signed_sans`。一個綁在**萬用位址**上的監聽器（`0.0.0.0:853`，預設值）完全推導不出任何東西，因為 `0.0.0.0` 不是任何用戶端會撥接的身分——在萬用綁定上，那份清單就是唯一指名這台機器的東西。

這是一次名稱檢查，不是一個信任決定，而且它最先失敗。用戶端仍然必須被告知去信任那張憑證——把它釘選起來，或透過 DANE/TLSA 發布並檢查它——因為一張自簽憑證沒有信任鏈。一個什麼都不驗證的用戶端（`kdig +tls`、處於機會模式的 systemd-resolved）無論如何都不受影響。

### gRPC 管理

```yaml
grpc:
  tcp_bind: "127.0.0.1:50051"       # "" 停用 TCP
  unix_socket: /var/run/rolodex-dns.sock   # "" 停用 socket
  shared_secret: ""                 # 非 loopback 的 tcp_bind 必填
```

- **Unix socket 完全跳過認證**，所以它的檔案模式**就是**存取控制。它以 `0660` 建立（而非依 umask），因此請以 `chgrp` 把它指派給管理群組來授權，而不要放寬模式。
- **TCP 需要共用密鑰**，以定時比較進行核對，並在連續失敗後對該來源做鎖定。空的密鑰代表「不做認證」，這在 loopback 上沒問題，但在任何可路由位址上會在啟動階段被拒絕。
- 優先使用 socket。單主機部署建議的形態就是 `tcp_bind: ""` 搭配一個 socket 路徑。

### DHCP

區段出現即代表啟用；`tld` 為必填，也是主機名稱最終落腳的位置：

```yaml
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # 名為 "laptop" 的用戶端會註冊成 laptop.lan.example.com.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60
```

位址池屬於執行期狀態，並且是按網路範圍劃分的：

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1
```

一個位址池就是單一連續範圍，用盡時配置即失敗——不會跨池聚合。MAC 對 IP 的綁定是黏著的。用戶端提供的主機名稱必須是合法的單一 DNS 標籤（RFC 1123），否則註冊會被跳過並記錄警告；它是被拒絕而不是被清洗過，所以絕不會有東西被悄悄註冊成用戶端沒送出的名稱。

### ACME 簽發者與入口網站

區段出現即會在開機時建立根憑證機構，並啟動兩個監聽器：面向用戶端的 ACME 端點，以及註冊入口網站。

```yaml
acme:
  bind: "0.0.0.0:8555"
  portal_bind: "127.0.0.1:8500"                       # 僅限受信任網路
  directory_url: "https://dns.example.com:8555/acme"  # 請設定它——用戶端會看到這個
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  require_eab: true
  issuance_scope: managed_zones                       # 或 "any"
  tls: { auto_self_signed: true }
```

`directory_url` 是告訴 ACME 用戶端要去連的位址，因此必須是對外可達的 URL，而不是 `localhost`。**`portal_bind` 必須維持在受信任的位址上**——任何能連到入口網站的人都可以註冊。除非設定 `issuance_scope: any`，否則註冊會被限制在這台伺服器實際管理的區域內，而 `require_eab: true` 會讓帳號註冊必須先取得一份簽發出來的憑據。

### 指標

```yaml
metrics:
  bind: "127.0.0.1:9153"
```

預設不存在，所以升級不會開出新的連接埠。它是純 HTTP 且不做認證——只承載彙總計數，絕不含查詢名稱或記錄值——因此請把它綁在私有位址上。最值得先觀察的系列是 `rolodex_dns_answers_total{source}`（哪個階段回答的）、`rolodex_dns_dnssec_verdicts_total{verdict}` 與 `rolodex_dns_blocklist_rotated_out`。

### DNS64、TTL 漂移與位址族

```yaml
dns64:
  enabled: false
  prefix: "64:ff9b::"       # 眾所周知的前綴

ttl_drift:
  mode: disabled            # disabled | fixed | logarithmic
  fixed_adjustment: "5m"    # "5m"、"-30s"、"1h30m"、"2d12h"
  log_multiplier: 0.1

address_family:
  mode: auto                # auto | off | force4 | force6
  probe_interval_secs: 30
  fail_threshold: 2
```

`address_family: auto` 是預設值，通常也是你要的：它會以 TCP 連到公用解析器的 `:443`，測試**實際的**各位址族可達性，並針對主機無法路由的族抑制 A 或 AAAA 答案，讓用戶端改用另一族而不是卡住。用 `force4`／`force6` 可以不做探測直接釘住一族，用 `off` 則一律兩族都回答。

### 專屬 TLD 與入口

它們不算設定——存在資料庫裡並於執行期管理——但有兩個設定欄位與它們相關：

- `dns.ingress_listen_port`（預設 53）是每個 TLD 入口監聽器綁定的連接埠。IP 則是逐 TLD 指定的，用 `add-scope-tld --listen-ip` 給定。
- 入口監聽器會在開機時從資料庫重放。若疊加網路的介面尚未存在，綁定會失敗，該項目會被視為不存在，因此在通道拉起後重新加入該 TLD 就會重試綁定，不需要重啟。

## 執行期變更與需要重啟者

許多看起來像設定的東西其實是 SQLite 裡的執行期狀態，可透過 gRPC 變更且無須重啟：

| 可在執行期變更（gRPC/CLI） | 需要重啟 |
| ---- | ---- |
| 記錄、範圍內記錄、範圍、關聯 | `dns.bind` 以及所有其他綁定位址 |
| 權威區域、專屬 TLD、入口監聽器 | `mode` **以外**的 `resolution.*`，以及 `forwarders`（初始值；`set-forwarders` 可即時變更） |
| DNSBL 設定、本地項目、允許清單 | `dnssec.*` |
| DNS64、TTL 漂移、代理、DoT/DoH/DoQ 設定 | `security.*` |
| DHCP 位址池、租約、憑證選項 | `database_path`、`dhcp.*`、`acme.*`、`metrics.*` |
| DNSSEC 金鑰與區域簽章；ACME 憑證機構與 EAB 憑據 | `<transport>.tls.*`——那些路徑與 SAN 清單，而不是憑證本身 |
| TLS 憑證**檔案**——就地覆寫，30 秒內會被撿起 | — |
| `resolution.mode`——`set-resolution-mode` 切換它，`get-resolution-mode` 讀取實際生效的那個 | — |

記錄與封鎖清單的變更會在下一次查詢時生效——記錄變更會自動清空回應快取。

## 伺服器拒絕啟動的情況

這些都是刻意設計的硬性失敗，而不是警告，因為每一項若被放過，都會產生一台「看起來健康、實際上在做錯事」的伺服器：

- **可路由的 `grpc.tcp_bind` 搭配空的 `shared_secret`。** 這個組合就是在一個可達的連接埠上放了一個未認證的管理平面。Loopback 沒問題，那也是文件記載的開發形態；`0.0.0.0` 與 `::` 不是 loopback。
- **格式錯誤的 DNSSEC 信任錨點。** 退回 IANA 金鑰會讓一位設定了私有根的維運人員被錨定到錯誤的東西上，卻還驗證得很順利。
- **無法剖析的封鎖清單拒答碼。** 一個悄悄失效的碼，就是一個會被讀成「已列入」的拒答——凡是對照該供應商檢查的名稱都會 NXDOMAIN。
- **無法解析的綁定位址**——一個沒有任何位址的介面，或一個既不是 IP 也不是介面的名稱。這對 DNS、DoT、DoH、DoQ、gRPC、DHCP 與指標監聽器來說是致命的；兩個 ACME 監聽器則只記錄錯誤，伺服器其餘部分繼續執行。

YAML 的剖析錯誤同樣是致命的。檔案不存在則不是。

**一個解析成功但在作業系統層失敗的綁定**——連接埠被佔用，或位址尚不存在——並不致命：它會逐監聽器記錄下來，伺服器其餘部分照常執行。所以 `:53` 上的 `EADDRINUSE` 只會顯示為一行錯誤，而不是啟動失敗；請去看日誌，不要因為開機看起來乾淨就假設每個監聽器都起來了。

## 疑難排解

| 症狀 | 可能原因 |
| ---- | -------- |
| 區網外的用戶端除了你自己的區域以外，查什麼都得到 REFUSED | 這是預期行為：`security.recursion_cidrs`。若他們該有遞迴權限，請把其網段加進去 |
| 某個疊加網路對等節點查任何名稱都得到 REFUSED | 它落在 `security.overlay_cidrs` 內卻沒呼叫 `JoinNetwork`，或其關聯 TTL 已過期 |
| 你覆寫過的網域底下，某個公開名稱回 NXDOMAIN | 加了一筆記錄就讓這台伺服器對整個區域具權威。請在本地補上該名稱，或把覆寫改到你自己擁有的名稱上 |
| 某個名稱在別處都能解析，在這裡卻 SERVFAIL | DNSSEC 驗證把它擋掉了。檢查 `rolodex_dns_dnssec_verdicts_total{verdict="bogus"}`；再用 `dig +cd`（停用檢查）確認 |
| **每一個**名稱都 SERVFAIL，而且整條鏈從不降級到加密上游 | 根區域本身無法通過驗證：一個這個組建不認識的信任錨點（一次 KSK 輪替）、一個錯誤的 `dnssec.trust_anchors`，或是 `:53` 上有什麼東西拿它自己的材料在回答 DNSKEY 查詢。這是刻意的——一個無法通過驗證的根是一項判定，而不是一次層級失敗，所以該查詢會被拒絕，而不是被悄悄改問一個不做驗證的上游。在你修好錨點之前，`dnssec.validate: false` 就是逃生口 |
| `arpa.` 底下的某個名稱回 REFUSED（`ipv4only.arpa`，或對一個你並未持有的位址做 `dig -x`） | 這是預期行為：在每一種解析模式下，`arpa.` 及其底下的一切要嘛由本地資料回答，要嘛就不回答。那個子樹裡沒有任何東西會被送到上游。請在本地補上該記錄，或等待反解區域那項工作 |
| `rolodex_dns_dnssec_blamed_roots` 不為零 | 有一台根伺服器回覆了對照你的錨點無法通過驗證的 DNSSEC，因而被從根集合中剔除 15 分鐘，每再犯一次加倍。若**所有**的根都被剔除，該懷疑的是錨點或根區域，而不是那些伺服器——日誌會明確這麼說。歸責只存在記憶體中，重啟即重置 |
| 對照某個封鎖清單檢查的每個名稱都開始 NXDOMAIN | 這是尚未做拒答處理時的行為。用 `get-dnsbl-config` 檢查被移出輪替的供應商，以及該供應商的配額 |
| 某個 DHCP 用戶端的主機名稱始終沒出現在 DNS | 它不是合法的單一 DNS 標籤——主機名稱是被拒絕而非被清洗。警告訊息會指出它 |
| 某台明明正常的主機 `dig -x` 失敗 | 有一條本地封鎖項目匹配到了該位址。`add-dnsbl-allow --name <ip>` 可解除 |
| 更新後的憑證沒有被提供 | 給它 30 秒。若持續如此，日誌會說明原因——每一次失敗的重新載入都會在每次輪詢時被記錄。常見原因是憑證與金鑰對不上，而那也正是一次寫到一半的樣子；一次永久停在半途的更新永遠不會完成。一個使用 `auto_self_signed` 的監聽器根本不會被輪詢：它沒有檔案 |
| 某個 DoT 用戶端回報這台機器的主機名稱或區網位址憑證名稱不符 | 產生出來的憑證只指名 loopback 那一組與該監聽器的綁定位址，而萬用綁定不貢獻任何東西。請把該名稱加進 `dot.tls.self_signed_sans` 並重啟。這與「是否信任那張憑證」是兩回事，而自簽憑證仍然需要後者 |
| 某個 DoT 用戶端以 `no_application_protocol` 交握失敗 | 它提出的是 `dot` 以外的 ALPN 協定。監聽器宣告 `dot`，並拒絕一個只提出其他東西的用戶端；一個完全不提 ALPN 的用戶端會被正常服務 |
| 入口監聽器始終沒起來 | 它的 IP 在開機時還不存在。介面起來後重新加入該 TLD 即可 |

完整的欄位參考請見[設定選項](README.zh-TW.md#設定選項)。
