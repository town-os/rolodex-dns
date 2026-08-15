# Rolodex DNS 配置指南

这是一份任务导向的逐步说明：先让服务器跑起来，再逐一开启各子系统，并说明你为什么会想开它。完整的字段列表请见 README 的[配置选项](README.zh-CN.md#配置选项)。

> 语言：[English](CONFIGURATION.md) ｜ [繁體中文](CONFIGURATION.zh-TW.md) ｜ **简体中文** ｜ [Español (España)](CONFIGURATION.es-ES.md) ｜ [Español (México)](CONFIGURATION.es-MX.md) ｜ [日本語](CONFIGURATION.ja-JP.md)

- [配置如何加载](#配置如何加载)
- [最小可用配置](#最小可用配置)
- [绑定地址](#绑定地址)
- [部署形态](#部署形态) — 四个实例
- [子系统](#子系统) — 每个一节
- [运行期变更与需要重启者](#运行期变更与需要重启者)
- [服务器拒绝启动的情况](#服务器拒绝启动的情况)
- [故障排查](#故障排查)

## 配置如何加载

服务器读取一个 YAML 文件，默认为 `rolodex-dns.yml`：

```bash
rolodex-dns                        # 读取 ./rolodex-dns.yml
rolodex-dns -c /etc/rolodex-dns/config.yml
```

**文件不存在并不是错误。** 服务器会记录 `No config file found, using defaults` 并以内置默认值启动——那是一组真正可用的配置：DNS 监听 `0.0.0.0:53`、从根服务器开始的迭代解析并启用 DNSSEC 验证、gRPC 监听 loopback 与一个 Unix 套接字、封锁列表关闭、加密传输关闭。

每个段都是可选的，段中每个字段都有默认值，所以配置文件只需要写出你要更改的部分。那些以“是否出现”作为开关的段——`dot`、`doh`、`doq`、`proxy`、`dhcp`、`acme`、`metrics`——省略时就什么都不会启动。

日志由 `RUST_LOG` 环境变量控制，不在配置文件内：

```bash
RUST_LOG=rolodex_dns=debug rolodex-dns -c /etc/rolodex-dns/config.yml
```

## 最小可用配置

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""          # 只通过套接字管理
```

这就是一台具备本地记录数据库、会做验证的递归解析器。通过套接字新增记录：

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  --name nas.example.com --record-type a --value 192.168.1.10
```

端口 53 需要特权。开发时请用高位端口——`make dev` 会按 `dev.yml` 跑在 `127.0.0.1:5300`——生产环境请给可执行文件 `CAP_NET_BIND_SERVICE`，或通过你的服务管理器代为绑定，而不要以 root 运行。

## 绑定地址

所有接受地址的地方（`dns.bind`、`dot.bind`、`doh.bind`、`doq.bind`、`grpc.tcp_bind`、`dhcp.bind`、`acme.bind`、`acme.portal_bind`、`metrics.bind`）都接受四种写法：

（`dns.bind` 收的是一串“协议／地址”配对，而 `dot.bind`、`doh.bind` 与 `doq.bind` 既收**单个地址也收一个列表**——列表是一个监听器同时覆盖两个地址族的办法，因为 `0.0.0.0` 只管 IPv4，而 `[::]` 的套接字会在同一端口上与它相撞。其余的都只收单个地址。）

| 写法 | 示例 | 结果 |
| ---- | ---- | ---- |
| `ip:port` | `192.168.1.1:53` | 在该地址上建立一个监听器 |
| `[ipv6]:port` | `[::1]:53` | 一个监听器；方括号为必需 |
| `primary:port` | `primary:53` | 操作系统默认路由的出向 IP，于启动时探测 |
| `interface:port` | `eth0:53` | **该接口上每个 IP 各建一个监听器** |

`primary` 是以一次不发送数据的 UDP connect 朝 `8.8.8.8:53` 解出来的——它只是向路由表询问会用哪个源地址，实际不发出任何数据包。`interface:port` 会展开成该接口上被分配的每一个地址，所以在双栈主机上 `eth0:53` 会建立两个监听器。

`dns.bind` 是一串单键映射，因为一个监听器同时是协议**和**地址：

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - tcp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "127.0.0.1:53"
```

基于接口的绑定是在**启动时**解析的，之后不会重新解析。开机后才取得地址的接口（例如稍后才拉起的 WireGuard 隧道）在重启前不会被纳入——这正是为什么各 TLD 的入口监听器可以在运行期重新注册，见[专属 TLD 与入口](#专属-tld-与入口)。

## 部署形态

### 1. 家用／小型办公室解析器

会做验证、封锁广告与恶意软件、提供少量本地名称，且仅限局域网可达。

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  auto_ptr: true                # 让反向 PTR 与 A/AAAA 记录保持同步

resolution:
  mode: auto                    # 先走根服务器，再走加密上游，最后才是 ISP 的解析器

dnssec:
  validate: true                # 这是默认值；写在这里是因为它很重要

dnsbl:
  enabled: true
  providers:
    - zone: dbl.spamhaus.org
      enabled: true

security:
  # 默认值已涵盖 RFC 1918；若你的局域网只是其中一部分，可以再缩小
  recursion_cidrs: ["127.0.0.0/8", "192.168.0.0/16", "::1/128"]

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""

metrics:
  bind: "127.0.0.1:9153"
```

关于这些选择的说明：`resolution.mode: auto` 表示只要根服务器可达，就没有第三方看得到你的查询，而在会过滤 `:53` 的网络上解析仍能存活。`recursion_cidrs` 是让 `0.0.0.0:53` 绑定不至于变成开放解析器的关键——默认列表本身已经安全，把它缩小到你自己的网段是一种精调，而非必需。

### 2. 纯权威服务器

完全不做上游解析：每个答案都来自本地数据库，找不到的一律回权威 NXDOMAIN。

```yaml
database_path: /var/lib/rolodex-dns/auth.db

forwarders: []
resolution:
  mode: forward                 # forward 模式且没有转发器 = 没有上游

dnssec:
  validate: false               # 没有任何东西是从上游解析来的，也就没有东西要验证

security:
  recursion_cidrs: []           # 双保险：对所有人关闭递归

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
```

`forwarders: []` 搭配 `mode: forward` 就是那个开关。`recursion_cidrs: []` 与它重复，但它把意图写了出来，同时也关掉封锁列表提供方查询与缓存预热这两条路径。

声明你拥有权威的区域，让区域内找不到的名称回 NXDOMAIN，而不是变成一次无处可去的查找：

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-auth-zone --zone example.com.
```

（任何**已经有**记录的区域会自动被视为权威——见[受管区域与权威区域](#受管区域与权威区域)。）

### 3. 分割视域叠加节点（Town OS 形态）

这台机器同时位于局域网与 WireGuard 叠加网络上。叠加网络的对等节点被分隔进各个网络范围；局域网则看得到全部。

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  ingress_listen_port: 53

security:
  overlay_cidrs: ["10.64.0.0/10"]     # 这些来源会被强制套用范围
  recursion_cidrs:                    # 这些来源可以做上游解析
    - "127.0.0.0/8"
    - "10.0.0.0/8"                    # 包含叠加网络
    - "192.168.0.0/16"
    - "::1/128"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""
```

这两份 CIDR 列表回答的是**不同的问题**，也应该各自独立设置：

- `overlay_cidrs`——“谁会被强制套用范围？”列表内的来源必须已加入某个网络（`JoinNetwork`），否则就是 REFUSED，而且它只看得到自己范围的 TLD。
- `recursion_cidrs`——“谁可以让这台服务器去问别人？”列表外的来源仍然拿得到你的权威数据，只是不能驱动上游查找。

接着在运行期建立这些范围，而不是写在配置文件里——它们存在数据库中：

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI create-scope --name office                       # 隐含 office.home.
$CLI add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
$CLI add-scoped-record -s office --name git.office. --record-type a --value 10.64.0.5
$CLI join-network --ip 10.64.0.7 --scope office --ttl 300
```

### 4. 位于敌意／受过滤网络上的解析器

有些网络会丢弃对外的 `:53`，并以 DPI 拦截 `:853` 的 DoT 握手。`auto` 链就是为此而生，唯一值得调整的是它使用哪些加密上游：

```yaml
resolution:
  mode: auto
  secure_upstreams:
    - transport: https            # :443 上的 DoH——看起来就像普通 HTTPS
      addr: "1.1.1.1:443"         # 以 IP 拨号，因此不需要先有 DNS
      hostname: cloudflare-dns.com
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  switch_grace_failures: 3        # 降级生效前需要几次偏离的查询
  recovery_probe_secs: 60         # 已降级的链多久重试一次上层
```

安全上游是以 **IP** 拨号，并用 `hostname` 验证证书，所以这个层级启动时不需要自己先做 DNS。请注意，一条已降到第 0 层以下的 `auto` 链**不会**经过 DNSSEC 验证（转发来的答案是别人的结论摘要），而它会以“不置 AD 位”如实表明这一点。

## 子系统

### 上游解析

```yaml
forwarders:                       # 即 "local" 层级，也是 forward 模式下唯一的上游
  - "8.8.8.8:53"
  - "8.8.4.4:53"

resolution:
  mode: auto                      # auto | recursive | forward
  root_hints: []                  # 覆盖内置的 IANA 根服务器
  public_fallback: ["1.1.1.1:53", "8.8.8.8:53"]
  delegation_persist_min_ttl: 300 # TTL 高于此值的已学得委派才会持久化
  default_ttl: 300                # “仅”在完全没有任何 TTL 可用时才使用
```

| 模式 | 使用时机 |
| ---- | -------- |
| `auto`（默认） | 你以隐私为先，但解析必须能在受过滤的网络上存活 |
| `recursive` | 要么走根服务器要么不解析——绝不接触任何上游解析器 |
| `forward` | 你要的是单纯的转发器（或搭配 `forwarders: []`，完全不要上游） |

**这里的 `mode` 是启动时的种子，而不是正在生效的那个设置。** 它只在启动时
读一次；
从那以后，模式就是 `SetResolutionMode` 最后一次设定的那个，而 `GetResolutionMode`
报告的是真正在解析查询的那个——所以两者可能不一致，而以正在运行的服务器为准。
`rolodex-dns-cli set-resolution-mode -m <mode>` /
`get-resolution-mode` 就是这两个调用在命令行上的写法。改文件再重启当然也行，
但重启一台机器唯一的解析器，就是让它上面的一切都断一次 DNS——这正是那个 RPC
存在的全部理由。与文件不同，该 RPC 会**拒绝**无法识别的模式，而不是发出告警
再退回 `auto`。

`default_ttl` 是**后备值，不是下限**。存在的 TTL 一律按原样采用，包括区域 SOA 的否定 TTL。如果你想缩短或延长实际的 TTL，那是 [TTL 漂移](#dns64ttl-漂移与地址族)，不是这个。

### DNSSEC

两个彼此独立的部分。**验证**默认开启且不需要任何配置：

```yaml
dnssec:
  validate: true
  trust_anchors: []        # 空值 = IANA 根密钥
```

它只作用于迭代路径（`recursive` 模式，以及 `auto` 的根服务器层级），所以在 `forward` 模式下完全不起作用。伪造的数据会变成 SERVFAIL，且永不缓存。只有在你有具体理由时才关掉它——例如一个你无法修复的坏掉的上游，或一套你还没设置信任锚点的私有层级。

`trust_anchors` 采用 DNSKEY 的呈现格式，也就是 `dig DNSKEY .` 打印出的那四个 RDATA 字段；而且覆盖是**取代**IANA 密钥，不是追加：

```yaml
dnssec:
  trust_anchors:
    - "257 3 15 <base64 key>"     # 一个私有根；IANA 将“不再”被信任
```

格式错误的锚点会导致启动失败，而不是退回 IANA——一个无法对上任何真实 DNSKEY 的锚点，会让每个已签名的区域都失败，而且没有任何线索指向锚点才是原因。

**签名**完全不在 YAML 中配置；它是针对某个区域的运行期操作：

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
$CLI sign-zone --zone example.com.
```

变更记录后请重新运行 `sign-zone`。签名是被取代，而不是累积。RSA（算法 8）在生成密钥时就会被拒绝——`ring` 无法生成 RSA 密钥——而经过认证的否定证明（NSEC/NSEC3）只会被验证，永远不会被生成。

### 安全：两份 CIDR 列表

```yaml
security:
  qname_case_randomization: true      # 对转发查询做 0x20 编码
  overlay_cidrs: ["10.64.0.0/10"]     # 会被强制套用范围的来源
  recursion_cidrs: [ ... ]            # 允许做上游解析的来源
```

把这两者搞混是最常见的配置错误，所以直说：

| | `overlay_cidrs` | `recursion_cidrs` |
| --- | --- | --- |
| 问题 | 这个来源会拿到哪个**视域**？ | 这个来源可以让我们去问上游吗？ |
| 在列表内 | 必须已加入某个网络，否则 REFUSED；只看得到自己的范围 | 可以驱动上游解析 |
| 在列表外 | 受信任的本机来源；使用全局命名空间 | 仍拿得到本地／权威答案；任何需要离开本机的都 REFUSED |
| 默认值 | `10.64.0.0/10` | loopback、RFC 1918、link-local、ULA、CGNAT |

除非你是要**缩小**它，否则不要动 `recursion_cidrs`。把它往公网放宽，等于把这台机器变成开放解析器，那就是一项反射／放大攻击的资产，无论当下有没有人正在滥用它。

`qname_case_randomization` 应该保持开启。只有当某个上游会把它回送的问题名称大小写归一化时，才需要关掉它——否则这种解析器会让每一次查询都失败，因为大小写比对正是让 0x20 真正具有防护力的机制。

### 封锁列表（DNSBL）

**DNSBL 以名称封锁**，在任何外部解析之前检查。它默认为禁用且提供方列表为空，所以在你加入提供方之前，不会发出任何查询，也不会把任何名称交给封锁列表运营方。

```yaml
dnsbl:
  enabled: true
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
```

地址是由**本地列表**封锁的，而不是由提供方封锁：提供方被问及的是正在解析的那个名称，而在反向查找中，那是一个没有人会为其发布信誉数据的名称。见下面的本地条目。

开启它们之前有三件事值得知道：

1. **本地记录一律优先。** 封锁列表在本地记录与受管区域之后才执行，所以第三方的列入永远不可能弄掉一个内部服务。它在响应缓存与解析器**之前**执行，所以即使某个名称此前已被缓存，列入仍会生效。
2. **封锁是逐一针对被查询的名称，而非针对后缀。** `doubleclick.net` 被列入并不会封锁 `stats.g.doubleclick.net`——提供方必须把它也列进去。允许列表**则是**以后缀匹配的，因为一个漏掉子域名的逃生口根本称不上逃生口。
3. **量大时拒答码很重要。** 封锁列表告诉你“你超出配额了”时，用的是跟“已列入”同一种 `A` 记录。拒答处理默认就会启用，并带有一组内置码；唯一需要配置 `refusal_codes` 的理由，是某个私有封锁列表的真实列入值恰好与其中之一相撞（`refusal_codes: ["none"]`），或你想缩小这组码。见[拒答码与提供方轮换](README.zh-CN.md#拒答码与提供方轮换)。

本地条目与允许列表属于运行期状态，不是配置：

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI add-local-blocklist --name 10.0.0.5 --reason "known spam source"
$CLI add-dnsbl-allow --name vendor.example.com --reason "false positive"
$CLI add-dnsbl-allow --name 192.168.1.100 --reason "our own relay"   # IP 也可以
```

### 受管区域与权威区域

配置文件里没有区域列表。一个区域会通过以下两种方式之一成为权威：

- **隐式地**，因为它有记录。区域内任何位置的任何一条记录，都会让这台服务器对“整个区域”具权威——所以把 `foo.example.com` 加成本地覆盖，就意味着 `www.example.com` 会回 NXDOMAIN，而不是从互联网解析。这就是分割视域的取舍，也值得刻意为之：只有在你真的打算拥有某个公开域名时，才去覆盖它。
- **显式地**，用 `add-auth-zone`，这是你用来声明一个尚无记录的区域，或一个反向区域的方式（隐式规则刻意跳过 `in-addr.arpa`／`ip6.arpa`，因为那套启发式在那里会声明整棵全球反向树）。

### 加密传输

各段是否出现就是开关，且每一个都需要 TLS 材料：

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
    auto_self_signed: true            # 在受信任网络上没问题
    self_signed_sans:                 # 局域网客户端拨打本机时所用的名称
      - dns.home
      - town-os.local
```

`auto_self_signed: true`（默认值）会在没有配置证书时于启动阶段生成一张，这在受信任网络上很方便。

**续期后的证书无需重启。** 配置了 `cert_path`/`key_path` 的监听器每 30 秒重新读取这些文件，并在该窗口内开始提供新的一对——已经打开的连接会在它握手时所用的证书下走完，而下一条到达的连接拿到新证书。没有什么信号要发，也无需与写文件的一方做任何协调：轮询若落在 ACME 客户端的两次写入之间，会看到一把与证书不匹配的私钥，从而拒绝它、继续提供旧的一对，并在下一次滴答重试。自动生成的（`auto_self_signed`）证书不会被轮询——它背后没有文件，而按定时器重新生成会每半分钟给每个客户端一张不同的证书。

**可以指名一份尚未签发的证书。** 只有在 `auto_self_signed` 关闭时，把 `cert_path`／`key_path` 指向一个并不存在的文件才是硬性失败。开启它之后，监听器会先用生成的材料起步，而上面那次轮询会在真正的那一对落地的当下把它接过去。正是这一点，让这两个路径可以在签发证书的那个东西还没跑之前就写下去——在一台 CA 是在解析器启动之后才被创建的机器上，那本来就是常态，而另一条路是等文件出现之后再重启这台机器唯一的解析器。

**DoT、DoH 与 DoQ 都可以在运行期重新配置**，经由 `SetDotConfig`／`SetDohConfig`／`SetDoqConfig`。绑定地址、证书路径与 SAN 列表都可以在一台运行中的服务器上改动，而 `Get*Config` 报告的是实际绑定的内容。下面的 YAML 是启动配置；它不是唯一的入口，服务器起来之后它也不再是权威。

**如果某个 DoT 客户端报告证书名称不匹配，问题就在这个设置上。** 自动生成的证书涵盖 `localhost`、`127.0.0.1`、`::1` 以及该监听器自身的绑定地址——因此监听在 `192.168.1.5:853` 上的服务对拨打该地址的客户端已经可用，无需配置任何东西。它无法涵盖的是本机所应答的其他一切：它的主机名、它的 mDNS `.local` 名称、局域网所熟知的某个 CNAME，或者某个 NAT 对外发布它的地址。这些都写进 `self_signed_sans`。绑定**通配**地址的监听器（`0.0.0.0:853`，即默认值）根本不会推导出任何名称，因为 `0.0.0.0` 不是任何客户端所拨打的身份——在通配绑定上，这份列表就是唯一为本机署名的东西。

这是名称校验，不是信任决策，而且它先失败。客户端仍然必须被告知去信任这张证书——固定它，或者通过 DANE/TLSA 发布并校验它——因为自签证书没有链可查。什么都不验证的客户端（`kdig +tls`、机会模式下的 systemd-resolved）无论如何都不受影响。

### gRPC 管理

```yaml
grpc:
  tcp_bind: "127.0.0.1:50051"       # "" 禁用 TCP
  unix_socket: /var/run/rolodex-dns.sock   # "" 禁用套接字
  shared_secret: ""                 # 非 loopback 的 tcp_bind 必填
```

- **Unix 套接字完全跳过认证**，所以它的文件模式**就是**访问控制。它以 `0660` 创建（而非按 umask），因此请用 `chgrp` 把它分配给管理组来授权，而不要放宽模式。
- **TCP 需要共享密钥**，以恒定时间比较进行核对，并在连续失败后对该来源做锁定。空的密钥代表“不做认证”，这在 loopback 上没问题，但在任何可路由地址上会在启动阶段被拒绝。
- 优先使用套接字。单主机部署推荐的形态就是 `tcp_bind: ""` 搭配一个套接字路径。

### DHCP

段出现即代表启用；`tld` 为必填，也是主机名最终落脚的位置：

```yaml
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # 名为 "laptop" 的客户端会注册成 laptop.lan.example.com.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60
```

地址池属于运行期状态，并且是按网络范围划分的：

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1
```

一个地址池就是单一连续范围，用尽时分配即失败——不会跨池聚合。MAC 对 IP 的绑定是粘滞的。客户端提供的主机名必须是合法的单一 DNS 标签（RFC 1123），否则注册会被跳过并记录警告；它是被拒绝而不是被清洗过，所以绝不会有东西被悄悄注册成客户端没发出的名称。

### ACME 签发者与门户

段出现即会在开机时创建根证书颁发机构，并启动两个监听器：面向客户端的 ACME 端点，以及注册门户。

```yaml
acme:
  bind: "0.0.0.0:8555"
  portal_bind: "127.0.0.1:8500"                       # 仅限受信任网络
  directory_url: "https://dns.example.com:8555/acme"  # 请设置它——客户端会看到这个
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  require_eab: true
  issuance_scope: managed_zones                       # 或 "any"
  tls: { auto_self_signed: true }
```

`directory_url` 是告诉 ACME 客户端要去连的地址，因此必须是对外可达的 URL，而不是 `localhost`。**`portal_bind` 必须保持在受信任的地址上**——任何能连到门户的人都可以注册。除非设置 `issuance_scope: any`，否则注册会被限制在这台服务器实际管理的区域内，而 `require_eab: true` 会让账号注册必须先取得一份签发出来的凭据。

### 指标

```yaml
metrics:
  bind: "127.0.0.1:9153"
```

默认不存在，所以升级不会开出新的端口。它是纯 HTTP 且不做认证——只承载汇总计数，绝不含查询名称或记录值——因此请把它绑在私有地址上。最值得先观察的系列是 `rolodex_dns_answers_total{source}`（哪个阶段回答的）、`rolodex_dns_dnssec_verdicts_total{verdict}` 与 `rolodex_dns_blocklist_rotated_out`。

### DNS64、TTL 漂移与地址族

```yaml
dns64:
  enabled: false
  prefix: "64:ff9b::"       # 众所周知的前缀

ttl_drift:
  mode: disabled            # disabled | fixed | logarithmic
  fixed_adjustment: "5m"    # "5m"、"-30s"、"1h30m"、"2d12h"
  log_multiplier: 0.1

address_family:
  mode: auto                # auto | off | force4 | force6
  probe_interval_secs: 30
  fail_threshold: 2
```

`address_family: auto` 是默认值，通常也是你要的：它会以 TCP 连到公用解析器的 `:443`，测试**实际的**各地址族可达性，并针对主机无法路由的族抑制 A 或 AAAA 答案，让客户端改用另一族而不是卡住。用 `force4`／`force6` 可以不做探测直接钉住一族，用 `off` 则一律两族都回答。

### 专属 TLD 与入口

它们不算配置——存在数据库里并于运行期管理——但有两个配置字段与它们相关：

- `dns.ingress_listen_port`（默认 53）是每个 TLD 入口监听器绑定的端口。IP 则是逐 TLD 指定的，用 `add-scope-tld --listen-ip` 给定。
- 入口监听器会在开机时从数据库重放。若叠加网络的接口尚未存在，绑定会失败，该条目会被视为不存在，因此在隧道拉起后重新加入该 TLD 就会重试绑定，不需要重启。

## 运行期变更与需要重启者

许多看起来像配置的东西其实是 SQLite 里的运行期状态，可通过 gRPC 变更且无须重启：

| 可在运行期变更（gRPC/CLI） | 需要重启 |
| ---- | ---- |
| 记录、范围内记录、范围、关联 | `dns.bind` 以及所有其他绑定地址 |
| 权威区域、专属 TLD、入口监听器 | `mode` **以外**的 `resolution.*`，以及 `forwarders`（初始值；`set-forwarders` 可实时变更） |
| DNSBL 配置、本地条目、允许列表 | `dnssec.*` |
| DNS64、TTL 漂移、代理、DoT/DoH/DoQ 配置 | `security.*` |
| DHCP 地址池、租约、证书选项 | `database_path`、`dhcp.*`、`acme.*`、`metrics.*` |
| DNSSEC 密钥与区域签名；ACME 证书颁发机构与 EAB 凭据 | `<transport>.tls.*`——路径与 SAN 列表，而不是证书本身 |
| TLS 证书**文件**——就地重写，30 秒内被取用 | — |
| `resolution.mode`——`set-resolution-mode` 切换它，`get-resolution-mode` 读取实际生效的那个 | — |

记录与封锁列表的变更会在下一次查询时生效——记录变更会自动清空响应缓存。

## 服务器拒绝启动的情况

这些都是刻意设计的硬性失败，而不是警告，因为每一项若被放过，都会产生一台“看起来健康、实际上在做错事”的服务器：

- **可路由的 `grpc.tcp_bind` 搭配空的 `shared_secret`。** 这个组合就是在一个可达的端口上放了一个未认证的管理平面。Loopback 没问题，那也是文档记载的开发形态；`0.0.0.0` 与 `::` 不是 loopback。
- **格式错误的 DNSSEC 信任锚点。** 退回 IANA 密钥会让一位配置了私有根的运维人员被锚定到错误的东西上，却还验证得很顺利。
- **无法解析的封锁列表拒答码。** 一个悄悄失效的码，就是一个会被读成“已列入”的拒答——凡是对照该提供方检查的名称都会 NXDOMAIN。
- **无法解析的绑定地址**——一个没有任何地址的接口，或一个既不是 IP 也不是接口的名称。这对 DNS、DoT、DoH、DoQ、gRPC、DHCP 与指标监听器来说是致命的；两个 ACME 监听器则只记录错误，服务器其余部分继续运行。

YAML 的解析错误同样是致命的。文件不存在则不是。

**一个解析成功但在操作系统层失败的绑定**——端口被占用，或地址尚不存在——并不致命：它会逐监听器记录下来，服务器其余部分照常运行。所以 `:53` 上的 `EADDRINUSE` 只会显示为一行错误，而不是启动失败；请去看日志，不要因为开机看起来干净就假设每个监听器都起来了。

## 故障排查

| 症状 | 可能原因 |
| ---- | -------- |
| 局域网外的客户端除了你自己的区域以外，查什么都得到 REFUSED | 这是预期行为：`security.recursion_cidrs`。若他们该有递归权限，请把其网段加进去 |
| 某个叠加网络对等节点查任何名称都得到 REFUSED | 它落在 `security.overlay_cidrs` 内却没调用 `JoinNetwork`，或其关联 TTL 已过期 |
| 你覆盖过的域名底下，某个公开名称回 NXDOMAIN | 加了一条记录就让这台服务器对整个区域具权威。请在本地补上该名称，或把覆盖改到你自己拥有的名称上 |
| 某个名称在别处都能解析，在这里却 SERVFAIL | DNSSEC 验证把它挡掉了。检查 `rolodex_dns_dnssec_verdicts_total{verdict="bogus"}`；再用 `dig +cd`（禁用检查）确认 |
| **每一个**名称都 SERVFAIL，而且整条链从不降级到加密上游 | 根区域本身无法通过验证：一个这个构建不认识的信任锚点（一次 KSK 轮转）、一个错误的 `dnssec.trust_anchors`，或是 `:53` 上有什么东西拿它自己的材料在回答 DNSKEY 查询。这是刻意的——一个无法通过验证的根是一项判定，而不是一次层级失败，所以该查询会被拒绝，而不是被悄悄改问一个不做验证的上游。在你修好锚点之前，`dnssec.validate: false` 就是逃生口 |
| `arpa.` 底下的某个名称回 REFUSED（`ipv4only.arpa`，或对一个你并未持有的地址做 `dig -x`） | 这是预期行为：在每一种解析模式下，`arpa.` 及其底下的一切要么由本地数据回答，要么就不回答。那个子树里没有任何东西会被发送到上游。请在本地补上该记录，或等待反解区域那项工作 |
| `rolodex_dns_dnssec_blamed_roots` 不为零 | 有一台根服务器回复了对照你的锚点无法通过验证的 DNSSEC，因而被从根集合中剔除 15 分钟，每再犯一次翻倍。若**所有**的根都被剔除，该怀疑的是锚点或根区域，而不是那些服务器——日志会明确这么说。归责只存在内存中，重启即重置 |
| 对照某个封锁列表检查的每个名称都开始 NXDOMAIN | 这是尚未做拒答处理时的行为。用 `get-dnsbl-config` 检查被移出轮换的提供方，以及该提供方的配额 |
| 某个 DHCP 客户端的主机名始终没出现在 DNS | 它不是合法的单一 DNS 标签——主机名是被拒绝而非被清洗。警告信息会指出它 |
| 某台明明正常的主机 `dig -x` 失败 | 有一条本地封锁条目匹配到了该地址。`add-dnsbl-allow --name <ip>` 可解除 |
| 续期后的证书没有被提供 | 请给它 30 秒。若仍然如此，日志会说明原因——失败的重载每次轮询都会被记录。常见原因是证书与私钥不匹配，而那也正是一次写到一半的样子；一次被永久留在半途的续期永远不会完成。使用 `auto_self_signed` 的监听器根本不会被轮询：它没有文件 |
| 某个 DoT 客户端就本机的主机名或局域网地址报告证书名称不匹配 | 自动生成的证书只署名回环集合与该监听器的绑定地址，而通配绑定什么都不提供。请把该名称加入 `dot.tls.self_signed_sans` 并重启。这与是否信任该证书是两回事，自签证书仍然需要被信任 |
| 某个 DoT 客户端以 `no_application_protocol` 握手失败 | 它提供的是 `dot` 之外的 ALPN 协议。监听器通告 `dot`，并拒绝只提供其他协议的客户端；完全不提供 ALPN 的客户端会照常获得服务 |
| 入口监听器始终没起来 | 它的 IP 在开机时还不存在。接口起来后重新加入该 TLD 即可 |

完整的字段参考请见[配置选项](README.zh-CN.md#配置选项)。
