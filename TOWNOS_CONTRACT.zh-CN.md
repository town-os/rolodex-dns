# Town OS 契约

> 语言：[English](TOWNOS_CONTRACT.md) | [繁體中文](TOWNOS_CONTRACT.zh-TW.md) | **简体中文** | [Español (España)](TOWNOS_CONTRACT.es-ES.md) | [Español (México)](TOWNOS_CONTRACT.es-MX.md) | [日本語](TOWNOS_CONTRACT.ja-JP.md)

这是 rolodex 与 Town OS 之间、双向跨越边界的所有事物的权威清单。

**方向与 gfeh 相反。** gfeh 是 Town OS 的客户端；rolodex 则是被 Town OS 驱动的东西。Town OS 的 systemcontroller 是 rolodex 的 gRPC 客户端，`../install` 镜像负责写出 rolodex 的启动配置文件，而 ttyforce 则写出决定 rolodex 能发现什么的网络配置。因此接下来的内容大多是**那三方对 rolodex 可以做出的假设**，以及一小段 rolodex 反过来要求的东西。

**这里没有任何东西被钉在某个修订版上。** `make check-townos-sync` 在运行的当下解析这台机器上实际存在的检出。一个没有任何脚本会读的已记录修订版，是一个没有人在维护的主张；而钉住版本会在那些根本没改到 rolodex 所依赖之处的 Town OS 提交上大声失败——两边最糟的那一面。

| 命令 | 检查对象 | 会跳过吗？ |
|---|---|---|
| `make check-townos-sync` | 本机检出（`TOWNOS_DIR=`、`INSTALL_DIR=`） | 会，若不存在 |

它会作为 `make lint` 的一部分运行，因此日常开发免费得到这道检查，而且在一台只有这个仓库的机器上仍然可用。

### 这道检查实际验证了什么

光有名称是不够的——一个仍然存在但位置移动了的常量，正是那种在这里保持绿灯、却在机器上坏掉的失败。这道检查比对：

- **Town OS 的 `Client` 接口所声明的每一个方法，都存在于 rolodex 自己的 Go 客户端（`go/client.go`）上。** 那个——而不是 proto——才是 Town OS 绑定的接口：它自己的 `client` 结构直接委派给这个仓库的 Go 包。其中有些方法是便利包装而非独立的 rpc（`AddScopeTldWithListener` 就是设了 `listen_ip` 的 `AddScopeTld`），所以只看 proto 的检查会报告不存在的偏移，同时漏掉被移除的包装，而后者才是真正的偏移。
- **两个解析器里的转发器 scheme 集合完全相同**——这里的 `src/forwarder.rs` 与那里的 `src/rolodex/forwarder.go`。在两个彼此看不见的仓库里，用手写的两个解析器去解析同一套文法，是这份文档里最新、也最没有防护的东西。
- **三个仓库里的固定地址彼此一致**：DoH 后端、metrics 监听器、rolodex 绑定的 loopback，以及 TLS 目录，分别作为一个 Go 常量、安装脚本里的一个字面值，以及这里的一个默认值。

## 范围

三个对口，而且它们并不能互换：

1. **Town OS（`../town-os`）**——systemcontroller。通过 gRPC 编程设置 rolodex 的*配置*，并抓取它的 metrics。它不写任何配置文件。
2. **安装镜像（`../install`）**——`scripts/rolodex-config.sh` 写出 `rolodex.yml`，除此之外没有别的写入者。它只承载那些无法在运行中的 rolodex 上设置的东西。
3. **ttyforce（`~/src/github.com/erikh/ttyforce`）**——写出 networkd 单元。它出现在这里，只是因为它的某个选择（`UseDNS=no`）决定了 Town OS 的转发器发现能找到什么，而这件事从任何一边看都不明显。

没有别的东西跨越这道边界。尤其是：

- **rolodex 从不调用 Town OS。** 没有 HTTP 客户端、没有账号查询、没有存储调用。所有东西都是流进来的。
- **rolodex 不写任何 Town OS 会读的文件。** 它的数据库是它自己的；gRPC socket 与 metrics 端点就是全部的对外表面。

## `rolodex.yml` 只用于启动，而且两个仓库必须一起移动

`../install` 里的 `scripts/rolodex-config.sh` 是唯一的写入者。它只承载那些无法在运行中的服务器上设置的东西：

| 键 | 为何无法被编程设置 |
|---|---|
| `dns.bind` | 监听器必须在任何 API 调用能够抵达之前就存在 |
| `metrics.bind` | rolodex 只在启动时依该节的存在把那个监听器打开一次 |
| `doh` / `dot` / `doq` | 依各节的存在，在启动时只打开一次 |
| `database_path`、`grpc` | 在服务器存在之前就被读取 |
| `forwarders`、`resolution.mode` | 只是启动**默认值**——systemcontroller 会通过 gRPC 编程设置操作者真正的选择 |

**serde 会直接拒绝未知或缺少的字段。** 一个在该镜像修订版上是必需、却不存在于文件里的字段——或者存在于文件里、但该镜像不认得的字段——都会在启动时变成一个硬性的 `failed to parse config file`，而在 `Restart=always` 之下那就是一个崩溃循环，且整台机器上的所有东西都没有 DNS。这已经发生过一次，就在 `rbl` → `dnsbl` 的更名上。

由此得出的规则：**安装仓库的 `rolodex-config.sh` 与已发布的 rolodex 镜像必须一起移动。** 在这里改了一个配置键的名字、而那里没有对应的变更，得到的是一台坏掉的机器，而不是一个失败的测试。Town OS 里的 `TestRolodexDohBackendMatchesTheInstallScript` 只抓得到其中一个方向，而且只在 `../install` 有被检出时才抓。

## 配置只存在于内存中

rolodex **不会**持久化任何通过 gRPC 设置的东西。它在启动时从 `rolodex.yml` 取得种子，其余全部留在内存里，所以在 `Restart=always` 之下的一次崩溃、一次让该单元重启的 DHCP 租约变更，或是操作者手动重启，都会让 Town OS 推送过的每一项配置退回启动默认值。

因此 Town OS 的义务是：**每次重启之后都要重新推送。** `ProgramRolodex` 以 15 秒为周期运行，并通过 `Manager.Generation`——也就是 rolodex 在启动时绑定的那个 gRPC socket 的标识（设备、inode、修改时间）——察觉重启。rolodex 里没有任何东西会宣告自己重启了；socket 的标识就是那个信号。

有两个后果值得明讲：

- **一次完全相同的重新推送必须是免费的。** `SetForwarders` 与封锁清单的设置器都是单纯的存放——没有缓存清空、没有上游重新连接——正是为了让那个周期可以无条件推送而不必比对差异。`SetResolutionMode` 就*不是*免费的（切换进 `auto` 会重启层级探索），这也是为什么 Town OS 会把它对照 `GetResolutionMode` 做差异比对，只在真的改变时才推送。
- **逐转发器的健康状态必须撑过那个周期。** 一个由被推送的清单所拥有的断路器，会每 15 秒就被重置一次——比三次失败能够让它跳脱还要快——所以 `forwarder::carry_health` 会依标签把健康状态移到替换后的清单上。这完全是由 Town OS 的推送节奏所造成的、rolodex 这一侧的义务，也是为什么转发器的标签是稳定的而不是装饰性的。

## 转发器规格文法

**两个手写的解析器、一套文法，而且它们之间没有任何生成出来的代码。** 这里的 `src/forwarder.rs` 与 Town OS 里的 `src/rolodex/forwarder.go` 接受相同的字符串；这两个仓库彼此看不见，而且在构建期没有任何东西把它们绑在一起。`make check-townos-sync` 会比对 scheme 集合，而两边的单元测试也刻意钉住相同的案例。请把那当成仅有的防护。

`SetForwarders` 取用的仍然是 `repeated string`，没有改变，所以这套文法是搭在既有的线路类型上：

| 规格 | 传输 |
|---|---|
| `8.8.8.8:53` | 明文 UDP（Do53） |
| `tcp://8.8.8.8:53` | 明文 TCP（RFC 7766） |
| `tls://cloudflare-dns.com@1.1.1.1:853` | DoT（RFC 7858） |
| `https://cloudflare-dns.com@1.1.1.1/dns-query` | DoH（RFC 8484） |
| `quic://dns.adguard.com@94.140.14.14:853` | DoQ（RFC 9250） |

Town OS 那一侧精确依赖的性质：

- **裸的 `ip:port` 就是明文 UDP。** 每一个在传输尚不可命名之前写下的调用端都能继续工作，而 scheme 是调用端为了要求别的东西才加上去的。`udp://` 与裸写形式会解析成同一个转发器，并带有相同的 metrics 标签。
- **地址永远是字面值，绝不是主机名。** `name@ip` 在单一字符串里同时携带了要拨接的地址，以及要用来验证证书的名称。这就是那个开机自举的性质：一个必须先被解析才能用的加密上游，不可能成为那个修好一台没有可用 DNS 的机器的东西。
- **转发器落在哪一层是 rolodex 的决定，不是 Town OS 的。** 它是从转发器本身推导出来的——先加密，然后明文私有，然后明文公开——所以 Town OS 不可以用排序这份清单来表达偏好，也不可以假设它送出的顺序就是被尝试的顺序。
- **验证是全有或全无。** `SetForwarders` 会替换整份清单，所以 rolodex 会在应用其中任何一项之前先解析每一项，而 Town OS 则在推送之前先验证。一份被接受、但其中一项被丢掉的清单，会让解析器持有某个没有人要求过的东西。

**加密上游只能通过这份清单被编程设置。** `rolodex.yml` 里的 `resolution.secure_upstreams` 没有 gRPC 设置器，而且只在启动时被读取一次。在这份清单被类型化之前，那意味着在一个过滤对外 `:53` 的网络上唯一能工作的层级，同时也是那个不重启整台机器唯一的解析器就无法重新配置的层级——而那个*可以*被编程设置的层级，却只能承载这种网络正好会丢掉的明文地址。

## 固定地址

以下每一项都被写在不只一个仓库里，而且每一对都至少错过一次：

| 值 | rolodex | Town OS | `../install` |
|---|---|---|---|
| `127.0.0.2` | `dns.bind` 的第一项 | `rolodex.DNSLoopback` | `add_bind 127.0.0.2` |
| `127.0.0.2:9153` | `metrics.bind` | `rolodex.DefaultMetricsPort` | `metrics.bind` 字面值 |
| `127.0.0.2:4443` | `doh.bind` | `systemcontroller.RolodexDohBackend` | `doh.bind` 字面值 |
| `/data/tls/dot` | `dot`／`doq` 的 `cert_path` | `systemcontroller.RolodexTLSSubdir` | `ENC_CERT` / `ENC_KEY` |
| `/data/rolodex.sock` | `grpc.unix_socket` | `Config.UnixSocketPath` | `unix_socket` 字面值 |

用 `4443` 而不是 `443` 是有承重作用的：ingress 发布在 `0.0.0.0:443` 上，而 rolodex 以 `--net host` 运行，所以在同一个命名空间里同时有一个通配的 `:443` 与一个特定的 `127.0.0.2:443`，对后绑定的那一个来说就是 `EADDRINUSE`——DNS 或 ingress 会有一个挂掉，取决于开机顺序。

用 `127.0.0.2` 而不是 `127.0.0.1`，可以避开 systemd-resolved 在 `127.0.0.53` 上的 stub 以及 `127.0.0.1` 上的任何其他东西；它同时也是 `bootstrap-dns.sh` 把 resolved 指向的地址，因此它是这台机器自身的解析少了就无法工作的那一个绑定。

## Metrics

rolodex 在 `127.0.0.2:9153` 上提供 Prometheus 文本输出，依 `metrics` 这一节的存在，在启动时只打开一次。Town OS 是从 `rolodex.Manager.MetricsAddr()` 配置抓取目标，而不是从某个默认值重新组出来，因此目标与绑定不可能漂移。

Town OS 的监控所依赖的两个性质：

- **每个标签维度都是有界的。** 一个固定的枚举，或者由配置加以限界。任何由客户端控制的东西都会折进一个总括值（查询类型用 `OTHER`，TLD 用 `other`）。**查询名称永远不会成为标签。** `upstream_queries_total{server}` 与 `upstream_skipped_total{server}` 由已配置的转发器清单加以限界。
- **新的标签值只会被追加，绝不插入。** 那些 `BLOCK_*` 形式的常量是预先分配数组里的位置；一次插入会悄悄地把每一个既有的计数器都重新贴上标签。

新增或更名一个 metric，就意味着要更新 `README.md` 与 `DESIGN.md` 里的系列数量以及受影响的查询——`tests/promql_docs_test.rs` 会把文档中记载的数量钉在注册表实际输出的东西上。

## Town OS 必须做到：不要重新排序，也不要假设是 Do53

有两件事是 Town OS *不可以*做的，而这两件事过去都是安全的：

- **不要为了表达偏好而排序或重排转发器清单。** 一个层级内的顺序是被尊重的——那是 rolodex 尝试的次序——但层级本身是推导出来的。一份被 Town OS 依「加密优先」排过的清单，最好的情况是多余，而如果那个排序与 rolodex 的推导不一致，就会在日志里造成误导。
- **不要假设一个转发器就是 `ip:port`。** `Manager.Forwarders` 可能返回一个带 scheme 的规格。任何用 `:` 去切开一个转发器以取回主机与端口的做法，对 `tls://name@ip:853` 是错的，对 IPv6 字面值则是灾难性的错误。

## Town OS 必须做到：DHCP 解析器无法从 resolv.conf 被发现

这是唯一一处，Town OS／ttyforce 的某个选择会悄悄地让一个面向 rolodex 的功能失效；记录在这里，是因为单独看任何一边都没有错。

- ttyforce 在它的 networkd 单元上写下 `[DHCPv4] UseDNS=no`（以及 v6 的对应项），因此 DHCP 提供的解析器永远不会变成一个会盖过 rolodex 的逐链路解析器。
- `../install` 里的 `bootstrap-dns.sh` 只要 rolodex 是活着的，就会把 systemd-resolved 指向 `127.0.0.2`。
- `/etc/resolv.conf` 是 resolved 自己的 `127.0.0.53` stub。

这三者全都是 loopback 或根本不存在，而且三者都正确地被当成查询循环丢弃。所以 Town OS 的 `HostResolversFrom` 在一台运行中的机器上什么也**找不到**，而它的本地转发器发现必须去读 `/proc/net/route` 里的**默认网关**才能找到任何东西。网关之所以幸存，是因为它来自 DHCP 租约的 *router* 选项，而不是它的 DNS 选项。

任何改动那三个选择之一的事情，都会改变发现能找到什么。要么一起改，要么都别改。

## 已知的分歧

记录下来，免得有人是靠调试才发现：

- **rolodex 的 gRPC 表面远大于 Town OS 所使用的部分。** proto 声明了完整的管理 API；Town OS 的 `Client` 接口只是其中的一个子集。这道检查验证的是 Town OS 声明的每一项都存在于这里，而不是反过来——一个没有任何 Town OS 客户端会调用的 rpc 并不算偏移。
- **`shared_secret` 是空的，而认证靠的是文件系统权限。** 安装脚本写下 `grpc.tcp_bind: ""` 与一个 Unix socket，所以那个 socket 的模式就是全部的访问控制。一个 TCP 绑定会需要那个秘密，而 Town OS 里没有任何东西会设置它。
- **`GetForwarders` 并不存在。** Town OS 是无条件推送的，无法读回 rolodex 实际持有的东西。这正是为什么 `GET /dns/status` 报告的是 Town OS *将会*编程设置的东西，而不是 rolodex 已经拥有的东西。
- **Scope／TLD 转发器是另一份清单。** `SetScopeTldForwarders` 是逐范围的对等转发，并不是全局的转发器清单；它是单纯的 `ip:port`，不接受上面那套传输文法。

## 保持同步

Town OS 是以逐架构的容器镜像发布的，没有语义化版本，因此一个提交修订版是唯一精确的同步单位——而且这里刻意**没有钉住版本**。

**每当有变更触及 gRPC 表面、转发器文法，或任何一个固定地址时：**

1. 在 `TOWNOS_DIR` 与 `INSTALL_DIR` 指向那些检出的情况下运行 `make check-townos-sync`。
2. 任何失败都要借由同时更新另一侧**与**这份文档来调和——绝不只更新其中一边。
3. 如果该变更更名或移除了一个 `rolodex.yml` 的键，那么安装脚本与已发布的镜像必须一起出货。没有任何版本握手能抓到这件事。
