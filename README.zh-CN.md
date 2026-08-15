# Rolodex DNS

一套隐私优先的分割视域（split-horizon）DNS 服务器与递归／转发解析器，具备加密传输、DNSSEC 与 gRPC 管理，用 Rust 编写。

> 语言：[English](README.md) ｜ [繁體中文](README.zh-TW.md) ｜ **简体中文** ｜ [Español (España)](README.es-ES.md) ｜ [Español (México)](README.es-MX.md) ｜ [日本語](README.ja-JP.md)

Rolodex DNS 提供 UDP、TCP、TLS（DoT）、HTTPS（DoH）与 QUIC（DoQ）上的 DNS 服务，并具备一个优先于外部解析的本地记录数据库。记录通过 gRPC 远程管理（TCP 上使用共享密钥认证，或通过 Unix 套接字免认证）。它支持带域名叠加的 TLD 级解析，因此内部的 DNS 表述一律优先。内置的 DNS 响应缓存可在某条记录被见过之后，防止查询泄漏到上游解析器。

非本地的名称默认会**从根服务器开始迭代解析**，并依次退回加密（DoH/DoT）与明文上游，因此在会过滤对外 53 端口的网络上解析仍能存活。见[上游解析](#上游解析)。

从根服务器解析出来的答案默认会对照 IANA 信任锚点进行 **DNSSEC 验证**；伪造的数据永不提供也永不缓存。见 [DNSSEC](#dnssec)。

Rolodex DNS 另外支持用于垃圾邮件／恶意软件过滤的域名封锁列表（DNSBL）、DNSSEC 区域签名、DANE TLSA 证书关联、内置的 ACME 证书颁发机构、DNS64 AAAA 合成、逐网络的 DNS 分隔，以及集成的 DHCPv4 服务器。

第一次接触？请从 **[配置指南](CONFIGURATION.zh-CN.md)** 开始——那是一份任务导向的逐步说明，从最小可用配置一路走到每个子系统，并为每种部署形态附上实例。

## 功能特性

- **隐私优先的 DNS 缓存**：本地的 DNS 响应缓存可防止查询泄漏到上游。一旦缓存，查询就在本地作答，不会接触任何转发器。设置 `forwarders: []` 即可成为纯权威服务器。
- **加密传输**：DNS-over-TLS（DoT，853 端口）、DNS-over-HTTPS（DoH，443 端口，支持 GET/POST）、DNS-over-QUIC（DoQ，8853 端口）
- **分割视域 DNS**：本地数据库记录一律优先于外部解析出来的结果
- **UDP 与 TCP 上的 DNS**：两种传输层均完整支持
- **具韧性后备的递归解析器**：默认从根服务器迭代解析，接着是对公共解析器的 DoH/DoT，接着是已配置的转发器，最后是明文的公共解析器——因此在会过滤 `:53`（以及以 DPI 阻断 DoT `:853`）的网络上解析仍然可用。粘滞的层级避免在死掉的路径上付出超时代价，而每一次层级切换都会清空缓存
- **尊重 TTL 的解析器缓存**：一份持久化的“区域 → 名称服务器”委派缓存（跨重启保持预热）、一份供粘合记录／无粘合记录的 NS 查找／CNAME 跳转使用的内存缓存，以及 RFC 2308 的否定缓存——全都以其剩余寿命提供
- **地址族感知**：后台探测会测试真实的 IPv4/IPv6 互联网可达性，并针对主机无法路由的族抑制 A 或 AAAA 答案，让客户端改用另一族而不是卡在死掉的协议栈上
- **转发解析器**：可配置的上游 DNS 转发器，可通过 `resolution.mode: forward` 专门使用
- **TLD／域名叠加**：可在任意层级（包含 TLD）新增记录以覆盖公开 DNS
- **DNSSEC 签名**：Ed25519（首选）与 ECDSA P-256/P-384 的密钥生成、区域签名与 DS 记录计算。RSA/SHA-256 可验证但无法生成（`ring` 没有 RSA 密钥生成功能），而经过认证的否定证明（NSEC/NSEC3）不会被生成
- **DNSSEC 验证**：迭代解析出来的答案会对照 IANA 根信任锚点验证，默认开启（`dnssec.validate`）。信任链是自上而下、与委派走访并行建立的，因此获取一条 DS 不需要额外查询；未签名的委派必须**证明**自己未签名（已签名的 NSEC/NSEC3），因此剥除签名构不成降级。伪造的数据是 SERVFAIL 且永不缓存，而 AD 只为真正 Secure 的答案置位
- **DANE TLSA + ACME 签发者**：从证书生成 TLSA 记录、内置的 ACME 证书颁发机构（逐区域的中间证书颁发机构）、自签根证书颁发机构生成、ACME DNS-01 挑战处理（原生提供 `_acme-challenge` TXT 记录）
- **通过 DNS 分发证书颁发机构**：根与逐区域中间证书链会以 `CERT` 记录（RFC 4398）发布，并附有分块的 `TXT` 后备，因此任何解析得到该区域的客户端都能获取并信任该证书颁发机构——不需要访问门户（见[分发与信任证书颁发机构](#分发与信任证书颁发机构)）
- **22 种记录类型**：A、AAAA、CNAME、MX、TXT、NS、SOA、SRV、PTR、URI、SSHFP、DNAME、ANAME、ZONEMD、TLSA、CERT、DNSKEY、DS、RRSIG、NSEC、NSEC3、NSEC3PARAM。全部 22 种都可存储与列出；NSEC、NSEC3 与 NSEC3PARAM 永远不会被生成或提供（见 [DNSSEC](#dnssec)）
- **DNS 通配符**：符合 RFC 4592 的通配符匹配（`*.example.com.` 匹配单一标签替换，精确匹配优先）
- **权威 DNS**：对本地区域与明确声明的权威区域强制置 AA 位
- **EDNS（RFC 6891）**：OPT 记录支持、载荷大小协商、用于 DNSSEC 的 DO 位、版本大于 0 时回 BADVERS
- **DNS64（RFC 6147）**：从 A 记录合成 AAAA，前缀可配置（默认 `64:ff9b::/96`）
- **TTL 漂移**：固定模式（加减一段时长，支持 `"1h30m"` 这类复合格式）与实验性的对数模式（以延迟为基础）
- **QNAME 大小写随机化**：0x20 编码会把转发查询中的 QNAME 大小写随机化，作为缓存投毒的防御
- **gRPC 管理**：通过 gRPC 进行远程记录管理，使用共享密钥或 Unix 套接字认证
- **封锁列表支持**：具备内存缓存的 DNSBL 提供方检查，另有供自定义封锁条目使用的本地封锁列表数据库
- **DNSBL 支持**：域名封锁列表（Spamhaus DBL、SURBL、URIBL）会在任何外部解析之前检查，因此即使此前已缓存了一个转发答案，被列入的名称仍会被拒绝
- **封锁列表拒答处理**：DNSxL 响应“已列入”与“别再查我们”用的是同一种 `A` 记录，因此拒答码（`127.255.255.254`、`127.0.0.1` 等）会被识别为**不是**列入，而该提供方会被移出查询轮换一段冷却时间——而不是把每一个对照它检查的名称都变成 NXDOMAIN
- **封锁列表允许列表**：一个涵盖所有列表与两道关卡的逃生口——一个条目可让某个名称及其子域名豁免于 DNSBL／本地检查，并让某个地址（以反向名称或 IP 字面量指定）豁免于反向查找检查
- **递归访问控制**：`security.recursion_cidrs` 决定谁可以驱动**上游**解析，默认为从互联网不可路由的范围，因此默认的 `0.0.0.0:53` 绑定并不是一台开放递归解析器。陌生人仍然收得到这台服务器的权威答案
- **网络范围划分**：具备逐范围记录与以 IP 为基础之访问控制的分割视域 DNS。范围强制仅限于已配置的叠加网络（WireGuard）CIDR；loopback、局域网与容器来源受到信任且永不被拒绝
- **逐网络的专属 TLD**：由某个范围拥有的全局唯一 TLD，在叠加对等节点之间分隔且绝不转发到上游，并可选择性地为每个 TLD 设立**入口 DNS 监听器**，在该网络自己的地址上作答，并把已编程的名称改写到它的入口控制器
- **集成的 DHCPv4 服务器**：逐范围的地址池、粘滞的 MAC 绑定、自动的 A/PTR 注册、通过站点专用选项交付证书，以及后台租约清扫
- **自动反向 PTR 记录**：可选（`dns.auto_ptr`）为通过 gRPC 新增的 A/AAAA 记录维护对应的 `in-addr.arpa`／`ip6.arpa` PTR
- **代理支持**：通过 HTTP CONNECT、SOCKS5 或 DoH 代理转发 DNS 查询
- **Prometheus 指标**：一个可选、默认关闭的 `/metrics` 端点，输出 82 个具备有界标签基数的指标系列——包含逐阶段的答案归因与逐 TLD 隔离，让分割视域流水线从外面看得懂。查询名称永远不会成为标签
- **SQLite 持久化**：DNS 记录跨重启保存
- **TLS 热重载**：证书文件每 30 秒被轮询一次，续期后的一对会在该窗口内由 DoT、DoH、DoQ、ACME 与登记门户提供出去，无需重启，也不会掉连接。重建失败——文件被截断，或者轮询恰好落在 ACME 客户端的两次写入之间——会让此前的证书继续提供，并在下一次轮询时重试
- **性能**：多线程 tokio 运行时、无锁的封锁列表与解析器状态（`AtomicBool` + `ArcSwap` + 原子操作）、范围／区域／TLD／封锁条目的开机内存缓存、供上游转发使用的 UDP 套接字池，以及全面采用的 DashMap/DashSet 并发缓存

## 构建

```
make build
```

## 测试

```
make test
```

会运行 lint（翻译漂移检查、`cargo fmt --check` + `clippy --all-targets -D warnings`）、Go 集成测试与单元测试、Rust 集成测试与单元测试、JavaScript 的 lint／集成／单元测试，以及文档中 PromQL 的执行检查。Rust 集成层包含以真实套接字进行的套件：DNSSEC 签名与验证（对照一套已签名的模拟层级，其响应在序列化时才被篡改，因此每个测试都是“一个有效的部署，遭到攻击”）、封锁列表的 NXDOMAIN 契约、封锁列表拒答码、DoQ、代理、TLS 重载、ZONEMD、ACME 管理，以及逐项安全发现对应的 `security_*` 套件。使用 `make test-log` 可运行同一轮并 tee 进 `/tmp/rolodex-dns/log` 底下带时间戳的日志文件（可用 `LOG_DIR` 覆盖），即使失败也会在结尾打印路径。单独的层级：`make lint`、`make rust-test`、`make rust-integration-test`、`make go-test`、`make go-integration-test`、`make js-test`、`make js-integration-test`。

`make test` 也会运行 `make prometheus-test`，它会把本文件中记载的每一条 PromQL 查询，通过一个抓取实际服务器的真正 Prometheus 容器运行一遍——借此抓到一个**作为 PromQL 就格式错误**的查询，而不只是指名了不存在的系列。它需要 podman；没有 podman 时这项检查会**大声跳过**而不是失败，因此没有容器运行环境的机器仍能得到绿灯，同时绝不会假装那些查询已被验证。设置 `ROLODEX_PROMETHEUS_REQUIRED=1` 可让那个跳过变成硬性失败，而 `ROLODEX_PROMETHEUS_IMAGE` 可指向该镜像的镜像站。

## 开发

启动一台供测试与开发使用的本地开发服务器：

```
make dev
```

它会：
1. 以 debug 模式构建项目（`cargo build`）
2. 使用 `dev.yml` 启动服务器，配置如下：
   - DNS 监听器位于 `127.0.0.1:5300` 以及主要对外 IP 的 `5300` 端口（UDP 与 TCP）
   - gRPC Unix 套接字位于 `/tmp/rolodex-dns.sock`（没有 TCP gRPC 监听器）
   - SQLite 数据库位于 `/tmp/rolodex-dns-dev.db`
   - 不需要认证
   - 封锁列表检查禁用
   - 默认的上游转发器（`8.8.8.8:53`、`8.8.4.4:53`），作为默认 `auto` 解析链的 `local` 层级

`make help` 会按段分组列出每个目标与说明（它也是默认目标，所以直接运行 `make` 就会打印它）。

若要以 release 优化的开发服务器：
```
make dev-release
```

若要把可执行文件安装到你的 Cargo bin 目录：
```
make install
```

开发服务器启动后，你可以用 `rolodex-dns-cli` 可执行文件或连到 `/tmp/rolodex-dns.sock` 的 Go 客户端库来管理它。按 Ctrl+C 停止服务器。

## 容器镜像

Rolodex DNS 会用 `cargo-zigbuild` 在构建主机上交叉编译它的可执行文件，然后组出一个精简的运行期镜像（`debian:bookworm-slim`），其中只包含去除符号的可执行文件与一份 CA 证书包。`Containerfile` 刻意**不含任何 `RUN` 步骤**，这正是让任何主机都能在不需模拟、不需构建虚拟机的情况下，为任何架构构建镜像的原因。

镜像以涵盖 `linux/amd64` 与 `linux/arm64` 的多架构清单列表发布到 `quay.io/town/rolodex`。

### 多架构构建

构建是**原生的**：每个架构都在该架构的主机上编译。每个镜像都以 `uname -m` 的机器名称加上架构后缀标记（`-x86_64` 或 `-aarch64`，**不是** OCI 的 `amd64`／`arm64` 名称），因此部署主机可以直接拉取 `` <tag>-`uname -m` `` 而不需要任何映射转换。另有一个独立的清单步骤，把各架构镜像组成单一的多架构标签。

#### 选择架构：`TARGET`

`TARGET` 为每一个容器目标（`image`、`push-arch`、`push-rc`、`push-release`）选择架构。它默认为主机架构，并且比照 town-os `install` 仓库所使用的 `TARGET=` 模型，因此同一个值可以传给任一边：

| `TARGET` | 构建出 |
| -------- | ------ |
| *(未设置)* | 主机架构 |
| `x86_64`、`x86`、`amd64` | amd64 镜像，标记 `-x86_64` |
| `aarch64`、`arm64` | arm64 镜像，标记 `-aarch64` |
| `rpi` | arm64 镜像，标记 `-aarch64` |
| `rg35xxpro`、`rg35xx-pro`、`rg35xx`、`anbernic` | arm64 镜像，标记 `-aarch64` |

其他任何值都是错误，并会列出可接受的值。开发板风味不会改变镜像——rolodex-dns 每个架构只出一个容器镜像，而不是每块板子一个——它们之所以被接受，是为了让一个在 `install` 中有特定含义的 `TARGET=rg35xxpro`，在这里也能合理地解析。

**任何主机都能构建任何架构。** 外来的 `TARGET` 是交叉编译而非模拟，因此没有任何被拒绝的组合，也不需要构建虚拟机——见下面的“交叉编译”。

`podman build` 的 RUN 步骤共享主机网络（`--network=host`），好让它们能使用主机 loopback 上的 DNS 解析器（例如 rolodex 自己）；用 `BUILD_NETWORK=` 覆盖以退出此行为。

发布多架构镜像的端到端流程——每个架构一台主机：

1. 在 amd64 主机上：`make push-release` → 推送 `…:latest-x86_64`（以及日期标签）。
2. 在 arm64 主机上：`make push-release` → 推送 `…:latest-aarch64`（以及日期标签）。
3. 在任一主机上（两者都推送完成后）：`make manifest-release` → 创建并推送多架构的 `…:latest` 清单列表。

拉取 `quay.io/town/rolodex:latest` 的使用者接着就会透明地收到与其架构相符的镜像。

#### 交叉编译

两种架构都在运行 `make` 的那台主机上交叉编译，使用 `cargo-zigbuild` 并以 zig 作为 C 交叉编译器与链接器。`make deps` 会在**不需要 root** 的情况下配置整套工具链，并检查 `python3`（`make translation-check` 需要它，而它无法在不需要 root 的前提下安装）：

```bash
make deps        # rustup targets + cargo-zigbuild + zig、JS 开发依赖，以及 python3 检查
make cross-deps  # 只装 Rust 交叉工具链
```

单纯的 `rustup target add` 是不够的：`rusqlite` 会编译 SQLite 随附的 C 源码，而 `ring` 会编译 C 与汇编，所以必须有一套真正的交叉 **C** 工具链，否则构建会在 `cc` 那一步失败。zig 提供了一套，而且不需要任何发行版专属的包，并且链接到一个钉住的 glibc（`GLIBC_VERSION`，默认 `2.36` 以对应 `debian:bookworm`），因此无论构建主机带的是哪个版本，产出的可执行文件都能在运行期镜像上跑。

版本钉选均可覆盖：`ZIG_VERSION`、`ZIGBUILD_VERSION`、`GLIBC_VERSION`。

```bash
make image TARGET=x86_64         # 交叉编译 + 组出 amd64 镜像
make push-release TARGET=aarch64 # 交叉编译 + 推送 arm64 镜像
make push-release-all            # 从单一主机推送两种架构 + 清单
```

`make image-amd64`、`push-rc-amd64` 与 `push-release-amd64` 仍保留为 `TARGET=x86_64` 形式的别名。

### 构建镜像

为**主机**架构构建 release 镜像（标记为 `quay.io/town/rolodex:latest-<arch>`）：

```
make image
```

为特定架构构建：

```
make image TARGET=x86_64
make image TARGET=aarch64
```

以指定标签构建：

```
make IMAGE_TAG=v1.2.3 image
```

Cargo 的注册表与 git 缓存会保存在 `.cache/` 中以加速重建。

### 推送

登录 Quay.io（从环境变量或 `.env` 读取 `QUAY_USERNAME` 与 `QUAY_PASSWORD`）：

```
make quay-login
```

为 `TARGET` 构建并推送候选发布镜像（自动标记 `rc.YYYYMMDD-<arch>` 与 `rc.latest-<arch>`，例如 `rc.latest-x86_64`／`rc.latest-aarch64`）：

```
make push-rc
make push-rc TARGET=x86_64    # 明确指定架构
```

为 `TARGET` 构建并推送正式发布镜像（自动标记 `release.YYYYMMDD-<arch>` 与 `latest-<arch>`）：

```
make push-release
make push-release TARGET=aarch64
```

#### 组出多架构清单

在**所有**架构的各架构镜像都推送完成后（在每台原生主机上运行 `push-rc`／`push-release`），可从任一主机组出并推送多架构清单列表：

```
make manifest-rc       # 合并 rc.latest-x86_64 + rc.latest-aarch64 → rc.latest（以及 rc.YYYYMMDD 日期标签）
make manifest-release  # 合并 latest-x86_64 + latest-aarch64 → latest（以及 release.YYYYMMDD 日期标签）
```

清单是从注册表中已有的镜像组出来的（`podman manifest add docker://…`），因此不需要各架构镜像存在于本地。

#### 推送指定标签

使用 `IMAGE_TAG` 可构建并推送一个确切的标签，取代自动生成的日期标签。各架构镜像仍会套上架构后缀：

```
make IMAGE_TAG=v1.2.3 push-release    # 推送 quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release # 合并 v1.2.3-x86_64 + v1.2.3-aarch64 → v1.2.3
```

同样的做法适用于 `push-rc`／`manifest-rc`：

```
make IMAGE_TAG=v1.2.3-rc1 push-rc
make IMAGE_TAG=v1.2.3-rc1 manifest-rc
```

若要把已构建好的镜像以不同标签推送而不重新构建：

```
sudo podman tag quay.io/town/rolodex:latest quay.io/town/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:v1.2.3
```

若要推送到完全不同的注册表：

```
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push registry.example.com/myorg/rolodex:v1.2.3
```

### 清理

移除本地容器镜像：

```
make clean-containers
```

## 配置

Rolodex DNS 从一个 YAML 文件读取配置（默认 `rolodex-dns.yml`，可用 `-c`／`--config` 覆盖）。每个段都是可选的——文件不存在时，服务器会以默认值启动。

若想要一份逐个子系统把配置建立起来、并为每种部署形态附上实例的逐步说明，请见 **[配置指南](CONFIGURATION.zh-CN.md)**。下面的参考是完整的字段列表。

### 绑定地址语法

绑定地址字符串（用于 `dns.bind`、`dot.bind`、`doh.bind`、`doq.bind`、`grpc.tcp_bind`、`dhcp.bind`）接受四种写法：

| 写法 | 示例 | 说明 |
| ---- | ---- | ---- |
| `ip:port` | `192.168.1.1:53` | 绑定到指定的 IPv4 地址与端口 |
| `[ipv6]:port` | `[::1]:53` | 绑定到指定的 IPv6 地址与端口（方括号为必需） |
| `primary:port` | `primary:53` | 探测操作系统默认路由的对外 IP 并绑定到它 |
| `interface:port` | `eth0:53` | 绑定到指定网络接口上的所有 IP |

`primary` 关键字会探测操作系统会使用哪个 IP 地址来连上公网（通过一次不发送数据、朝向 `8.8.8.8:53` 的 UDP connect），并在该地址上绑定单一个监听器。这个关键字不分大小写。

接口绑定会解析出分配给该接口的所有 IPv4 与 IPv6 地址，并为每一个创建独立的监听器。举例来说，若 `eth0` 有 `192.168.1.5` 与 `fe80::1`，那么 `eth0:53` 会在 `192.168.1.5:53` 与 `[fe80::1]:53` 上各创建一个监听器。

`dot.bind` 与 `doq.bind` 既接受**单个绑定字符串，也接受它们的一个列表**：

```yaml
dot:
  bind:
    - "0.0.0.0:853"
    - "[2001:db8::1]:853"
```

列表是一个监听器同时覆盖两个地址族的办法。`0.0.0.0` 只管 IPv4，
而 `[::]` 并不是能同时顶替两者的可移植写法：在
`net.ipv6.bindv6only=0`（Linux 的默认值）之下，`[::]` 的套接字
也会收下 v4 映射的流量，于是它会与同一端口上 `0.0.0.0` 的套接字
相撞，后绑定的那个以 `EADDRINUSE` 失败。请改为逐个写出 v6 地址。
每一项都各自走上面那四种写法，重复的地址会被丢弃而不是绑定两次，
而且裸字符串仍然被接受——在列表写法出现之前写下的每一份配置都
照样能解析。

`dns.bind` 字段是一串“协议／地址”配对。每一项都是一个单键映射，键为 `udp` 或 `tcp`，值为绑定地址：

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "lo:53"
    - tcp: "eth0:53"
```

### 配置示例

```yaml
# 数据库文件路径
database_path: rolodex-dns.db

# 上游 DNS 转发器（address:port 格式）。作为 auto 链的 "local" 层级使用，
# 或在 resolution.mode 为 "forward" 时作为唯一的上游。
# 设为空列表（并搭配 resolution.mode: forward）即为纯权威服务器
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

# 上游解析策略（所有字段皆可选；此处显示默认值）
resolution:
  mode: auto              # "auto"（层级链）、"recursive"（只走根服务器）、"forward"
  root_hints: []          # 覆盖内置的 IANA 根服务器地址
  secure_upstreams:       # 加密层级，在根递归失败时尝试
    - transport: https    # "https"（DoH :443，首选）或 "tls"（DoT :853）
      addr: "1.1.1.1:443" # 以 IP 拨号，因此不需要先有 DNS
      hostname: cloudflare-dns.com  # 验证 SNI／证书名称
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  public_fallback:        # 明文 Do53，最后才尝试
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  switch_grace_failures: 3      # 层级降级生效前需要几次偏离的查询
  recovery_probe_secs: 60       # 已降级的链多久从最上层重试一次
  delegation_persist_min_ttl: 300  # TTL 高于此值的委派才会持久化
  default_ttl: 300              # 仅在完全没有任何 TTL 时作为后备

# 对从根服务器解析出的答案做 DNSSEC 验证（仅限迭代路径）
dnssec:
  validate: true          # 伪造的数据会变成 SERVFAIL 且永不缓存
  trust_anchors: []       # 空值 = IANA 根密钥；覆盖是“取代”它们

# 每一项把一个协议（udp/tcp）与一个绑定地址配成一对。
# 绑定地址接受 ip:port、[ipv6]:port、primary:port 或 interface:port。
dns:
  bind:
    - udp: "0.0.0.0:53"     # 或 "eth0:53" 以绑定到特定接口
    - tcp: "0.0.0.0:53"
  auto_ptr: false           # 为通过 gRPC 新增的 A/AAAA 维护反向 PTR
  ingress_listen_port: 53   # 各 TLD 入口监听器的端口（IP 是逐 TLD 指定的）

# DNS-over-TLS（RFC 7858）
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false
    # 仅在证书是自动生成时才会用到。回环名称与
    # 该监听器自身的绑定地址会被自动涵盖；此处列出
    # 客户端拨打本机时所用的其他名称。
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
  # TCP gRPC 监听器（空字符串代表禁用）
  tcp_bind: "127.0.0.1:50051"
  # Unix 套接字路径（空字符串代表禁用）
  unix_socket: /var/run/rolodex-dns.sock
  # TCP gRPC 认证用的共享密钥（Unix 套接字不需要）
  shared_secret: your-secret-here

# 域名封锁列表（按名称检查，在任何外部解析之前）
dnsbl:
  # 全局启用／禁用封锁列表检查（默认：false）
  enabled: false
  # 拒绝我们查询的提供方被移出轮换的秒数
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
      # 代表“查询被拒绝”而非“已列入”的码。省略即使用内置集合；
      # 单一条目 "none" 会为此提供方禁用拒答检测。
      refusal_codes: []
      # 逐提供方覆盖移出轮换的时长（省略则沿用上层）
      refusal_cooldown_secs: 3600
    - zone: multi.surbl.org
      enabled: true

# 集成的 DHCPv4 服务器（省略此段即禁用）
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # 必填：主机名会注册为 <host>.lan.<tld>.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60

# ACME 签发者／证书颁发机构（省略此段即禁用）
acme:
  bind: "0.0.0.0:8555"                    # 面向客户端的 ACME HTTPS 监听器
  portal_bind: "127.0.0.1:8500"           # 受信任网络的注册门户
  directory_url: "https://dns.example.com:8555/acme"  # 对客户端公告的地址
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  tlsa_port: 443
  tlsa_proto: tcp
  require_eab: true
  issuance_scope: managed_zones           # 或 "any"

# 转发 DNS 查询用的 HTTP 代理
proxy:
  url: "http://proxy:8080"
  auth: "user:pass"
  mode: "connect"  # "connect"（HTTP CONNECT 隧道）、"socks5"（SOCKS5 代理）或 "doh"（以 DoH 代理查询）

# TTL 漂移调整
ttl_drift:
  mode: "fixed"          # "fixed" 或 "logarithmic"（实验性）
  fixed_adjustment: "5m" # 例如 "5m"、"-30s"、"1h30m"、"2d12h"（仅 fixed 模式）
  log_multiplier: 1.0    # 乘数（仅 logarithmic 模式，实验性）

# DNS64 AAAA 合成
dns64:
  enabled: false
  prefix: "64:ff9b::"    # 默认的众所周知前缀（64:ff9b::/96）

# 地址族答案偏好
address_family:
  mode: auto              # "auto"（探测并抑制）、"off"、"force4"、"force6"
  probe_interval_secs: 30
  fail_threshold: 2       # 一个地址族被标记为不可用前需要几轮失败
  probe_timeout_secs: 2
  targets_v4: ["1.1.1.1:443", "8.8.8.8:443"]
  targets_v6: ["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]

# 安全设置
security:
  qname_case_randomization: true  # 对转发查询做 0x20 编码
  overlay_cidrs: ["10.64.0.0/10"] # 会被套用网络范围强制的来源范围
  # 谁可以驱动“上游”解析。此列表之外的来源仍拿得到这台服务器具权威的
  # 答案，但任何需要离开本机的请求都会得到 REFUSED。
  # 空列表 = 对所有人都纯粹只做权威回答。
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

# Prometheus 抓取端点（省略此段即不启动监听器）
metrics:
  bind: "127.0.0.1:9153"
  # 在逐 TLD 查询指标上拥有自己 `tld` 标签的 TLD。专属 TLD 会自动被追踪；
  # 所有未被追踪的都折叠进 `other`。
  tracked_tlds:
    - common
```

### 配置选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `database_path` | `"rolodex-dns.db"` | SQLite 数据库文件的路径 |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | 上游 DNS 解析器地址（`auto` 模式下的 `local` 层级；`forward` 模式下唯一的上游） |
| `resolution.mode` | `"auto"` | 上游策略：`"auto"`（层级链）、`"recursive"`（只走根服务器）、`"forward"`（只走转发器）。**只是启动时的种子**——`SetResolutionMode` 无需重启即可改动正在运行的服务器上的模式，`GetResolutionMode` 报告实际生效的那个 |
| `resolution.root_hints` | `[]`（内置 IANA 根服务器） | 覆盖 `recursive`／`auto` 模式所使用的根服务器提示 |
| `resolution.secure_upstreams` | 以 DoH 连 Cloudflare + Google | `secure` 层级的加密上游：`{transport, addr, hostname, path}` |
| `resolution.public_fallback` | `["1.1.1.1:53", "8.8.8.8:53"]` | 明文的公共解析器，在 `auto` 模式下最后才尝试 |
| `resolution.switch_grace_failures` | `3` | `auto` 层级降级生效前，连续偏离的查询次数 |
| `resolution.recovery_probe_secs` | `60` | 已降级的 `auto` 链多久从最上层重试一次 |
| `resolution.delegation_persist_min_ttl` | `300` | 一个已学得的委派要被持久化到 SQLite 所需的最低 TTL |
| `resolution.default_ttl` | `300` | 记录／响应完全没有自带 TTL 时的后备 TTL |
| `dnssec.validate` | `true` | 对迭代解析出的答案做 DNSSEC 验证（`recursive` 模式与 `auto` 的根服务器层级）。伪造与无法判定的数据会变成 SERVFAIL 且永不缓存 |
| `dnssec.trust_anchors` | `[]`（IANA 根密钥） | 以 DNSKEY 呈现格式表示的锚点，`"<flags> <protocol> <algorithm> <base64 key>"`——也就是 `dig DNSKEY .` 打印出的那些 RDATA 字段。每个字段都在启动时验证，有问题就是硬性失败。覆盖是**取代**IANA 密钥而非追加 |
| `dns.bind` | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | DNS 监听器；由 `{udp: addr}`／`{tcp: addr}` 条目组成的列表 |
| `dns.auto_ptr` | `false` | 为通过 gRPC 新增的 A/AAAA 维护反向 PTR 记录 |
| `dns.ingress_listen_port` | `53` | 各 TLD 入口监听器的 UDP/TCP 端口（绑定 IP 是逐 TLD 指定的） |
| `dns.udp_shards` | `0`（每核心一个） | 每个 UDP 监听地址所绑定的 `SO_REUSEPORT` 套接字数量。单一套接字会把监听器序列化——一个接收循环、所有回复共用一个套接字——使吞吐量远低于 CPU 饱和点。分片让内核得以把数据报分散到各核心。设为 `1` 可恢复旧的单一套接字行为 |
| `dot.bind` | `""`（禁用） | DoT 监听器；支持 interface:port（通常为 853 端口）。接受**单个地址或一个列表**——列表是一个监听器同时覆盖两个地址族的办法 |
| `dot.tls.cert_path` | `""` | DoT 的 TLS 证书路径 |
| `dot.tls.key_path` | `""` | DoT 的 TLS 私钥路径 |
| `dot.tls.auto_self_signed` | `true` | 为 DoT 自动生成自签证书 |
| `dot.tls.self_signed_sans` | `[]` | 自动生成之 DoT 证书的额外主体备用名称。回环集合与该监听器的绑定地址会被自动加入；通配绑定（`0.0.0.0`）不提供任何名称，因此请在此署名本机 |
| `doh.bind` | `""`（禁用） | DoH 监听器；支持 interface:port（通常为 443 端口） |
| `doh.tls.cert_path` | `""` | DoH 的 TLS 证书路径 |
| `doh.tls.key_path` | `""` | DoH 的 TLS 私钥路径 |
| `doh.tls.auto_self_signed` | `true` | 为 DoH 自动生成自签证书 |
| `doh.tls.self_signed_sans` | `[]` | 同 `dot.tls.self_signed_sans`，用于 DoH |
| `doh.enable_h3` | `false` | 为 DoH 启用 HTTP/3（QUIC）传输 |
| `doq.bind` | `""`（禁用） | DoQ 监听器；支持 interface:port（通常为 8853 端口）。与 `dot.bind` 一样，接受**单个地址或一个列表** |
| `doq.tls.cert_path` | `""` | DoQ 的 TLS 证书路径 |
| `doq.tls.key_path` | `""` | DoQ 的 TLS 私钥路径 |
| `doq.tls.auto_self_signed` | `true` | 为 DoQ 自动生成自签证书 |
| `doq.tls.self_signed_sans` | `[]` | 同 `dot.tls.self_signed_sans`，用于 DoQ |
| `grpc.tcp_bind` | `"127.0.0.1:50051"` | TCP gRPC 监听器；支持 interface:port（空值代表禁用） |
| `grpc.unix_socket` | `"/var/run/rolodex-dns.sock"` | Unix 套接字路径（空值代表禁用） |
| `grpc.shared_secret` | `""` | TCP gRPC 认证用的共享密钥（空值 = 不做认证） |
| `dnsbl.enabled` | `false` | 全局启用域名封锁列表（DNSBL）检查 |
| `dnsbl.providers[].zone` | -- | 要查询的 DNSBL 区域（被查询的名称会前置于它） |
| `dnsbl.providers[].enabled` | `true` | 启用／禁用单个 DNSBL 提供方 |
| `dnsbl.providers[].refusal_codes` | `[]`（内置集合） | 代表“查询被拒绝”而非“已列入”的答案。每一项是一个 IPv4 地址或 `address/prefix`。空值代表内置集合；单一条目 `none` 会为该提供方禁用检测。明确列出的列表是取代默认值而非扩充，而无法解析的码会在启动时被拒绝（见[拒答码与提供方轮换](#拒答码与提供方轮换)） |
| `dnsbl.providers[].refusal_cooldown_secs` | （沿用列表默认） | 拒答后逐提供方的移出轮换时长 |
| `dnsbl.refusal_cooldown_secs` | `3600` | 对于未自行设置的提供方，一个拒答中的提供方被移出轮换的秒数。`0` 代表“使用默认值”，而非“不冷却” |
| `dhcp.bind` | `"0.0.0.0:67"` | DHCP 监听器（段不存在 = DHCP 禁用） |
| `dhcp.tld` | -- | 启用 DHCP 时必填：主机名会注册为 `<host>.lan.<tld>.` |
| `dhcp.default_lease_duration` | `3600` | 默认租约时长（秒） |
| `dhcp.reclaim_timeout` | `86400` | 过期后多久回收一个 IP（秒） |
| `dhcp.sweep_interval` | `60` | 后台租约清扫的间隔（秒） |
| `acme.bind` | `"0.0.0.0:8555"` | 面向客户端的 ACME HTTPS 监听器（段不存在 = ACME 禁用） |
| `acme.portal_bind` | `"127.0.0.1:8500"` | 受信任网络的注册门户监听器 |
| `acme.directory_url` | `"https://localhost:8555/acme"` | 对客户端公告的外部 ACME 目录 URL（请务必设置） |
| `acme.root_ca_cn` | `"Rolodex Root CA"` | 开机时创建的根证书颁发机构通用名称 |
| `acme.leaf_validity_days` | `90` | 签发出的叶证书有效期 |
| `acme.tlsa_port` / `acme.tlsa_proto` | `443` / `"tcp"` | 每个名称的 DANE-TA TLSA 记录发布位置 |
| `acme.tlsa_endpoints` | `[]` | 除了 `tlsa_port`／`tlsa_proto` 之外，额外发布 DANE-TA TLSA 记录的 `"<port>/<proto>"` 端点。TLSA 记录指的是服务端点而非证书，因此同时提供 DoT（`853/tcp`）与 DoQ（`853/udp`）的一张证书，两者各需要一条记录；格式错误的条目会在启动时被拒绝，而不是跳过 |
| `acme.require_eab` | `true` | 账号注册时要求 External Account Binding |
| `acme.issuance_scope` | `"managed_zones"` | `"managed_zones"`（区域必须有证书颁发机构）或 `"any"` |
| `proxy.url` | `""`（禁用） | 转发 DNS 查询用的 HTTP 代理 URL |
| `proxy.auth` | `""` | 代理认证（`"user:pass"`） |
| `proxy.mode` | `"connect"` | 代理模式：`"connect"`（HTTP CONNECT）、`"socks5"`（SOCKS5）或 `"doh"` |
| `ttl_drift.mode` | `"disabled"` | TTL 漂移模式：`"disabled"`、`"fixed"` 或 `"logarithmic"` |
| `ttl_drift.fixed_adjustment` | `""` | 固定的 TTL 调整值。支持简单（`"5m"`、`"-30s"`、`"1h"`、`"2d"`）与复合时长（`"1h30m"`、`"2d12h"`） |
| `ttl_drift.log_multiplier` | `0.1` | 对数模式的乘数（按上游延迟调整 TTL） |
| `dns64.enabled` | `false` | 启用 DNS64 AAAA 合成 |
| `dns64.prefix` | `"64:ff9b::"` | DNS64 合成用的 IPv6 前缀 |
| `security.qname_case_randomization` | `true` | 启用 0x20 QNAME 大小写随机化 |
| `security.overlay_cidrs` | `["10.64.0.0/10"]` | 被视为不受信任的叠加对等节点并套用范围强制的来源范围；其他所有来源皆受信任 |
| `security.recursion_cidrs` | loopback、RFC 1918、link-local、ULA、CGNAT | 允许驱动**上游**解析的来源范围。其他来源会被提供本地／权威数据，而任何需要离开本机的请求都会得到 REFUSED；空列表即对所有人关闭递归（见[递归访问控制](#递归访问控制)） |
| `address_family.mode` | `"auto"` | `"auto"`（探测并抑制无法路由的族）、`"off"`、`"force4"`、`"force6"` |
| `address_family.probe_interval_secs` | `30` | `auto` 模式下两次可路由性探测之间的秒数 |
| `address_family.fail_threshold` | `2` | 一个地址族被标记为不可用前，连续失败的探测轮数（恢复则是立即的） |
| `address_family.probe_timeout_secs` | `2` | 每次探测对每个目标的 TCP connect 超时 |
| `address_family.targets_v4` / `targets_v6` | `:443` 上的 Cloudflare/Google | 各地址族的探测目标（IP 字面量） |
| `metrics.bind` | `127.0.0.1:9153` | Prometheus `/metrics` HTTP 监听器；支持 interface:port。此段为可选且默认省略，省略时不会启动任何监听器（见 [Prometheus 指标](#prometheus-指标)） |
| `metrics.tracked_tlds` | `[]` | 在逐 TLD 查询指标上拥有自己 `tld` 标签值的 TLD。专属 TLD 会自动被追踪；`common` 会展开成内置的常见 TLD 集合；所有未被追踪的都折叠进 `other` |

## 使用方式

### 服务器

```
rolodex-dns [OPTIONS]

Options:
  -c, --config <CONFIG>  配置文件路径 [默认: rolodex-dns.yml]
  -h, --help             打印帮助
```

### CLI 客户端

`rolodex-dns-cli` 是一个命令行客户端，通过 gRPC 管理界面管理运行中的 Rolodex DNS 服务器。它同时支持 TCP 与 Unix 套接字两种传输方式。

```
rolodex-dns-cli [OPTIONS] <COMMAND>
```

#### 全局选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-a, --address <ADDRESS>` | `127.0.0.1:50051` | TCP 连接使用的 gRPC 服务器地址（host:port）。设置 `--unix-socket` 时会被忽略。 |
| `-u, --unix-socket <PATH>` | -- | Unix domain socket 路径。会覆盖 `--address`。Unix 套接字连接会跳过认证。 |
| `-t, --auth-token <TOKEN>` | `""` | TCP 连接的认证令牌。服务器有配置共享密钥时为必需。Unix 套接字连接会忽略它。 |
| `-h, --help` | -- | 打印帮助 |
| `-V, --version` | -- | 打印版本 |

#### 命令

| 命令 | 说明 |
|------|------|
| **记录** | |
| `add-record` | 新增一条 DNS 记录到本地数据库 |
| `remove-record` | 从本地数据库移除 DNS 记录 |
| `list-records` | 列出 DNS 记录，可加筛选条件 |
| **转发器与解析** | |
| `set-forwarders` | 在运行期设置上游 DNS 转发器 |
| `set-resolution-mode` | 在运行期切换上游解析模式（`auto`、`recursive`、`forward`）|
| `get-resolution-mode` | 显示当前实际生效的解析模式 |
| **封锁列表** | |
| `set-dnsbl-config` | 在运行期配置域名封锁列表（DNSBL） |
| `get-dnsbl-config` | 获取当前的 DNSBL 配置 |
| `flush-cache` | 清空封锁列表的结果缓存 |
| `add-local-blocklist` | 新增一条本地封锁条目 |
| `remove-local-blocklist` | 移除一条本地封锁条目 |
| `list-local-blocklist` | 列出所有本地封锁条目 |
| `add-dnsbl-allow` | 让某个名称（及其子域名）豁免于封锁列表检查 |
| `remove-dnsbl-allow` | 移除一条 DNSBL 允许列表条目 |
| `list-dnsbl-allow` | 列出所有 DNSBL 允许列表条目 |
| **网络范围划分** | |
| `create-scope` | 创建一个新的网络范围 |
| `delete-scope` | 删除一个网络范围及其所有数据 |
| `list-scopes` | 列出所有已配置的网络范围 |
| `join-network` | 把一个 IP 关联到某个范围 |
| `leave-network` | 移除某个 IP 的范围关联 |
| `list-associations` | 列出 IP 对范围的关联 |
| `add-scoped-record` | 在某个范围内新增一条 DNS 记录 |
| `remove-scoped-record` | 从某个范围移除 DNS 记录 |
| `list-scoped-records` | 列出某个范围内的 DNS 记录 |
| `get-search-domains` | 获取某个 IP 的搜索域 |
| **专属 TLD／入口** | |
| `add-scope-tld` | 为某个范围注册一个全局唯一的专属 TLD（可选的 `--listen-ip` 会启动入口监听器） |
| `remove-scope-tld` | 从某个范围移除一个专属 TLD |
| `list-scope-tlds` | 列出某个范围所拥有的 TLD |
| `set-scope-tld-forwarders` | 设置某个范围之 TLD 的对等转发器 |
| `list-scope-tld-forwarders` | 列出某个范围之 TLD 的对等转发器 |
| `list-scope-tld-listeners` | 列出绑定到某个范围各 TLD 的入口 DNS 监听器 |
| **权威区域** | |
| `add-auth-zone` | 声明某个区域为权威 |
| `remove-auth-zone` | 从权威列表中移除某个区域 |
| `list-auth-zones` | 列出所有权威区域 |
| **缓存** | |
| `cache-stats` | 显示 DNS 缓存的命中／未命中统计 |
| `flush-dns-cache` | 清空 DNS 响应缓存 |
| **DHCP** | |
| `add-dhcp-pool` / `remove-dhcp-pool` / `list-dhcp-pools` | 管理各范围的 DHCP 地址池 |
| `list-dhcp-leases` / `delete-dhcp-lease` | 查看与删除 DHCP 租约 |
| `set-dhcp-cert` / `remove-dhcp-cert` / `list-dhcp-certs` | 管理通过 DHCP 选项交付的证书 |
| **DNSSEC** | |
| `generate-dnssec-key` | 生成一组 DNSSEC 密钥对（KSK 或 ZSK） |
| `list-dnssec-keys` | 列出某个区域的 DNSSEC 密钥 |
| `sign-zone` | 用区域的 DNSSEC 密钥为它签名 |
| **DANE / ACME** | |
| `generate-tlsa` | 从证书生成一条 TLSA 记录 |
| `request-acme-cert` | 通过 ACME DNS-01 请求证书 |
| `acme-status` | 检查 ACME 证书状态 |
| `ensure-zone-ca` | 确保逐区域的中间证书颁发机构存在；打印根 + 中间 PEM 并把证书链发布进 DNS |
| `create-eab` / `remove-eab` | 铸造或移除一份限定于某区域的 EAB 凭据 |
| `list-acme-accounts` | 列出已注册的 ACME 账号 |
| `list-acme-certs` | 列出已签发的证书 |
| **TTL 漂移** | |
| `set-ttl-drift` / `get-ttl-drift` | 设置／获取 TTL 漂移配置 |
| **DNS64** | |
| `set-dns64` / `get-dns64` | 设置／获取 DNS64 配置 |
| **可观测性** | |
| `latency-stats` | 显示逐服务器的上游查询延迟 |

传输（DoT/DoH/DoQ）、代理，以及少数 DNSSEC/DANE 操作可通过 gRPC 使用，但没有对应的 CLI 子命令——见[其他 gRPC 方法](#其他-grpc-方法)。完整的命令标志请运行 `rolodex-dns-cli <COMMAND> --help`。

##### `add-record`

新增一条 DNS 记录到本地数据库。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/AddRecord`

```
rolodex-dns-cli add-record -n <NAME> -v <VALUE> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 完整域名（例如 `"example.com."`——建议带结尾的点） |
| `-r, --record-type <TYPE>` | `a` | DNS 记录类型（见记录类型表） |
| `-v, --value <VALUE>` | -- | 记录数据。格式视记录类型而定（见“记录类型”一节） |
| `--ttl <TTL>` | `300` | 存活时间（秒）。设为 0 时服务器会默认为 300 |
| `-p, --priority <PRIORITY>` | `0` | MX 与 SRV 记录的优先级。数值越小优先级越高。其他类型会忽略 |

示例：
```bash
# 通过 TCP 新增一条 A 记录
rolodex-dns-cli -a 127.0.0.1:50051 -t my-secret add-record \
  -n example.com. -r a -v 10.0.0.1 --ttl 600

# 通过 Unix 套接字新增一条 MX 记录
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  -n example.com. -r mx -v mail.example.com. -p 10

# 新增一条 CNAME 记录
rolodex-dns-cli add-record -n www.example.com. -r cname -v example.com.

# 新增一条 SRV 记录
rolodex-dns-cli add-record -n _sip._tcp.example.com. -r srv \
  -v "5 5060 sip.example.com." -p 10

# 新增一条 URI 记录
rolodex-dns-cli add-record -n example.com. -r uri \
  -v "10 1 \"https://example.com/\"" -p 10

# 新增一条 SSHFP 记录
rolodex-dns-cli add-record -n host.example.com. -r sshfp \
  -v "2 1 123456789abcdef..."

# 新增一条通配符记录
rolodex-dns-cli add-record -n "*.example.com." -r a -v 10.0.0.99
```

##### `remove-record`

从本地数据库移除 DNS 记录。按名称移除，并可加上类型与值的筛选条件。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/RemoveRecord`

```
rolodex-dns-cli remove-record -n <NAME> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 要移除之记录的完整域名 |
| `-r, --record-type <TYPE>` | -- | 指定时只移除此类型的记录。省略时移除该名称的所有类型 |
| `-v, --value <VALUE>` | -- | 指定时只移除值与之完全相同的那条记录 |

示例：
```bash
# 移除某个名称的所有记录
rolodex-dns-cli remove-record -n old.example.com.

# 只移除某个名称的 A 记录
rolodex-dns-cli remove-record -n example.com. -r a

# 按值移除指定的一条记录
rolodex-dns-cli remove-record -n example.com. -r a -v 10.0.0.1
```

##### `list-records`

从本地数据库列出 DNS 记录，可加筛选条件。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/ListRecords`

```
rolodex-dns-cli list-records [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 按域名筛选。支持 `"*."` 通配符前缀以匹配所有子域名（例如 `"*.example.com."`） |
| `-r, --record-type <TYPE>` | -- | 按记录类型筛选。省略时返回所有记录类型 |

示例：
```bash
# 列出所有记录
rolodex-dns-cli list-records

# 列出指定名称的记录
rolodex-dns-cli list-records -n example.com.

# 列出所有子域名
rolodex-dns-cli list-records -n "*.example.com."

# 只列出 AAAA 记录
rolodex-dns-cli list-records -r aaaa
```

##### `set-forwarders`

在运行期设置上游 DNS 转发器。会取代整份转发器列表。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/SetForwarders`

```
rolodex-dns-cli set-forwarders -f <ADDR>...
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-f, --forwarders <ADDR>...` | -- | 上游 DNS 服务器地址，格式为 `"host:port"`。多个地址以空格分隔 |

示例：
```bash
# 设置 Google 与 Cloudflare DNS
rolodex-dns-cli set-forwarders -f 8.8.8.8:53 1.1.1.1:53

# 设置单一转发器
rolodex-dns-cli set-forwarders -f 9.9.9.9:53

# 移除所有转发器（纯权威模式）
rolodex-dns-cli set-forwarders -f ""
```

##### `set-resolution-mode`

切换本服务器对自己不具权威的名称的解析方式，无需重启。配置文件里的
`resolution.mode` 只是启动时的种子——这条命令改的才是真正在解析查询的
那个模式。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/SetResolutionMode`

```
rolodex-dns-cli set-resolution-mode -m <MODE>
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-m, --mode <MODE>` | -- | `auto`、`recursive` 或 `forward`。不区分大小写 |


无法识别的模式会以 `InvalidArgument` 被拒绝，而不是像配置文件那样悄悄退回
`auto`：把模式打错的调用方，绝不该被告知机器处在某个模式、而它实际却在用
另一个模式解析。

示例：
```bash
# 根优先的后备链（默认）
rolodex-dns-cli set-resolution-mode -m auto

# 只从根迭代，没有任何后备
rolodex-dns-cli set-resolution-mode -m recursive

# 只走已配置的转发器
rolodex-dns-cli set-resolution-mode -m forward
```

切换*进入* `auto` 会重新跑一遍层级预热，因此切换之后的头几次查询不必付冷层级的
代价。

##### `get-resolution-mode`

显示当前实际生效的模式。这是真正在解析查询的那个模式，未必就是配置文件里
写的那个——一次 `set-resolution-mode` 之后，两者就会
不同。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/GetResolutionMode`

```
rolodex-dns-cli get-resolution-mode
```

示例：
```bash
$ rolodex-dns-cli get-resolution-mode
Resolution mode: auto
```

##### `flush-cache`

清空封锁列表结果缓存。强制后续查询重新查找。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/FlushCache`

```
rolodex-dns-cli flush-cache
```

##### `create-scope`

创建一个带有保留 `.home` 域名的新网络范围。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

```
rolodex-dns-cli create-scope -n <NAME> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 网络范围的唯一名称（例如 `"office"`、`"lab"`） |
| `-d, --home-domain <DOMAIN>` | `"<name>.home."` | 此范围保留的 `.home` 域名。省略时默认为 `"<name>.home."` |

示例：
```bash
# 以默认 home 域名创建范围
rolodex-dns-cli create-scope -n office
# 创建名为 "office" 的范围，home 域名为 "office.home."

# 以自定义 home 域名创建范围
rolodex-dns-cli create-scope -n lab -d lab.internal.
```

##### `delete-scope`

删除一个网络范围及其所有记录与关联。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

```
rolodex-dns-cli delete-scope -n <NAME>
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-n, --name <NAME>` | -- | 要删除的范围名称 |

##### `list-scopes`

列出所有已配置的网络范围。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

```
rolodex-dns-cli list-scopes
```

##### `join-network`

把一个 IP 地址关联到某个网络范围。这个关联带有 TTL，必须定期刷新。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/JoinNetwork`

```
rolodex-dns-cli join-network -i <IP> -s <SCOPE> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-i, --ip <IP>` | -- | 要关联的客户端 IP 地址（例如 `"192.168.1.100"`） |
| `-s, --scope <SCOPE>` | -- | 要加入的网络范围名称 |
| `--ttl <TTL>` | `300` | 关联的 TTL（秒）。必须在到期前刷新。为 0 时默认为 300 |

示例：
```bash
# 以默认 TTL 加入
rolodex-dns-cli join-network -i 192.168.1.100 -s office

# 以自定义 TTL 加入
rolodex-dns-cli join-network -i 10.0.0.5 -s lab --ttl 600
```

##### `leave-network`

移除某个 IP 地址与其网络范围的关联。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

```
rolodex-dns-cli leave-network -i <IP>
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-i, --ip <IP>` | -- | 要解除关联的客户端 IP 地址 |

##### `list-associations`

列出 IP 对范围的关联，可按范围筛选。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

```
rolodex-dns-cli list-associations [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 按范围名称筛选。省略时列出所有关联 |

##### `add-scoped-record`

在指定的网络范围内新增一条 DNS 记录。范围内记录只对关联到该范围的 IP 可见。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

```
rolodex-dns-cli add-scoped-record -s <SCOPE> -n <NAME> -v <VALUE> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 要新增记录的网络范围 |
| `-n, --name <NAME>` | -- | 完整域名 |
| `-r, --record-type <TYPE>` | `a` | DNS 记录类型 |
| `-v, --value <VALUE>` | -- | 记录数据 |
| `--ttl <TTL>` | `300` | 存活时间（秒） |
| `-p, --priority <PRIORITY>` | `0` | MX 与 SRV 记录的优先级 |

示例：
```bash
# 新增一条范围内的 A 记录
rolodex-dns-cli add-scoped-record -s office -n printer.office.home. -v 192.168.1.50

# 新增一条范围内的 CNAME
rolodex-dns-cli add-scoped-record -s lab -n app.lab.home. -r cname -v server.lab.home.
```

##### `remove-scoped-record`

从指定的网络范围移除 DNS 记录。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

```
rolodex-dns-cli remove-scoped-record -s <SCOPE> -n <NAME> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 要移除记录的网络范围 |
| `-n, --name <NAME>` | -- | 完整域名 |
| `-r, --record-type <TYPE>` | -- | 按记录类型筛选 |
| `-v, --value <VALUE>` | -- | 按完全相同的值筛选 |

##### `list-scoped-records`

列出某个网络范围内的 DNS 记录。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

```
rolodex-dns-cli list-scoped-records -s <SCOPE> [OPTIONS]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-s, --scope <SCOPE>` | -- | 要查询的网络范围 |
| `-n, --name <NAME>` | -- | 按域名筛选（支持 `"*."` 通配符前缀） |
| `-r, --record-type <TYPE>` | -- | 按记录类型筛选 |

##### `get-search-domains`

获取某个客户端 IP 地址的搜索域。
**gRPC 路径：** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

```
rolodex-dns-cli get-search-domains -i <IP>
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-i, --ip <IP>` | -- | 要查询的客户端 IP 地址 |

## gRPC API

管理 API 定义在 `proto/rolodex_dns.proto` 中。所有方法都接受一个 `auth_token` 字段，供通过 TCP 连接时的共享密钥认证使用。Unix 套接字连接会跳过认证。

完整的 API 参考请见 proto 文件。这个服务定义了 74 个 RPC 方法，涵盖记录管理、网络范围划分、专属 TLD 与入口、封锁列表、DHCP、加密传输、DNSSEC、DANE/ACME、缓存、DNS64、指标与可观测性。

### 服务：`rolodex_dns.RolodexDnsService`

#### `AddRecord`

**路径：** `/rolodex_dns.RolodexDnsService/AddRecord`

新增一条 DNS 记录到本地数据库。

**参数：**
- `record`（DnsRecord，必填）：要新增的 DNS 记录
  - `name`（string）：完整域名（例如 `"example.com."`）
  - `record_type`（RecordType）：DNS 记录类型（见下方“记录类型”）
  - `value`（string）：记录数据（例如 IP 地址、主机名）
  - `ttl`（uint32）：存活时间（秒）。设为 0 时默认为 300
  - `priority`（uint32）：MX/SRV 记录的优先级（其他类型会忽略）。默认：0
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `RemoveRecord`

**路径：** `/rolodex_dns.RolodexDnsService/RemoveRecord`

从本地数据库移除 DNS 记录。

**参数：**
- `name`（string，必填）：完整域名
- `record_type`（RecordType）：有设置时只移除此类型的记录。未设置（A/0）时移除该名称的所有记录
- `value`（string）：非空时只移除值与之完全相同的那条记录
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `removed_count`（uint32）：被移除的记录条数
- `message`（string）：`success` 为 false 时的错误信息

#### `ListRecords`

**路径：** `/rolodex_dns.RolodexDnsService/ListRecords`

以可选的筛选条件查询本地 DNS 数据库。

**参数：**
- `name_filter`（string）：按域名筛选。支持 `"*."` 通配符前缀以匹配所有子域名（例如 `"*.example.com."`）
- `record_type_filter`（RecordType）：按记录类型筛选（仅在 `filter_by_type` 为 true 时套用）
- `filter_by_type`（bool）：是否套用 `record_type_filter`。默认：false
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `records`（repeated DnsRecord）：符合条件的 DNS 记录

#### `SetForwarders`

**路径：** `/rolodex_dns.RolodexDnsService/SetForwarders`

在运行期设置上游 DNS 转发器。

**参数：**
- `forwarders`（repeated string）：上游 DNS 服务器地址列表，格式为 `"host:port"`（例如 `"8.8.8.8:53"`）
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `SetResolutionMode`

**路径：** `/rolodex_dns.RolodexDnsService/SetResolutionMode`

在运行期更改上游解析模式。

配置文件里的 `resolution.mode` 原本是一个只在启动时读取的设置，这让它成了编排方
无法在不重写该文件并重启进程的前提下改动的唯一一项上游行为——而重启一台机器
唯一的解析器，就是让它上面的一切都断一次
DNS。

**参数：**
- `mode`（string）：`"auto"`（根优先的后备链）、`"recursive"`（只从根迭代）或 `"forward"`（只走已配置的转发器）。不区分大小写
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

无法识别的模式会返回 `InvalidArgument`，而不是像配置文件那条路径那样退回
`auto`。文件是由能看见告警的运维在启动时读一次的；而 RPC 那头有个调用方在
等答复，告诉它"成功"却在用它没要的模式解析，正是一台机器在过滤 `:53` 的
网络上落进 `recursive`、而日志里对每个名称为何解析失败只字未提的
由来。


切换**进入** `auto` 会派生与启动路径相同的层级预热，因此切换之后的头几次
查询不必付冷层级的代价。层级恢复探测是无条件运行的，所以在运行期切换进
`auto` 的模式仍然能夺回一个已恢复的
层级。

#### `GetResolutionMode`

**路径：** `/rolodex_dns.RolodexDnsService/GetResolutionMode`

返回当前实际生效的解析模式——真正在解析查询的那个，而不是配置文件里写的
那个。一次 `SetResolutionMode` 调用之后，两者就会
不同。

**参数：**
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `mode`（string）：`"auto"`、`"recursive"` 或 `"forward"`

#### `FlushCache`

**路径：** `/rolodex_dns.RolodexDnsService/FlushCache`

清空封锁列表查找缓存。

**参数：**
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `CreateNetworkScope`

**路径：** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

创建一个带有保留 `.home` 域名的新网络范围。

**参数：**
- `scope`（NetworkScope，必填）：要创建的范围
  - `name`（string）：范围的唯一名称（例如 `"office"`、`"lab"`）
  - `home_domain`（string）：保留的 `.home` 域名。为空时默认为 `"<name>.home."`
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `DeleteNetworkScope`

**路径：** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

删除一个网络范围及其所有记录与关联。

**参数：**
- `name`（string，必填）：要删除的范围名称
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `ListNetworkScopes`

**路径：** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

获取所有已配置的网络范围。

**参数：**
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `scopes`（repeated NetworkScope）：所有已配置的范围

#### `JoinNetwork`

**路径：** `/rolodex_dns.RolodexDnsService/JoinNetwork`

把一个客户端 IP 地址关联到某个网络范围。这个关联带有 TTL，必须定期刷新才能维持 DNS 解析。

**参数：**
- `ip_address`（string，必填）：要关联的客户端 IP（例如 `"192.168.1.100"`）
- `scope_name`（string，必填）：要加入的网络范围名称
- `ttl_seconds`（uint64）：TTL（秒）。设为 0 时默认为 300。必须在到期前刷新。
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `LeaveNetwork`

**路径：** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

移除某个 IP 地址与其网络范围的关联。

**参数：**
- `ip_address`（string，必填）：要解除关联的客户端 IP
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `GetNetworkAssociations`

**路径：** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

获取 IP 对范围的关联。

**参数：**
- `scope_name`（string）：按范围名称筛选。为空时返回所有关联。
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `associations`（repeated NetworkAssociation）：符合条件的关联
  - `ip_address`（string）：被关联的 IP
  - `scope_name`（string）：范围名称
  - `ttl_seconds`（uint64）：该关联的 TTL

#### `AddScopedRecord`

**路径：** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

在指定的网络范围内新增一条 DNS 记录。范围内记录只对关联到该范围的 IP 可见。

**参数：**
- `scope_name`（string，必填）：要新增记录的范围
- `record`（DnsRecord，必填）：要新增的 DNS 记录
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `message`（string）：`success` 为 false 时的错误信息

#### `RemoveScopedRecord`

**路径：** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

从指定的网络范围移除 DNS 记录。

**参数：**
- `scope_name`（string，必填）：要移除记录的范围
- `name`（string，必填）：要移除记录的完整域名
- `record_type`（RecordType）：可选的类型筛选
- `value`（string）：可选的完全相同值筛选
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `success`（bool）：操作是否成功
- `removed_count`（uint32）：被移除的记录条数
- `message`（string）：`success` 为 false 时的错误信息

#### `ListScopedRecords`

**路径：** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

查询某个网络范围内的 DNS 记录。

**参数：**
- `scope_name`（string，必填）：要查询的范围
- `name_filter`（string）：按域名筛选（支持 `"*."` 通配符前缀）
- `record_type_filter`（RecordType）：按记录类型筛选（仅在 `filter_by_type` 为 true 时套用）
- `filter_by_type`（bool）：是否套用 `record_type_filter`。默认：false
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `records`（repeated DnsRecord）：符合条件的范围内记录

#### `GetSearchDomains`

**路径：** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

获取某个客户端 IP 地址的搜索域。返回该 IP 所关联范围的 `.home` 域名。

**参数：**
- `ip_address`（string，必填）：要查询的客户端 IP
- `auth_token`（string）：认证用的共享密钥

**响应：**
- `search_domains`（repeated string）：该 IP 的搜索域（通常是范围的 `.home` 域名）

#### 其他 gRPC 方法

以下方法同样可用。完整的请求／响应定义请见 `proto/rolodex_dns.proto`。

| 方法 | 说明 |
|------|------|
| `AddAuthoritativeZone` | 声明某个区域为权威（置 AA 位、不转发到上游） |
| `RemoveAuthoritativeZone` | 从权威列表中移除某个区域 |
| `ListAuthoritativeZones` | 列出所有权威区域 |
| `GetCacheStats` | 获取 DNS 缓存统计（条目数、命中、未命中） |
| `FlushDnsCache` | 清空 DNS 响应缓存 |
| `SetTtlDriftConfig` | 配置 TTL 漂移调整（固定或对数模式） |
| `GetTtlDriftConfig` | 获取 TTL 漂移配置 |
| `GetQueryLatencyStats` | 获取逐服务器的上游查询延迟统计 |
| `SetResolutionMode` / `GetResolutionMode` | 在运行期切换上游解析模式，并读取当前实际生效的模式 |
| `SetTrackedTlds` / `ListTrackedTlds` | 替换受追踪的 TLD 列表，并读取已存、专属与实际生效的集合 |
| `AddLocalBlocklistEntry` | 新增一条本地封锁条目 |
| `RemoveLocalBlocklistEntry` | 移除一条本地封锁条目 |
| `ListLocalBlocklistEntries` | 列出所有本地封锁条目 |
| `SetDnsblConfig` / `GetDnsblConfig` | 配置／获取域名封锁列表（DNSBL）设置 |
| `AddDnsblAllowlistEntry` | 让某个名称（及其子域名）豁免于封锁列表检查 |
| `RemoveDnsblAllowlistEntry` | 移除一条 DNSBL 允许列表条目 |
| `ListDnsblAllowlistEntries` | 列出所有 DNSBL 允许列表条目 |
| `AddScopeTld` | 为某个范围注册一个全局唯一的专属 TLD；可选的 `listen_ip` 会同时启动一个入口 DNS 监听器 |
| `RemoveScopeTld` | 移除一个专属 TLD（以及在无人使用后移除其入口监听器） |
| `ListScopeTlds` | 列出某个范围所拥有的 TLD |
| `SetScopeTldForwarders` / `ListScopeTldForwarders` | 管理某个 TLD 的对等转发器 |
| `ListScopeTldListeners` | 列出绑定到某个范围各 TLD 的入口 DNS 监听器 |
| `AddDhcpPool` / `RemoveDhcpPool` / `ListDhcpPools` | 管理各范围的 DHCP 地址池 |
| `ListDhcpLeases` / `DeleteDhcpLease` | 查看与删除 DHCP 租约 |
| `SetDhcpCertOption` / `RemoveDhcpCertOption` / `ListDhcpCertOptions` | 管理通过 DHCP 选项交付的证书 |
| `EnsureZoneCa` | 若不存在则创建逐区域的中间证书颁发机构；返回根 + 中间 PEM |
| `CreateEabCredential` / `RemoveEabCredential` | 铸造或移除一份限定于某区域的 EAB 凭据 |
| `ListAcmeAccounts` / `ListAcmeCertificates` | 列出 ACME 账号与已签发的证书 |
| `SetDotConfig` / `GetDotConfig` | 配置／获取 DNS-over-TLS 设置 |
| `SetDohConfig` / `GetDohConfig` | 配置／获取 DNS-over-HTTPS 设置 |
| `SetDoqConfig` / `GetDoqConfig` | 配置／获取 DNS-over-QUIC 设置 |
| `SetProxyConfig` / `GetProxyConfig` | 配置／获取 HTTP 代理设置 |
| `GenerateDnssecKey` | 为某个区域生成一组 DNSSEC 密钥对 |
| `ListDnssecKeys` | 列出某个区域的 DNSSEC 密钥 |
| `DeleteDnssecKey` | 删除一把 DNSSEC 密钥 |
| `GetDsRecords` | 获取供父区域委派使用的 DS 记录 |
| `SignZone` | 用区域的 DNSSEC 密钥为它签名（或重新签名） |
| `GenerateTlsaRecord` | 从一张 PEM 证书生成一条 TLSA 记录 |
| `ListTlsaRecords` | 列出某个域名的 TLSA 记录 |
| `GenerateDaneRootCa` | 生成一张自签的 DANE 根证书颁发机构证书 |
| `RequestAcmeCert` | 通过 ACME DNS-01 挑战请求证书 |
| `GetAcmeStatus` | 获取某个域名的 ACME 证书状态 |
| `SetDns64Config` / `GetDns64Config` | 配置／获取 DNS64 合成设置 |

### 记录类型

| 枚举值 | 名称 | 说明 |
|--------|------|------|
| 0 | `A` | IPv4 地址映射。值：IPv4 地址（例如 `"192.168.1.1"`） |
| 1 | `AAAA` | IPv6 地址映射。值：IPv6 地址（例如 `"::1"`） |
| 2 | `CNAME` | 正式名称别名。值：目标完整域名（例如 `"target.example.com."`） |
| 3 | `MX` | 邮件交换。值：邮件服务器完整域名。使用 `priority` 字段 |
| 4 | `TXT` | 文本记录。值：文本内容 |
| 5 | `NS` | 名称服务器。值：名称服务器的完整域名 |
| 6 | `SOA` | 授权起始。值：`"mname rname serial refresh retry expire minimum"`（以空格分隔） |
| 7 | `SRV` | 服务定位。值：`"weight port target"`（以空格分隔）。使用 `priority` 字段 |
| 8 | `PTR` | 反向 DNS 指针。值：目标完整域名 |
| 9 | `URI` | URI 资源记录（RFC 7553）。值：`"priority weight \"uri\""` |
| 10 | `SSHFP` | SSH 指纹（RFC 4255）。值：`"algorithm fp_type fingerprint"` |
| 11 | `DNAME` | 委派名称（RFC 6672）。值：目标完整域名（改写整棵子树） |
| 12 | `ANAME` | 别名（草案）。值：目标完整域名（查询时才解析，可用于区域顶点） |
| 13 | `ZONEMD` | 区域消息摘要（RFC 9156）。值：`"serial scheme hash_algorithm digest"` |
| 14 | `TLSA` | TLS 证书关联（RFC 6698）。值：`"usage selector matching_type cert_data"` |
| 15 | `DNSKEY` | DNSSEC 公钥。由 DNSSEC 密钥生成流程自动管理 |
| 16 | `DS` | 委派签署者。由 DNSSEC 自动管理 |
| 17 | `RRSIG` | DNSSEC 资源记录签名。由区域签名自动管理 |
| 18 | `NSEC` | 下一个安全记录（DNSSEC）。由区域签名自动管理 |
| 19 | `NSEC3` | 下一个安全记录 v3（DNSSEC）。由区域签名自动管理 |
| 20 | `NSEC3PARAM` | NSEC3 参数（DNSSEC）。由区域签名自动管理 |
| 21 | `CERT` | 在 DNS 中存储证书（RFC 4398）。值：`"cert_type key_tag algorithm base64_cert_data"`。用于分发证书链 |
| 22 | `SVCB` | 服务绑定（RFC 9460）。值是一行表示格式：`"<priority> <target> [key=value ...]"`——例如 `"1 dns.home. alpn=dot port=853"`。DDR 在 `_dns.resolver.arpa.` 上发布的指定记录就是这个类型（RFC 9462）|
| 23 | `HTTPS` | HTTPS 专用的 SVCB 形式（RFC 9460 §9）。值的格式与 `SVCB` 相同 |

## 隐私优先的缓存

Rolodex DNS 会在本地缓存 DNS 响应，因此对同一个名称的重复查询无需接触任何上游转发器即可作答。这可防止 DNS 查询泄漏——一旦某条记录被缓存，外部观察者就再也看不到这个查询又被发出过。

缓存区分两种条目：

- **本地记录**（来自 SQLite 数据库）：以稳定的 TTL 缓存在内存中（不衰减）。这些条目不会被持久化到缓存的后端存储，因为它们本来就存在数据库里。只要记录通过 gRPC 被新增、移除或修改，内存中的 DNS 缓存就会自动失效，因此变更会立即生效。
- **转发回来的响应**（来自上游解析器）：以会衰减的 TTL 缓存，并持久化到一张以 SQLite 为后端的缓存表。重启时已持久化的条目会被重新加载，因此缓存立刻就是预热的。

否定答案（权威的 NXDOMAIN/NODATA）另外分开缓存，时长为区域所发布的 RFC 2308 否定 TTL（`min(SOA MINIMUM, SOA TTL)`）。为某个名称新增本地记录会丢掉它此前被缓存的否定结果，因此新加入的名称会立即解析，而不必等否定 TTL 走完。

缓存统计可通过 `GetCacheStats` 获取，缓存可通过 `FlushDnsCache` 清空。

若要达到最高的隐私程度，请设置 `resolution.mode: forward` 搭配 `forwarders: []`，让 Rolodex DNS 以纯权威服务器的形式运行，完全不做任何外部解析。所有答案都会来自本地数据库。

## 上游解析

无法在本地满足的名称会按 `resolution.mode` 解析：

| 模式 | 行为 |
| ---- | ---- |
| `auto`（默认） | 下面的分层后备链 |
| `recursive` | 只从根服务器迭代解析；绝不接触任何上游解析器 |
| `forward` | 只转发到已配置的 `forwarders` |

**配置文件只是启动时的种子。** `resolution.mode` 只在启动时
读一次；从那以后，生效的模式就是
[`SetResolutionMode`](#setresolutionmode) 最后一次设定的那个，而 [`GetResolutionMode`](#getresolutionmode) 报告的是真正在解析查询的
那个。一次切换之后两者就会不同——为了改模式绝不重启正在运行的服务器，因为
重启一台机器唯一的解析器，就是让它上面的一切都断一次
DNS。`rolodex-dns-cli set-resolution-mode` /
`get-resolution-mode`
就是这两个调用在命令行上的写法。

**`arpa.` 一律不在这台机器之外解析。** 在每一种模式下，`arpa.` 及其底下的一切，要么由本地数据回答——一条已存的 PTR、一条带范围的记录、一个受管理或具权威的反解区域——要么就是 **REFUSED**。那个子树里没有任何东西会被发送到根服务器、转发器或加密上游。返回 REFUSED 而不是 NXDOMAIN，是因为服务器是在拒绝为某个命名空间作答，而不是在宣称那个名称不存在。

这条规则是在标签边界上匹配的，因此 `notarpa.` 与 `arpa.example.com` 都是普通名称，会正常解析。在你把这个开在一台有人在用的机器上之前，有两个后果值得先知道：对于你没有任何数据的地址，反向查找会被拒绝，而不是从互联网取得答案（`dig -x 8.8.8.8`）；而 `ipv4only.arpa` 会被拒绝，正在探索 NAT64 的客户端会把这读成“这里没有 NAT64”。

### `auto` 后备链

各层级按“最受偏好（最受信任）优先”的顺序尝试：

| 层级 | 路径 | 理由 |
| ---- | ---- | ---- |
| 0 | 从根服务器迭代解析 | 没有第三方看得到你的查询 |
| 1 | 对 `resolution.secure_upstreams` 使用 DoH（`:443`）或 DoT（`:853`） | 已加密，且使用的端口能撑过 `:53` 过滤 |
| 2 | 对 `forwarders` 使用明文 Do53 | 本地／由 DHCP 提供的解析器 |
| 3 | 对 `resolution.public_fallback` 使用明文 Do53 | 最后手段 |

DoH 优先于 DoT，因为 `:443` 看起来就像普通的 HTTPS，能撑过那种“让 DoT 连接建立起来、却把它的 TLS 会话丢掉”的深度包检测。安全上游是**以 IP** 拨号，并用配置的 `hostname` 验证证书，因此这个层级启动时不需要任何先行的 DNS。

一个层级只有在传输成功且 rcode 为 NoError 或 NXDOMAIN 时才算“胜出”；SERVFAIL、REFUSED 与无法解析的响应会往下落。胜出的层级是**粘滞的**，因此查询不会每次都在一条死掉的路径上付出超时代价。恢复到更受偏好的层级是立即发生的；降级到较差的层级则要在连续 `resolution.switch_grace_failures` 次偏离的查询之后才提交，因此一次不稳的查询无法把解析器搞得来回震荡。**客户端查询绝不会被拿去探测**：起始层级一律就是已提交的层级。一个后台任务会每隔 `resolution.recovery_probe_secs` 以自己的一次性探针重新测试位于其上的那些层级，而要夺回第 0 层需要根区域自身 `DNSKEY` 的一个通过 DNSSEC 验证的答案——光靠“连得上”，会让任何劫持 `:53` 的中间盒把自己安装成最受信任的层级。每一次已提交的层级切换都会清空 DNS 缓存，因此某个层级的答案不会在切换到另一个层级后还残留着。

### 迭代解析器

解析器会从根服务器往下走访委派链——根 → TLD → 权威——并清除 recursion-desired 位，以事务 ID 与问题名称验证响应以抵御路径外欺骗，走 UDP 并在被截断时自动退回 TCP。

- **根服务器提示与预热。** 那 13 个 IANA 根地址（仅 IPv4，因此纯 v4 主机绝不会卡在 v6 的根上）是一个启动引导：Rolodex 会在启动时去问根服务器“根服务器有哪些”，并以真正的 TTL 缓存实际的 `.` NS 集合。预热绝不会在查询路径上运行，而在它失败时，那些提示仍是后备。可用 `resolution.root_hints` 覆盖。
- **负载分散到各服务器。** 名称服务器是按最低的 `hits × 平均延迟` 选出的，这会把查询分配成 `hits ∝ 1/latency`：快的服务器承担较多，但每一台健康的服务器都承担一些。这是刻意避免把每一次冷查询都钉在同一台根服务器上（无论是“第一台”还是“最快的那台”），因为那会招来速率限制，并把每次查找都变成一次超时与故障转移。
- **失败退避。** 一台失败的服务器会被暂停 2 秒，每次连续失败加倍，最高 300 秒，并在它首次成功时清除。处于退避中的服务器排在最后，但绝不会被丢弃，因此即使所有东西都在失败，解析仍会继续。
- **有界的工作量。** 每台名称服务器 1.5 秒超时、30 次转介、16 次 CNAME 跳转、深度 16、每个无粘合记录的委派最多尝试 4 台名称服务器，以及每次客户端查找最多 64 次上游查询的硬上限——各轴向的限制是相乘的，所以总量被直接封顶。

### 解析器缓存

有两份尊重 TTL 的缓存位于答案缓存之下，保留递归过程中一路学到的东西：

- **委派缓存**——“区域 → 名称服务器地址”，从每一次转介中学得。一次预热过的 `.com` 查找会完全跳过根那一跳。TTL 超过 `resolution.delegation_persist_min_ttl`（默认 300 秒）的委派会被持久化到 SQLite 并在开机时重新加载，因此重启后回来时是预热的；根与 TLD 的 NS 集合带有数天的 TTL，所以恰好是值得保留的那些条目存活了下来。
- **记录缓存**——粘合记录、无粘合记录的 NS 名称查找，以及 CNAME 跳转，以 `(name, type)` 为键，并以它们**剩余的**寿命提供。

两者都能撑过记录变更（新增一条记录绝不该把全世界的名称都送回根服务器），只有在 `auto` 模式的层级切换时才会被清空。

TTL 一律按发布的原样采用——包括区域 SOA 的否定 TTL，它从不被钳制。`resolution.default_ttl` 只在完全没有任何可用 TTL 的情况下才套用。

## 地址族过滤

网络经常会通告一条 IPv6 默认路由，然后把所有 v6 流量默默丢掉（在纯 v4 的 NAT 上则会发生镜像的情况）。一个拿到自己主机无法路由之地址族的客户端，会卡在那个死掉的族上而不是改用另一族——这正是在 v6 坏掉的连接上让容器镜像拉取卡死的那个故障。

在 `address_family.mode: auto`（默认值）下，后台探测会以 TCP 连到公共任播解析器的 `:443`——那是真实流量所使用的端口，也是能撑过某些网络强加的 `:53`／`:853` 过滤的端口——以测试**实际的**各地址族可达性。属于不可达族的 A/AAAA 记录接着会从答案中被丢掉（变成 NODATA），让客户端改用可用的协议栈。

第一次探测会在启动时同步运行且具决定性，因此开机到一条死掉地址族的连接上时，从第一次查询起就会抑制该族。之后，一个原本正常的族只有在连续 `address_family.fail_threshold` 轮探测都失败后才会被标记为不可用，而恢复则在首次成功时就生效。设置 `mode: off` 可一律两族都回答，或用 `force4`／`force6` 不做探测直接钉住一族。

## 加密传输

Rolodex DNS 支持三种加密的 DNS 传输协议，用以防止 DNS 查询被窃听：

**DNS-over-TLS（DoT）**——RFC 7858，默认端口 853，ALPN 代号 `dot`。标准的、以 TLS 封装的 TCP 上 DNS，使用同样的 2 字节长度前缀分帧。ALPN 代号是通告而非强制：提供 `dot` 的客户端会协商到它，只提供其他协议的客户端会被拒绝，而完全不发送 ALPN 扩展的客户端照样获得服务。以 YAML 中的 `dot` 段或通过 gRPC 的 `SetDotConfig` 配置。

**DNS-over-HTTPS（DoH）**——RFC 8484，默认端口 443。HTTPS 上的 DNS 查询，同时支持 GET（`/dns-query?dns=<base64>`）与 POST（`application/dns-message`）两种方法。可选择性地通过 QUIC 支持 HTTP/3（`enable_h3: true`）。以 YAML 中的 `doh` 段或通过 gRPC 的 `SetDohConfig` 配置。

**DNS-over-QUIC（DoQ）**——RFC 9250，默认端口 8853。以 QUIC 传输进行 DNS 查询，达成低延迟的加密解析。以 YAML 中的 `doq` 段或通过 gRPC 的 `SetDoqConfig` 配置。

这三种协议都需要 TLS 证书。你可以提供自己的证书与私钥，或设置 `auto_self_signed: true` 让 Rolodex DNS 自动生成一张自签证书。自动生成的证书涵盖 `localhost`、`127.0.0.1`、`::1` 以及该监听器自身的绑定地址；客户端拨打本机时所用的任何其他名称——它的主机名、它的 `.local` 名称、某个局域网别名——请加入 `self_signed_sans`，因为配置了认证名称的客户端会去校验它，而通配绑定本身并不提供任何名称。

**可以指名一份尚不存在的证书。** 只有在 `auto_self_signed` 关闭时，`cert_path`／`key_path` 指向一个不存在的文件才是硬性失败。开启它之后，监听器会先用生成的材料起步，而证书轮询器会在真正的那一对出现的当下把它接过去——不需要重启，也没有什么要协调。正是这一点让一个监听器可以被配置成使用一份别的东西尚未签发的证书，而在一台 CA 是在解析器启动之后才被创建的机器上，那本来就是常态。在 `auto_self_signed: false` 之下，缺失的文件仍然是致命的：那是运维在说"要么给我这份证书，要么什么都不要"。

**这三者都可以在服务器运行期间重新配置。** `SetDotConfig`、`SetDohConfig` 与 `SetDoqConfig` 可以打开、迁移、换钥或关停各自的监听器，无需重启；而 `Get*Config` 报告的是**实际绑定**的地址——只要请求写的是端口 0，它就与请求的不同。启动路径走的是同一段代码，因此一份从 YAML 生效的配置，经由 gRPC 到来时行为完全一致。

其中的次序值得知道，因为在旧监听器让出端口之前，新的无法启动。所有**不需要端口**就能做的检查会先做完——bind 列表可解析、TLS 材料可加载或可生成——因此一个坏地址或一份读不出来的证书会在旧监听器仍在服务时被拒绝。之后才停掉旧监听器并等待它们结束。如果绑定仍然失败，就把先前的配置放回去，并如实报告该传输已下线，而不是声称成功。空的 bind 列表是关停，不是错误。

这一切从头到尾都没有碰过 `:53`。加密传输是彼此独立的监听器，重新配置其中一个，在它自身之外不付出任何代价。

## DNSSEC

Rolodex DNS 有两个彼此独立的 DNSSEC 半边：它为自己的区域**签名**，也**验证**它从上游解析回来的答案。两者不共用任何代码——签名者处理的是我们自己写入的数据库行，每一个字节都在掌控之中；验证器处理的是来自“其诚实与否正是待证问题”的一方所发来的东西，而这两者必须有能力彼此不同意。

### 区域签名

签名支持下列算法：

- **Ed25519**（首选）——密钥与签名都精简，签名速度快
- **ECDSA P-256/SHA-256** 与 **ECDSA P-384/SHA-384**

**RSA/SHA-256（算法 8）无法生成**，且 `generate-dnssec-key` 会拒绝它：`ring` 没有 RSA 密钥生成功能。它仍然**可被解析**——一条归档在该算法下的已有密钥仍可被列出——而来自上游区域的 RSA 签名也是可验证的，但这里的任何东西都不会用它来签。一个无法端到端被贯彻的算法会在生成密钥时就被拒绝，而不是被悄悄替换掉，因为一个声称某算法却承载另一种密钥材料的 DNSKEY，会产出彼此都对不上的 DS、DNSKEY 与一整组 RRSIG，而那个失败会在某个做验证的解析器上浮现，而不是在本地。

由于 ring 密码学 crate 的限制，不支持 Ed448。

#### 签名流程

1. 为你的区域生成一把密钥签名密钥（KSK）与一把区域签名密钥（ZSK）：
   ```bash
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
   ```

2. 为区域签名：
   ```bash
   rolodex-dns-cli sign-zone --zone example.com.
   ```

3. 获取要交给注册商的 DS 记录。这件事没有对应的 CLI 子命令——请调用 `GetDsRecords` gRPC 方法（例如通过 Go 客户端的 `GetDsRecords(ctx, zone)`），或用任何 DNS 客户端从该区域查询 DS 记录。

签名会重新发布顶点的 DNSKEY RRset，并为每个 RRset 生成一条 RRSIG。新增或修改记录后请重新运行 `sign-zone`；已有的 RRSIG 是被取代而不是累积。

**不会生成经过认证的否定证明。** NSEC、NSEC3 与 NSEC3PARAM 是可存储、可列出的记录类型，但 `sign-zone` 既不生成也不提供它们，因此在这里签出来的区域只证明“存在什么”，不证明“不存在什么”。

DNSKEY、DS 与 RRSIG 以它们自己的类型码提供，RDATA 由签名者拿去做哈希的同一个规范编码器生成——送上线路的东西与被签的东西逐字节相同。

### 上游验证

**迭代**解析出来的答案会对照 IANA 根信任锚点验证。这默认是开启的：

```yaml
dnssec:
  validate: true        # 默认值
  trust_anchors: []     # 空值 = IANA 根密钥
```

它只适用于迭代路径——`recursive` 模式，以及 `auto` 的根服务器层级。转发回来的响应是别人的递归结论摘要，要验证它就意味着我们自己把整条链重新解析一遍，而那恰恰就是根服务器层级本身。因此一条已降到第 0 层以下的 `auto` 链是未经验证的，而它会以“不置 AD”如实表明。

RFC 4033 §5 的四种判定被清楚区分：

| 判定 | 含义 | 是否提供？ |
| ---- | ---- | ---------- |
| `Secure` | 签名链接到信任锚点 | 是，并为有询问的客户端置 AD |
| `Insecure` | 信任链**可证明地**中止了——路径上某个委派没有 DS，而这个“不存在”本身是被签名过的 | 是，AD 不置位 |
| `Bogus` | 数据声称自己已被签名，而这个声称站不住脚 | **绝不。** SERVFAIL |
| `Indeterminate` | 我们拿不到做出判断所需要的东西 | **绝不。** SERVFAIL |

承载安全性的区分是“非安全 vs 伪造”。“没有签名”**不等于**非安全——路径上攻击者能从任何响应中剥掉签名。只有当一份已签名的 NSEC/NSEC3 证明了上层委派处确实没有 DS 时，它才是非安全，而攻击者没有父区域的密钥就伪造不出这种证明。那份证明正是 NSEC/NSEC3 机制存在的理由；少了它，验证器就是一个会被攻击者降级成完全不存在的验证器。

它实际上的行为：

- **信任链是自上而下建立的**，与解析器本来就在执行的委派走访并行，因此 DS 就搭在转介里、不花额外代价。已验证的密钥集合（以及已被证明为非安全的委派）会逐区域缓存，因此一个已预热的区域不需要重新推导。
- **伪造的答案永不缓存**，无论正面或负面——一条被缓存的伪造否定响应会在其整个 TTL 期间压住真正的名称。在 `auto` 模式下，验证失败是一个**确定性**答案而非层级失败，所以一个坏掉的签名不可能被拿去经由某个不做验证的上游洗白。
- **AD 只在 `Secure` 时置位**，且只对设了 DO 或 AD 的客户端置位。以本地数据构造的答案永远不会置 AD。
- **对没有设置 DO 的客户端会剥除 RRSIG/NSEC/NSEC3**（RFC 4035 §3.2.1），除非它明确按名称要求该类型——一条已签名的 A 记录体积大约会变成三倍，而“小问题换大答案”正是 `security.recursion_cidrs` 存在要堵住的那种放大形状。
- **不支持的算法是非安全而非伪造**（RFC 6840 §5.11）：我们缺少某个算法，不是那个区域的故障。RSA/SHA-1/256/512、两种 ECDSA 曲线与 Ed25519 都可验证。NSEC3 迭代次数超过 100 时会被视为非安全而不去计算（RFC 9276）。
- **验证大约会让路径上每个区域多花一次查询**，因此启用验证时，每次查找的查询额度会在基础的 64 之上再加 32。
- **一个被拒绝的答案就是被拒绝，不会再问一次。** 在根服务器层级，一个扣住结果的判定是一次**确定性的** SERVFAIL：该查询不会落到加密上游或某个转发器，什么都不会被缓存，而一个验证失败的转介不会留下任何委派或粘合记录。
- **一个无法通过验证的根区域同样会被拒绝。** 过去，无法为根自己的 DNSKEY 建立锚定会表现成一个错误，而后备链把它读成“根服务器连不上”，于是改由一个不做验证的上游作答——所以只要破坏根 DNSKEY 的获取，就能在不产生任何一个 bogus 判定的情况下把验证移出路径。现在它是一项判定了。一个我们**连不上**的根仍然会往下落，这是刻意的：连不上不等于无效。这个取舍是真实存在的、也值得说明白——一个这个构建不认识的信任锚点会变成一次 DNS 中断，而不是无声的降级，而 `dnssec.validate: false` 就是逃生口。
- **一台提供无效 DNSSEC 的根服务器会被从根集合中剔除** 15 分钟，每再犯一次翻倍，上限 24 小时；依据的是那唯一一项不必问任何人就能检查的主张：它的根 DNSKEY 对照本地锚点。这项处分不会因为该服务器响应迅速而消失，只会被一个**通过验证**的答案清除（绝不会靠等待清除），而且绝不会套用在最后仅存的那一台根上——所有的根同时失败，代表问题出在区域或锚点，而不是十三台流氓服务器。它仅适用于根服务器；在根以下，验证失败通常是该区域自己的签名错误，而那些本来就已经安全地失败了。归责只存在内存中，重启后不会存续。可观察 `rolodex_dns_dnssec_blamed_roots`。

设置 `dnssec.validate: false` 的解析行为与此前完全相同：对外不置 DO 位、不建立信任链、伪造数据也不会变成 SERVFAIL。

**信任锚点。** `dnssec.trust_anchors` 采用 DNSKEY 呈现格式——`"<flags> <protocol> <algorithm> <base64 key>"`，也就是 `dig DNSKEY .` 打印出的那四个 RDATA 字段。覆盖是**取代**IANA 密钥而非追加，因此一个私有根只锚定到它自己的密钥、别无其他。每个字段都在启动时验证，而格式错误的锚点是硬性失败，不是悄悄退回——一个无法对上任何真实 DNSKEY 的锚点，会让每个已签名的区域都失败，而且没有任何线索指向锚点才是原因。

判定可通过 Prometheus 的 `rolodex_dns_dnssec_verdicts_total{verdict}` 观察，另有 `dnssec_servfail_total`、`dnssec_blamed_roots` 与 `key_cache_entries`。

## 分发与信任证书颁发机构

Rolodex DNS 自己就是一个 ACME 证书颁发机构：一张自签的**根证书颁发机构**签署**逐区域的中间证书颁发机构**，而每张中间证书签发通过 ACME 端点所核发的叶证书。客户端要信任那些证书，就必须信任根证书颁发机构。Rolodex 以三种方式分发证书链。

### 通过 DNS 分发证书颁发机构（CERT 记录，并以 TXT 为后备）

每当一个逐区域的中间证书颁发机构被创建时，Rolodex 就会把根证书与中间证书发布**到 DNS 本身**，因此任何解析得到该区域的客户端，都能在完全不接触注册门户的情况下获取并信任该证书颁发机构：

- **`CERT` 记录（RFC 4398）**位于 `_ca.<zone>.`——每张证书一条记录，RDATA 为 `"1 0 0 <base64 DER>"`（类型 1 = PKIX/X.509，key tag 与算法皆为 0）。根证书是以“自签证书”这个特征识别出来的。任何 DNS 客户端都可以用：
  ```bash
  dig CERT _ca.example.com
  ```
- **`TXT` 记录**位于 `_rolodex-ca.<zone>.`——同样的 base64 DER 被切成不超过 255 字节的块，框成 `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>`。独特的 `rolodex-ca:` 前缀把这些块与无关的 TXT 数据区分开来，而明确的序号让客户端无论答案顺序如何都能重新组装。这是给那些无法查询 `CERT` 的解析器栈使用的后备。

发布是幂等的（记录是被取代而不是重复新增），且会发生在每一个确保区域证书颁发机构存在的时点：门户注册、`EnsureZoneCa`／`CreateEabCredential` RPC，以及 ACME 的账号创建与 finalize。使用端应优先采用 `CERT`，并在必要时退回 `TXT`。

### 浏览器扩展

位于 [`extension/`](extension/) 的浏览器扩展有一个独立于门户的 **CA via DNS** 面板：给它一个 DoH URL（例如 `https://dns.example.com/dns-query`）与一个区域，它就会通过 DNS-over-HTTPS 获取证书链（优先 `CERT`，并退回 `TXT`）、分辨出哪张是根、哪张是中间、可选地对照已发布的 DANE-TA `TLSA` 记录验证中间证书，并提供根／中间／整条链的 PEM 下载。DNS 逻辑位于 `extension/ca_dns.js`，那是一个不依赖任何外部包的浏览器模块，JavaScript 测试套件也重复使用它。

### 门户与 CLI

在受信任的网络上，注册门户（`acme.portal_bind`，默认 `https://<host>:8500`）会在 `GET /api/ca` 提供根证书颁发机构，而管理 CLI 会打印出完整的链：

```bash
# 打印某个区域的根 + 中间 PEM
rolodex-dns-cli ensure-zone-ca --zone example.com

# 或从门户下载根证书颁发机构
curl -k https://<host>:8500/api/ca -o rolodex-root-ca.pem
```

获取根证书颁发机构的 PEM 之后，请把它加入每台设备的信任存储（例如 Fedora/RHEL 上的 `update-ca-trust`、Debian/Ubuntu 上的 `update-ca-certificates`、macOS 上的钥匙串访问，或 Firefox 自己的证书管理器）。通过 ACME 端点签发证书的服务器会提供一条 `叶证书 + 中间证书` 的链，它能对照这个根通过验证；支持 DANE 的客户端还可以额外通过 Rolodex 在签发时自动发布的 `TLSA` 记录来钉选中间证书。

## DNS64

DNS64（RFC 6147）会为需要连到纯 IPv4 主机的纯 IPv6 客户端，从 A 记录合成 AAAA 记录。当客户端查询 AAAA 记录而该记录不存在、但存在 A 记录时，Rolodex DNS 会把该 IPv4 地址嵌入配置好的 IPv6 前缀，构造出一条合成的 AAAA。

默认前缀是 `64:ff9b::/96`（众所周知的 NAT64 前缀）。举例来说，一条 `192.0.2.1` 的 A 记录会被合成为 `64:ff9b::192.0.2.1`（`64:ff9b::c000:201`）。

通过 YAML 配置：
```yaml
dns64:
  enabled: true
  prefix: "64:ff9b::"
```

或在运行期通过 gRPC：`SetDns64Config` / `GetDns64Config`。

## Prometheus 指标

一个可选的 `metrics` 段会在 `/metrics` 启动一个纯 HTTP 的抓取端点。这个段**默认不存在**，因此不会启动任何监听器，升级也不会开出新的端口。

```yaml
metrics:
  bind: "127.0.0.1:9153"
  # 会拿到自己 `tld` 标签的 TLD。专属 TLD 会自动被追踪。
  tracked_tlds:
    - common          # 展开成内置的常见 TLD 集合
    - lab.internal    # 其他你想隔离出来的，逐一指名
```

这个端点不做认证，且只承载汇总计数——没有查询名称、没有记录值、没有证书材料。请把它绑在私有地址上；默认是 loopback。这里刻意不提供 TLS，因为那会意味着要把一张自签证书发给每一个抓取端，而这个端点本来就不该对外可达。

输出 82 个指标系列，全部以 `rolodex_dns_` 为前缀，涵盖查询、响应缓存、封锁列表（包含拒答与被移出轮换的提供方）、上游层级、迭代解析器、DNSSEC 判定、分割视域状态、DHCP、ACME、gRPC 与运行期本身的阻塞工作。

其中最值得认识的是 `rolodex_dns_answers_total{source}`，它报告解析顺序中的哪个阶段产生了每个答案——`cache`、`local`、`scoped`、`scope_fallback`、`tld_peer`、`blocklist`、`reverse_blocklist`、`dns64`、`upstream`、`authoritative_nxdomain`、`refused`、`error`。它的总数等于查询总数，而这正是让分割视域流水线从外面看得懂的关键：

```
curl -s http://127.0.0.1:9153/metrics | grep answers_total
```

### 基数

有界的基数是一项设计约束，因为一个陌生人能无限撑大的指标端点，就是一个披着监控外衣的内存耗尽缺陷。每个标签要么是固定枚举，要么由配置所限制。**客户端**原本可能撑大的那两个维度，都被折叠进兜底值：

| 维度 | 界限 | 兜底值 |
|------|------|--------|
| `qtype` | 23 种已知记录类型 | `OTHER`——一场 `TYPE4242` 查询的洪水什么都产生不出来 |
| `tld` | 专属 TLD，加上 `metrics.tracked_tlds` | `other`——一台扫描垃圾 TLD 的扫描器什么都产生不出来 |

**查询名称永远不会成为标签。** 只有 TLD 后缀，而且只在运维人员已经主动纳入那个后缀时才有。

### 逐 TLD 隔离

`rolodex_dns_queries_by_tld_total{tld}` 把查询流按 TLD 拆开，这正是让分割视域部署中的各个网络，彼此之间、以及与公网之间得以分离的关键。有三个来源喂入这个被追踪的集合：

1. **专属 TLD，自动纳入。** 每个网络范围所拥有的 TLD——包含各范围隐含的 `.home` 域名——都不需要被指名就会被追踪。一个网络自己的命名空间是最值得隔离的东西，而要求它被写两次（一次是拥有它、一次是追踪它）是个坑，且它会以“某个系列悄悄不见”的形式浮现。
2. **配置列表。** YAML 中的 `metrics.tracked_tlds`。条目 `common` 会展开成内置的常见 TLD 集合（`com.`、`net.`、`org.`、`io.`、`dev.` 等），因此常见的公开 TLD 是一行而不是二十行。配置中的条目是被钉住的：它们撑得过重启，且无法通过 API 移除。
3. **存储列表。** 在运行期管理，不需要重启：

```bash
# 追踪常见集合，再加上一个特例 TLD
rolodex-dns-cli set-tracked-tlds --tld common --tld lab.internal

# 显示存储列表、专属列表与生效集合
rolodex-dns-cli list-tracked-tlds

# 清空存储列表（专属 TLD 与配置文件钉住的不受影响）
rolodex-dns-cli set-tracked-tlds
```

**生效**集合是三者的并集，而它才是真正产生系列的东西——这也是为什么两个命令都会把它打印出来。光看存储列表并不能告诉你哪些系列会出现。

### DNS 与 DHCP 是可分别选取的

DNS 与 DHCP 是两个恰好共用同一个进程的独立服务，它们的系列是刻意被分开的：

- DHCP 的系列把它们的维度命名为 **`message_type`** 与 **`lease_state`**，而不是通用的 `type` 与 `state`。通用的标签名称，正是让横跨两个子系统的聚合——例如某条记录规则里的 `sum by (type) (...)`——悄悄把 DHCP 的 ACK 计数混进 DNS 计数的原因。
- DNS 的汇总指标（`queries_total`、`traffic_bytes_total`、`records_served_total`、`queries_by_tld_total`）**只计 DNS**。`:67` 上的 DHCP 数据包从不被算成 DNS 流量，而一个由 DHCP 注册的名称，只有在真的有人去解析它时才会对 DNS 指标有所贡献。

> **升级提醒：** `rolodex_dns_dhcp_messages_total{type}` 改为 `{message_type}`，而 `rolodex_dns_dhcp_leases{state}` 改为 `{lease_state}`。选用旧标签名称的仪表板与告警需要更新。

### 常用查询

```promql
# 按传输方式的查询速率
sum by (proto) (rate(rolodex_dns_queries_total[5m]))

# 解析顺序中的哪个阶段正在作答
sum by (source) (rate(rolodex_dns_answers_total[5m]))

# NXDOMAIN 占所有答案的比例
sum(rate(rolodex_dns_queries_total{rcode="NXDOMAIN"}[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# 响应缓存命中率
sum(rate(rolodex_dns_cache_hits_total[5m]))
  / (sum(rate(rolodex_dns_cache_hits_total[5m])) + sum(rate(rolodex_dns_cache_misses_total[5m])))

# 各传输方式的 p99 查询延迟
histogram_quantile(0.99, sum by (le, proto) (rate(rolodex_dns_query_duration_seconds_bucket[5m])))
```

流量体积，以及其中有多少是真正的记录而非否定答案：

```promql
# 进出的线路字节数
sum by (direction) (rate(rolodex_dns_traffic_bytes_total[5m]))

# 放大倍数：每收到一字节所发出的字节数。在一个对外可达的监听器上，
# 这个数值持续攀升就是反射攻击的形状。
sum(rate(rolodex_dns_traffic_bytes_total{direction="tx"}[5m]))
  / sum(rate(rolodex_dns_traffic_bytes_total{direction="rx"}[5m]))

# 每次查询返回的记录数——一百万次 NXDOMAIN 与一百万次有内容的答案，
# 查询数相同，工作量却天差地别。
sum(rate(rolodex_dns_records_served_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))
```

封锁列表——真正重要的是“封锁数”与“拒答数”这一对，因为若只盯着封锁计数器，一份已经停止回答的列表看起来会跟一份干净的列表一模一样：

```promql
# 按实际命中的是哪份列表来分的封锁数
sum by (kind) (rate(rolodex_dns_blocklist_blocks_total[5m]))

# 被封锁的部分占所有流量的比例
sum(rate(rolodex_dns_blocklist_blocks_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# 按命中路径分的允许列表活动。这里持续攀升，代表运维人员正在
# 不断替一份误判中的列表打补丁。
sum by (kind) (rate(rolodex_dns_blocklist_allowlisted_total[5m]))

# 某个提供方已开始拒答我们，而不是在报告信誉
sum by (kind) (rate(rolodex_dns_blocklist_refusals_total[5m])) > 0

# 目前被移出轮换的提供方
rolodex_dns_blocklist_rotated_out > 0
```

逐 TLD、上游健康状况与 DNSSEC：

```promql
# 每个被追踪 TLD 的查询速率，忽略未追踪的兜底值
sum by (tld) (rate(rolodex_dns_queries_by_tld_total{tld!="other"}[5m]))

# 有多少比例的流量是你并未追踪的名称
sum(rate(rolodex_dns_queries_by_tld_total{tld="other"}[5m]))
  / sum(rate(rolodex_dns_queries_by_tld_total[5m]))

# 已从迭代层级降级（0=根服务器、1=安全、2=本地、3=公共）
rolodex_dns_upstream_active_tier > 0

# 层级抖动
sum by (direction) (rate(rolodex_dns_upstream_tier_switches_total[5m]))

# 验证失败的已签名数据：可能是攻击，也可能是某个区域自己把签名弄坏了。
# 这与 `indeterminate` 不同，后者是网络故障。
sum(rate(rolodex_dns_dnssec_verdicts_total{verdict="bogus"}[5m])) > 0

# 当前因为提供无法通过验证的 DNSSEC 而被剔除的根服务器。
# 一个稳定的非零值代表某台根实例被劫持或坏掉了；所有的根同时
# 出现，代表问题出在信任锚点或根区域，而不是那些服务器。
rolodex_dns_dnssec_blamed_roots > 0

# 因为委派超出作答区域而被丢弃的转介
rate(rolodex_dns_resolver_out_of_bailiwick_total[5m]) > 0

# 被逐次查找的查询额度终止掉的查找
rate(rolodex_dns_resolver_budget_exhausted_total[5m]) > 0
```

DHCP，使用隔离过的标签名称：

```promql
# 按状态分类的租约
rolodex_dns_dhcp_leases{lease_state="active"}

# 按类型分类的 DHCP 消息速率
sum by (message_type) (rate(rolodex_dns_dhcp_messages_total[5m]))

# 地址池耗尽
rate(rolodex_dns_dhcp_allocation_failures_total[5m]) > 0
```

控制平面与主机可达性：

```promql
# 有人正在猜测 gRPC 共享密钥
rate(rolodex_dns_grpc_auth_failures_total[5m]) > 0

# 一个主机无法路由的地址族，因此它的记录正在被抑制
rolodex_dns_address_family_reachable{family="ipv6"} == 0
```

运行期阻塞——同步工作正占用着本该在服务查询的线程的地方。`db_lock_wait` 与 `db_locked` 是那条唯一 SQLite 连接的两半：等待时间是别的调用者让你付出的代价，持有时间是你让他们付出的代价。

```promql
# 每一秒里，所有工作线程合计花在被阻塞上的时间有多少，按 site 分。
# 通常的答案是那条唯一的 SQLite 连接；`db_lock_wait` 上升而 `db_locked` 持平
# 表示争用，反过来则表示语句本身变慢了。
sum by (site) (rate(rolodex_dns_blocking_duration_seconds_sum[5m]))

# 排在那条唯一数据库连接后面的第 99 百分位等待时间
histogram_quantile(0.99, sum by (le) (rate(rolodex_dns_blocking_duration_seconds_bucket{site="db_lock_wait"}[5m])))

# 把一条线程占住 10ms 以上的阻塞区段。在工作线程位置上
# （db_locked、db_lock_wait、dnssec_verify、metrics_collect），这些就是
# 没有被轮询到的查询。
sum by (site) (rate(rolodex_dns_blocking_stalls_total[5m]))

# 抓取成本占抓取间隔的比例：/metrics 正在跟查询路径争同一条连接。
# 超过几个百分点，就把间隔拉长。
rate(rolodex_dns_blocking_duration_seconds_sum{site="metrics_collect"}[5m])
  / rate(rolodex_dns_metrics_scrapes_total[5m])

# 验证一个 RRset 的签名、含整组候选密钥的平均时间
rate(rolodex_dns_blocking_duration_seconds_sum{site="dnssec_verify"}[5m])
  / rate(rolodex_dns_blocking_duration_seconds_count{site="dnssec_verify"}[5m])
```

上面每一条查询都有测试涵盖，会把它的指标名称与标签匹配条件对照实际输出解析，因此文档中的查询不可能引用到不存在的系列。

## 封锁列表

Rolodex DNS 以两种方式封锁名称，被封锁的查询都会得到 `NXDOMAIN`：

- **DNSBL 提供方** —— 以名称查询的第三方区域，见下文 [DNSBL（域名封锁列表）](#dnsbl域名封锁列表)。
- **本地列表** —— 一份由运维人员手工封锁的名称与地址，存放在数据库中。

两者默认均为禁用／为空：在加入提供方之前，不会发出任何外部查询，也不会把任何名称交给封锁列表运营方。

### 本地封锁列表数据库

本地条目是运维人员自己的列表，会在询问任何提供方之前先行检查，并通过 `AddLocalBlocklistEntry`、`RemoveLocalBlocklistEntry` 与 `ListLocalBlocklistEntries` 管理。

一条条目可以命名一个**域名**（在正向名称这一道关卡匹配），也可以命名一个**地址**（在反向查找时匹配）。地址两种写法皆可——IP 字面量，或 `dig -x` 打印出的 `in-addr.arpa`／`ip6.arpa` 名称——两种写法都会封锁。地址永远只由这份列表封锁：提供方被问及的是正在解析的那个名称，而在反向查找中，那是一个没有人会为其发布信誉数据的名称。

```bash
# 以一个理由封锁特定 IP
rolodex-dns-cli add-local-blocklist --name 10.0.0.5 --reason "known spam source"

# 列出本地条目
rolodex-dns-cli list-local-blocklist

# 移除一条条目
rolodex-dns-cli remove-local-blocklist --name 10.0.0.5
```

### 缓存

- 正面结果（名称已列入）按提供方返回的 TTL 缓存
- 负面结果（未列入）缓存 5 分钟
- 查找错误不缓存，并被视为未列入，以避免误判
- 拒答同样不缓存，并会把该提供方移出轮换——见下文
- 缓存可通过 `FlushCache` gRPC 方法清空，该方法同时会把每一个被移出轮换的提供方放回轮换

### 拒答码与提供方轮换

一份 DNSxL 回答“已列入”与抱怨**你**用的是同一种方式：`127.0.0.0/8` 之下的一条 `A` 记录。`zen.spamhaus.org` 用 `127.0.0.2` 说“已列入”，用 `127.255.255.254` 说“你正通过公共解析器发问”，而**唯一能区分两者的就是地址本身**。把任何 `A` 记录都读成“已列入”，就等于在封锁列表决定不再回答你的那一刻，把**每一个**对照该提供方检查过的名称都变成 NXDOMAIN——而这会在你的查询量越过该提供方门槛时开始发生，可能是一次看起来一切正常的部署之后好几小时或好几周。Spamhaus 讲得很直接：那些码“不应被解读为任何形式的信誉评价”。

因此每个提供方都带有一组拒答码。符合的答案是 **`Refused`**：不是列入、不是否定、什么都不缓存——对被查询的名称什么都没学到。同一个响应中，任何位置的拒答都胜过同一个响应中的列入，因为一个正在抱怨的提供方不会同时在报告信誉，而往这个方向犯错会**失效放行**，反过来的顺序则会在每一个名称上失效阻断。

提供方未自行设置时所使用的内建集合：

| 码 | 含义 |
| -- | ---- |
| `127.255.255.0/24` | Spamhaus 错误范围：`.252` 区域名称打错、`.254` 通过公共／开放解析器查询、`.255` 查询过量。之所以取整个范围而不是那三个码，是因为 Spamhaus 保留了它并会往里面新增 |
| `127.0.1.255` | Spamhaus DBL 回应一个 IP 查询——“不支持 IP 查询” |
| `127.0.2.255` | Spamhaus ZRD 回应一个 IP 查询——同上 |
| `127.0.0.1` | URIBL/SURBL 的“查询已被封锁”。RFC 5782 §5 同时禁止 DNSxL 列入 `127.0.0.1`，因此它绝不可能是一个正当的列入 |
| `127.0.0.255` | URIBL 的“查询已被封锁”（超出配额） |

每一项是一个 IPv4 地址或 `address/prefix`。**空值代表内建集合**——它不可能代表“没有任何码”，因为在这项功能存在之前写的每一份配置都是空的。单一条目 `none` 可为那些真实列入值恰好与上述之一相撞的私有封锁列表禁用检测。明确列出的列表就只是那份列表；默认值不会被合并进来，所以把它写出来的运维人员也可以借此缩小范围。无法解析的码会被拒绝——在启动时，或由 RPC 回以 `InvalidArgument`——而不是被跳过，因为一个悄悄失效的码，就是一个会被读成“已列入”的拒答。

**轮换。** 一次拒答会把该提供方移出查询轮换 `refusal_cooldown_secs`（默认 3600 秒，可逐提供方覆盖），因此一份刚刚叫你别再问的封锁列表会被退避，而不是每次请求都再去问一遍。轮换：

- 只跳过**新的查找**——已缓存的判定仍然算数，因为“这个提供方不会回答新问题”不等于“它此前给的答案是错的”；
- 会**自行失效**，因此短暂的超额配额期不需要运维人员动手就会自愈；
- 会被 `flush-cache` 以及任何 `set-dnsbl-config` **清除**——重新配置往往正是那次拒答的修正动作（区域名称打错既是 `127.255.255.252` 的成因，也正是被修正的那个东西）；
- 会被 `get-dnsbl-config` 以及 `rolodex_dns_blocklist_refusals_total{kind}` / `rolodex_dns_blocklist_rotated_out` **报告出来**。

把冷却设为 `0` 代表“使用默认值”，而不是“不冷却”——零冷却等于去重问那个刚刚叫你别问了的提供方，而那正是轮换存在要防止的行为。

## DNSBL（域名封锁列表）

DNSBL 提供方是以**域名**封锁：被查询名称的标签会前置到提供方的区域之前，因此 `googleadservices.com` 对照 `dbl.spamhaus.org` 会被查询成 `googleadservices.com.dbl.spamhaus.org`。Spamhaus DBL、SURBL 与 URIBL 都是这样运作的。

DNSBL 让封锁列表**优先于外部 DNS**。这道检查在本地记录与受管／权威区域之后运行——因此内部数据一律胜出——但在上游响应缓存与任何外部解析**之前**。因此即使此前已为某个被列入的名称缓存了一个转发答案，它仍然会回 NXDOMAIN。

DNSBL 默认为禁用且提供方列表为空，单个提供方也可独立启用或禁用。一个已启用但为空的 DNSBL 是空操作。运维人员通常会加入的标准区域是 `dbl.spamhaus.org`、`multi.surbl.org` 与 `multi.uribl.com`。结果如上所述地缓存（正面结果按提供方 TTL，负面结果 5 分钟）。

```bash
rolodex-dns-cli set-dnsbl-config --enabled --providers dbl.spamhaus.org:true
rolodex-dns-cli get-dnsbl-config
```

### 为某台主机加入允许列表

允许列表是运维人员面对误判时的逃生口，而且它涵盖**所有列表与两道关卡**：正向名称检查（DNSBL 提供方与本地封锁列表）**以及**反向 DNS／IP 检查（指名某个地址的本地条目）。一个被错误列入的 IP 会让一台运作正常的主机 `dig -x` 失败，所以一个只够得到名称的逃生口根本称不上逃生口。

- **名称是后缀匹配的。** 一个条目涵盖该名称以及它底下的每一个名称，因此把 `example.com` 加进允许列表也会豁免 `www.example.com`；匹配是在标签边界上进行的，所以 `notexample.com` 不会被豁免。
- **一个地址可以用两种写法指名。** 一个反向查询会被指名 `in-addr.arpa`／`ip6.arpa` 名称**或**它所编码之 IP 字面量的条目所豁免，因此没有人需要手动反转八位组。反向**名称**像任何 DNS 名称一样以后缀匹配（把 `1.168.192.in-addr.arpa` 加进允许列表会解除整个 /24 的封锁）；而 IP **字面量**是**精确**匹配，因为地址是最高位八位组在前——`1.100` 不是 `192.168.1.100` 的父节点，把它当成父节点会豁免掉没有人指名过的地址。
- **它会整个短路掉这道检查。** 一个被豁免的名称或地址不会对照任何提供方检查，也完全不会发出任何封锁列表查找。
- 条目是归一化过的（小写、结尾带点），因此任何写法都会新增或移除同一个条目；它们会跨重启保存，且在下一次查询时就生效，不需要清空缓存。

```bash
# 豁免某台被提供方误判的主机
rolodex-dns-cli add-dnsbl-allow --name vendor.example.com --reason "blocklist false positive"

# 豁免某个地址——两种写法都可以
rolodex-dns-cli add-dnsbl-allow --name 192.168.1.100 --reason "our own mail relay"
rolodex-dns-cli add-dnsbl-allow --name 1.168.192.in-addr.arpa --reason "whole /24"

# 列出允许列表
rolodex-dns-cli list-dnsbl-allow

# 移除一条条目
rolodex-dns-cli remove-dnsbl-allow --name vendor.example.com
```

## 网络范围划分

网络范围划分提供分割视域的 DNS 视图，让 DNS 响应可以按客户端 IP 所关联的网络范围而不同。

### 概念

- **网络范围**：一个具名的 DNS 视图，拥有自己的一组 DNS 记录与一个保留的 `.home` 域名（例如 `office.home.`）。这个 `.home` 域名会被当作 DHCP 客户端的默认搜索域。
- **网络关联**：一个从客户端 IP 到某个范围的映射，带有必须定期刷新的 TTL。TTL 到期时，该 IP 会失去它的范围关联，DNS 查询也会被拒绝。
- **范围内记录**：属于某个特定范围的 DNS 记录，只对关联到该范围的 IP 可见。

### 运作方式

1. 创建一个网络范围（例如名为 `"office"`、域名为 `"office.home."`）
2. 为该范围新增范围内的 DNS 记录
3. 客户端 IP 通过关联到某个范围来加入网络（带有 TTL）
4. 当一个 DNS 查询抵达时：
   - 若它是抵达某个逐 TLD 的**入口监听器**：无论名称是什么，都在该监听器的拥有范围内作答
   - 若源 IP 已关联到某个范围：先检查范围内记录，接着落到全局记录，然后才向外解析
   - 若源 IP 位于 `security.overlay_cidrs` 之内（一个叠加网络／WireGuard 对等节点）却未加入任何范围：**REFUSED**
   - 其他任何来源——loopback、局域网、容器网桥——都受信任：它永远不会被拒绝，并解析全局命名空间
   - 若根本没有任何范围存在：沿用旧行为（所有查询都从全局记录作答）
5. 搜索域（通过 `GetSearchDomains`）会返回供 DHCP 集成使用的 `.home` 域名

### 受信任来源 vs. 叠加对等节点

范围强制**只**套用于位于 `security.overlay_cidrs`（默认 `10.64.0.0/10`，即 WireGuard 叠加网络范围）之内的源 IP。这样的对等节点必须已加入某个网络，否则就会被拒绝，而且它只看得到自己范围所分隔出来的 TLD。其他所有来源都受信任，并解析全局视图。

这正是让分割视域在实践中真正好用的地方：一个名称可以同时带有一条指向这台机器局域网地址的全局记录，与一条指向其叠加地址的范围内记录，而每一边拿到的都是它真的路由得到的地址。

### 递归访问控制

范围强制决定的是某个来源拿到**哪个视图**。另一个独立的轴向 `security.recursion_cidrs`，决定的则是某个来源究竟能不能取得**上游解析**。

`dns.bind` 默认为 `0.0.0.0:53`，因此在可路由的接口上，这个监听器对整个互联网都是可达的，而 `overlay_cidrs` 之外的每一个来源都会被归类为受信任的本地客户端。少了第二道检查，那就是一台**开放递归解析器**——经典的反射／放大攻击资产：一个小的伪冒查询会返回一个大的答案打向被伪冒的受害者，而对外的解析流量算在你的机器头上。

默认列表是每一个从互联网不可路由的范围——`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`100.64.0.0/10`、`::1/128`、`fe80::/10`、`fc00::/7`——它涵盖了 loopback、局域网、容器网桥与 WireGuard 叠加网络（`10.64.0.0/10` 位于 `10.0.0.0/8` 之内），因此任何正当使用这台服务器的东西都不会失去服务。空列表会对所有人关闭递归，留下一台纯权威服务器。

- **这道检查位于本地／远程的边界上**：在所有“从这台服务器持有的数据作答”的路径之后，在所有“去获取它没有的数据”的路径之前。一个陌生人仍然收得到你的权威答案与权威 NXDOMAIN——关闭递归绝不该把这台机器变成它自己区域的黑洞——但没办法让它去问别人。
- **它在响应缓存之前运行**，因为一个被缓存的答案放大效果跟新鲜的一样好，而把缓存预热正是这种攻击的准备手法。
- **拒绝的形式是 REFUSED 搭配空的答案段**，因此回复永远不会比引发它的问题更大。
- **每一种传输方式都受此把关**——UDP、TCP、DoT、DoQ，以及 DoH（它会带着连接信息提供服务，好让对端地址能进到分类逻辑；否则 `:443` 会把 `:53` 关上的东西重新打开）。

### 逐网络的专属 TLD

除了隐含的 `.home` 域名之外，一个范围还可以拥有额外的 TLD，用来把命名空间在各网络之间分隔开来。每个专属 TLD 对单一范围而言是**全局唯一**的，而它底下的名称绝不会被转发到上游——匹配不到的名称会产生一个权威 NXDOMAIN，并可在此之前选择性地咨询该 TLD 的**对等转发器**（同一网络中其他 Rolodex 成员的叠加地址）。

- 对一个**叠加对等节点**而言，专属 TLD 是严格分隔的：它解析得到自己网络的 TLD，而对任何其他范围的 TLD 得到 NXDOMAIN，因此两个网络的 TLD 绝不会在同一个端点上都解析得到。
- 对一个**受信任的本机来源**（loopback／局域网）而言，**每一个**专属 TLD 都能从它的拥有范围解析出来，因此所有网络 TLD 在局域网上都看得到。双栖名称仍然返回它们面向局域网的全局值；只有仅存在于范围中的名称才会从该范围提供。

因此一个范围可以纯粹为了拥有某个 TLD 而存在——把它标记为“与对等节点分隔、可从局域网解析”——而完全不需要为它绑定任何叠加网络。

```bash
# 为某个范围注册一个专属 TLD
rolodex-dns-cli add-scope-tld -s office --tld office.
# 把它底下匹配不到的名称指向该网络中其他的 Rolodex 成员
rolodex-dns-cli set-scope-tld-forwarders -s office --tld office. -f 10.64.0.2:53
rolodex-dns-cli list-scope-tlds -s office
```

### 入口 DNS 监听器

一个专属 TLD 可以在注册时附上一个本地的**入口 IP**（`add-scope-tld --listen-ip`），通常是该网络自己的叠加地址：

```bash
rolodex-dns-cli add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
rolodex-dns-cli list-scope-tld-listeners -s office
```

这会做三件事：

1. **在该 IP 上绑定一个 DNS 监听器**（UDP + TCP），端口为 `dns.ingress_listen_port`（默认 53）。监听器会在开机时从数据库重新创建，并在最后一个引用该 IP 的 TLD 被移除时拆除。一次失败的绑定——这是开机时的常见情况，因为那时叠加网络的接口还不存在——会在下一次重新注册时重试，而不是被记成“已经在监听了”。
2. **对每一个名称都提供拥有范围的视图。** 这个监听器是该网络的专用解析器，因此抵达它的查询无论名称是什么都属于拥有范围：专属 TLD 保持分隔，其他一切则落到全局解析与上游解析——这正是让对等节点可以把它当作通用解析器使用的原因。
3. **把已编程的名称改写成入口 IP。** 一个位于该 TLD 之下、且有存储 A/AAAA 记录的名称，会以入口 IP 而不是它存储的后端值作答，好让该网络的入口控制器收到流量并按 Host/SNI 路由。这一部分仍然是按名称把关的：一个穿透过去的名称会保留它解析出来的值，同一个名称在主要的 `:53` 监听器上会解析出它存储的值，而一个没有记录的名称仍然返回 NXDOMAIN（不做通配符合成）。

### 解析顺序（含范围）

1. 解析 EDNS OPT 记录（载荷大小协商、供 DNSSEC 用的 DO 位）
2. 检查本地封锁列表（针对反向 DNS 查询）
3. 检查 DNS 响应缓存
4. 检查客户端所属范围的范围内记录
5. 检查范围内的 CNAME 记录
6. 检查范围内的 DNAME 记录（子树改写）
7. 检查名称是否位于某个范围内的受管区域之下（权威 NXDOMAIN）
8. 检查全局数据库记录
9. 检查全局 CNAME 记录
10. 检查全局 DNAME 记录（子树改写）
11. 检查 ANAME 记录（在区域顶点解析别名）
12. 检查名称是否位于某个全局受管区域之下（权威 NXDOMAIN）
13. 检查通配符记录（`*.zone.`）
14. 检查本地封锁列表与 DNSBL 提供方（被列入的名称是 NXDOMAIN，优先于任何外部答案）
15. 强制执行 `security.recursion_cidrs`——不在其中的来源会在任何东西离开本机之前就被 REFUSED
16. 按 `resolution.mode` 向外解析（若已启用则使用 QNAME 大小写随机化，若有配置则经由代理），并在迭代路径上验证 DNSSEC
17. 套用 DNS64 合成（若已启用，且 AAAA 查询返回为空但存在 A 记录）
18. 缓存响应（伪造的答案永不缓存）
19. 套用 TTL 漂移调整（若有配置）
20. 丢弃属于不可路由地址族的 A/AAAA 答案（若 `address_family.mode: auto`）

## DHCP 服务器

Rolodex DNS 内含一台集成的 DHCPv4 服务器，具备 IP 地址管理与自动 DNS 注册功能。除非配置中出现 `dhcp` 段，否则它是禁用的。

- **逐范围的地址池。** 每个地址池属于某个网络范围，并定义单一连续范围、网关、子网掩码与 DNS 服务器。地址池用尽时分配即失败——不会跨池聚合。MAC 对 IP 的绑定是粘滞的：同一个 MAC 一律会拿回同一个 IP。
- **自动 DNS 注册。** 一个发出主机名（选项 12）的客户端，会在 `<hostname>.lan.<dhcp.tld>.` 取得一条 A 记录，以及一条对应的 `in-addr.arpa` PTR，两者都是该地址池所属范围中的范围内记录。这份租约同时会被加入该网络范围（`JoinNetwork`），因此该客户端会立刻看到那个网络的分割视域视图。租约被释放或到期时，这两条记录都会被移除。
- **租约状态。** `active`、`expired`（超过其时长）、`released`（客户端已释放）与 `reclaimable`（超过 `reclaim_timeout`，因此该 IP 可以再次发出）。
- **证书交付。** 证书可以通过站点专用的 DHCP 选项（代码 224–254）交给客户端，逐范围配置。
- **后台清扫。** 每隔 `sweep_interval` 秒，过期的租约会被退役（移除其 DNS 记录与范围关联），而超过 `reclaim_timeout` 的租约会释放它们的 IP。

```bash
# 给 "office" 范围的一个地址池
rolodex-dns-cli add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1

rolodex-dns-cli list-dhcp-pools -s office
rolodex-dns-cli list-dhcp-leases -s office
```

## Go 客户端

`go/` 底下附有一个 Go 客户端库，供以编程方式访问 Rolodex DNS 的 gRPC API。它可以作为 Go 模块依赖导入。

### 安装

```
go get gitea.com/town-os/rolodex-dns/go
```

### 连接

这个客户端支持两种传输方式：

**TCP**（搭配共享密钥认证）：

```go
client, err := rolodex_dns.Dial(ctx, "localhost:50051",
    rolodex_dns.WithAuthToken("my-secret"),
)
defer client.Close()
```

**Unix 套接字**（服务器端跳过认证）：

```go
client, err := rolodex_dns.Dial(ctx, "/var/run/rolodex-dns.sock",
    rolodex_dns.WithUnixSocket(),
)
defer client.Close()
```

### 客户端选项

| 选项 | 说明 |
|------|------|
| `WithAuthToken(token)` | 设置每次 RPC 都会发出、供 TCP 认证使用的共享密钥。Unix 套接字连接时服务器会忽略它。默认：空值（若服务器未配置密钥则成功） |
| `WithUnixSocket()` | 把该地址标记为 Unix domain socket 路径而非 TCP 地址。Unix 套接字连接时服务器会跳过认证 |
| `WithGRPCDialOption(opt)` | 追加一个底层的 `grpc.DialOption`（例如供 TLS 或拦截器使用） |

### 客户端方法

所有方法都接受一个 `context.Context`，供取消与截止时间使用。

#### 记录管理

| 方法 | 说明 |
|------|------|
| `AddRecord(ctx, record) error` | 新增一条 DNS 记录 |
| `RemoveRecord(ctx, name, opts) (uint32, error)` | 移除 DNS 记录（返回被移除的条数） |
| `ListRecords(ctx, opts) ([]*DnsRecord, error)` | 列出／筛选 DNS 记录 |

#### 转发器

| 方法 | 说明 |
|------|------|
| `SetForwarders(ctx, forwarders) error` | 设置上游 DNS 转发器 |
| `SetResolutionMode(ctx, mode) error` | 在运行期切换解析模式（`auto`、`recursive`、`forward`）|
| `GetResolutionMode(ctx) (string, error)` | 获取当前实际生效的模式 |

#### 封锁列表

| 方法 | 说明 |
|------|------|
| `SetDnsblConfig(ctx, enabled, providers) error` | 配置 DNSBL（域名封锁列表） |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs) error` | 同上，并附带 DNSBL 的移出轮换时长 |
| `GetDnsblConfig(ctx) (*DnsblStatus, error)` | 获取当前的 DNSBL 配置 |
| `FlushCache(ctx) error` | 清空封锁列表缓存，并把每一个被移出轮换的提供方放回轮换 |
| `AddLocalBlocklistEntry(ctx, entry) error` | 新增一条本地封锁条目 |
| `RemoveLocalBlocklistEntry(ctx, name) error` | 移除一条本地封锁条目 |
| `ListLocalBlocklistEntries(ctx) ([]*LocalBlocklistEntry, error)` | 列出本地封锁条目 |
| `AddDnsblAllowlistEntry(ctx, entry) error` | 让某个名称（及其子域名）豁免于封锁列表检查 |
| `RemoveDnsblAllowlistEntry(ctx, name) error` | 移除一条 DNSBL 允许列表条目 |
| `ListDnsblAllowlistEntries(ctx) ([]*DnsblAllowlistEntry, error)` | 列出 DNSBL 允许列表条目 |

#### 网络范围划分

| 方法 | 说明 |
|------|------|
| `CreateNetworkScope(ctx, scope) error` | 创建一个网络范围 |
| `DeleteNetworkScope(ctx, name) error` | 删除一个范围及其数据 |
| `ListNetworkScopes(ctx) ([]*NetworkScope, error)` | 列出所有范围 |
| `JoinNetwork(ctx, ip, scope, ttl) error` | 把一个 IP 关联到某个范围 |
| `LeaveNetwork(ctx, ip) error` | 移除某个 IP 的范围关联 |
| `GetNetworkAssociations(ctx, scope) ([]*NetworkAssociation, error)` | 列出关联 |
| `AddScopedRecord(ctx, scope, record) error` | 新增一条范围内的 DNS 记录 |
| `RemoveScopedRecord(ctx, scope, name, opts) (uint32, error)` | 移除范围内记录 |
| `ListScopedRecords(ctx, scope, opts) ([]*DnsRecord, error)` | 列出范围内记录 |
| `GetSearchDomains(ctx, ip) ([]string, error)` | 获取某个 IP 的搜索域 |
| `AddScopeTld(ctx, scope, tld) error` | 为某个范围注册一个全局唯一的专属 TLD |
| `AddScopeTldWithListener(ctx, scope, tld, listenIP) error` | 注册一个专属 TLD 并绑定一个入口 DNS 监听器 |
| `RemoveScopeTld(ctx, scope, tld) error` | 从某个范围移除一个专属 TLD |
| `ListScopeTlds(ctx, scope) ([]string, error)` | 列出某个范围所拥有的 TLD |
| `SetScopeTldForwarders(ctx, scope, tld, forwarders) error` | 设置某个 TLD 的对等转发器 |
| `ListScopeTldForwarders(ctx, scope, tld) ([]string, error)` | 列出某个 TLD 的对等转发器 |
| `ListScopeTldListeners(ctx, scope) ([]*TldListener, error)` | 列出某个范围的入口 DNS 监听器 |

#### DHCP

| 方法 | 说明 |
|------|------|
| `AddDhcpPool(ctx, pool) (string, error)` | 为某个范围新增一个 DHCP 地址池 |
| `RemoveDhcpPool(ctx, poolID) error` | 移除一个 DHCP 地址池 |
| `ListDhcpPools(ctx, scope) ([]*DhcpPool, error)` | 列出 DHCP 地址池 |
| `ListDhcpLeases(ctx, scope) ([]*DhcpLease, error)` | 列出 DHCP 租约 |
| `DeleteDhcpLease(ctx, mac) error` | 按 MAC 删除一条 DHCP 租约 |
| `SetDhcpCertOption(ctx, opt) error` | 通过 DHCP 选项交付一张证书 |
| `RemoveDhcpCertOption(ctx, scope, optionCode) error` | 移除一个 DHCP 证书选项 |
| `ListDhcpCertOptions(ctx, scope) ([]*DhcpCertOption, error)` | 列出 DHCP 证书选项 |

#### 权威区域

| 方法 | 说明 |
|------|------|
| `AddAuthoritativeZone(ctx, zone) error` | 声明某个区域为权威 |
| `RemoveAuthoritativeZone(ctx, zone) error` | 移除一个权威区域 |
| `ListAuthoritativeZones(ctx) ([]string, error)` | 列出权威区域 |

#### 缓存

| 方法 | 说明 |
|------|------|
| `GetCacheStats(ctx) (*CacheStats, error)` | 获取缓存统计（条目数、命中、未命中） |
| `FlushDnsCache(ctx) error` | 清空 DNS 响应缓存 |

#### 加密传输

| 方法 | 说明 |
|------|------|
| `SetDotConfig(ctx, config) error` | 配置 DNS-over-TLS |
| `GetDotConfig(ctx) (*DotConfig, error)` | 获取 DoT 配置 |
| `SetDohConfig(ctx, config) error` | 配置 DNS-over-HTTPS |
| `GetDohConfig(ctx) (*DohConfig, error)` | 获取 DoH 配置 |
| `SetDoqConfig(ctx, config) error` | 配置 DNS-over-QUIC |
| `GetDoqConfig(ctx) (*DoqConfig, error)` | 获取 DoQ 配置 |

#### 代理

| 方法 | 说明 |
|------|------|
| `SetProxyConfig(ctx, config) error` | 配置 HTTP 代理 |
| `GetProxyConfig(ctx) (*ProxyConfig, error)` | 获取代理配置 |

#### DNSSEC

| 方法 | 说明 |
|------|------|
| `GenerateDnssecKey(ctx, zone, algorithm, keyType) (*DnssecKey, error)` | 生成一组 DNSSEC 密钥对 |
| `ListDnssecKeys(ctx, zone) ([]*DnssecKey, error)` | 列出某个区域的 DNSSEC 密钥 |
| `DeleteDnssecKey(ctx, keyID) error` | 删除一把 DNSSEC 密钥 |
| `GetDsRecords(ctx, zone) ([]string, error)` | 获取要交给注册商的 DS 记录 |
| `SignZone(ctx, zone) error` | 用区域的密钥为它签名 |

#### DANE / ACME

| 方法 | 说明 |
|------|------|
| `GenerateTlsaRecord(ctx, opts) (string, error)` | 从一张证书生成一条 TLSA 记录 |
| `ListTlsaRecords(ctx, domain) ([]*DnsRecord, error)` | 列出某个域名的 TLSA 记录 |
| `GenerateDaneRootCa(ctx, name) (string, error)` | 生成一张自签的 DANE 根证书颁发机构证书 |
| `RequestAcmeCert(ctx, domain, providerURL) error` | 请求一张 ACME DNS-01 证书 |
| `GetAcmeStatus(ctx, domain) (*AcmeStatus, error)` | 获取 ACME 证书状态 |
| `EnsureZoneCa(ctx, zone) (*ZoneCa, error)` | 确保逐区域的中间证书颁发机构存在 |
| `CreateEabCredential(ctx, zone) (*EabCredential, error)` | 铸造一份限定于某区域的 EAB 凭据 |
| `RemoveEabCredential(ctx, kid) error` | 移除一份 EAB 凭据 |
| `ListAcmeAccounts(ctx) ([]*AcmeAccount, error)` | 列出已注册的 ACME 账号 |
| `ListAcmeCertificates(ctx, zone) ([]*AcmeCertificate, error)` | 列出已签发的证书 |

#### TTL 漂移

| 方法 | 说明 |
|------|------|
| `SetTtlDriftConfig(ctx, config) error` | 配置 TTL 漂移 |
| `GetTtlDriftConfig(ctx) (*TtlDriftConfig, error)` | 获取 TTL 漂移配置 |

#### DNS64

| 方法 | 说明 |
|------|------|
| `SetDns64Config(ctx, config) error` | 配置 DNS64 合成 |
| `GetDns64Config(ctx) (*Dns64Config, error)` | 获取 DNS64 配置 |

#### 可观测性

| 方法 | 说明 |
|------|------|
| `GetQueryLatencyStats(ctx) ([]*QueryLatencyStats, error)` | 获取逐服务器的延迟统计 |
| `SetTrackedTlds(ctx, tlds) ([]string, error)` | 替换受追踪的 TLD 列表；返回实际生效的集合 |
| `ListTrackedTlds(ctx) (*TrackedTlds, error)` | 获取已存、实际生效与专属的 TLD 集合 |

#### 连接

| 方法 | 说明 |
|------|------|
| `Close() error` | 关闭 gRPC 连接 |

### 记录类型

| 常量 | 值 | 说明 |
|------|----|------|
| `RecordTypeA` | 0 | IPv4 地址（默认） |
| `RecordTypeAAAA` | 1 | IPv6 地址 |
| `RecordTypeCNAME` | 2 | 正式名称别名 |
| `RecordTypeMX` | 3 | 邮件交换（使用 Priority） |
| `RecordTypeTXT` | 4 | 文本记录 |
| `RecordTypeNS` | 5 | 名称服务器 |
| `RecordTypeSOA` | 6 | 授权起始 |
| `RecordTypeSRV` | 7 | 服务定位（使用 Priority） |
| `RecordTypePTR` | 8 | 反向 DNS 指针 |
| `RecordTypeURI` | 9 | URI 资源记录（RFC 7553） |
| `RecordTypeSSHFP` | 10 | SSH 指纹（RFC 4255） |
| `RecordTypeDNAME` | 11 | 委派名称（RFC 6672） |
| `RecordTypeANAME` | 12 | 别名（区域顶点 CNAME 的替代方案） |
| `RecordTypeZONEMD` | 13 | 区域消息摘要（RFC 9156） |
| `RecordTypeTLSA` | 14 | TLS 证书关联（RFC 6698） |
| `RecordTypeDNSKEY` | 15 | DNSSEC 公钥 |
| `RecordTypeDS` | 16 | DNSSEC 委派签署者 |
| `RecordTypeRRSIG` | 17 | DNSSEC 资源记录签名 |
| `RecordTypeNSEC` | 18 | DNSSEC 下一个安全记录 |
| `RecordTypeNSEC3` | 19 | DNSSEC 下一个安全记录 v3 |
| `RecordTypeNSEC3PARAM` | 20 | DNSSEC NSEC3 参数 |
| `RecordTypeCERT` | 21 | 在 DNS 中存储证书（RFC 4398） |
| `RecordTypeSVCB` | 22 | 服务绑定（RFC 9460）；DDR 指定记录所用的类型 |
| `RecordTypeHTTPS` | 23 | HTTPS 专用的 SVCB 形式（RFC 9460 §9）|

## RFC 兼容性

| RFC | 名称 | 支持程度 |
|-----|------|----------|
| RFC 1034 / 1035 | 域名——概念与实现 | 从根服务器开始的迭代解析、委派跟随、粘合与无粘合记录的 NS 处理 |
| RFC 2308 | DNS 查询的否定缓存 | 否定 TTL 取 `min(SOA MINIMUM, SOA TTL)`，并按发布的原样采用 |
| RFC 4033 / 4034 / 4035 | DNSSEC 协议、记录与协议修改 | 区域签名（对规范化 RRset 的 RRSIG、KSK/ZSK 角色、DS 计算）与上游验证（自根起的信任链、四种判定、AD/DO 处理）。NSEC/NSEC3 只验证、绝不生成 |
| RFC 4255 | SSHFP DNS 记录 | 完整（存储、查找、算法／指纹类型） |
| RFC 4398 | CERT DNS 记录 | 完整（存储、查找、PKIX 证书链分发） |
| RFC 4592 | DNS 中的通配符 | 完整（单一标签替换、精确匹配优先） |
| RFC 5155 | DNSSEC 哈希式认证否定（NSEC3） | 仅验证（最近封闭者、opt-out、按 RFC 9276 的迭代次数上限）；绝不生成 |
| RFC 5782 | DNSBL | 完整（以名称为基础的查询格式、本地 + 外部提供方、`127.0.0.1` 绝不被读成列入） |
| RFC 6147 | DNS64 | 完整（从 A 记录合成 AAAA、前缀可配置） |
| RFC 6605 / 8080 | DNSSEC 的 ECDSA 与 Ed25519 | 完整（签名与验证；`ring` 不支持 Ed448） |
| RFC 6672 | DNAME | 完整（子树改写，不作用于所有者名称本身） |
| RFC 6698 | DANE TLSA | 完整（TLSA 记录生成、存储、DNS 解析） |
| RFC 6840 | DNSSEC 澄清 | 只能以不支持算法验证的答案视为 Insecure（§5.11）；AD 只为有询问的客户端置位（§5.7） |
| RFC 6891 | EDNS(0) | 完整（OPT 记录、载荷协商、DO 位、BADVERS）。启用验证时，对外的迭代查询会带着 DO 与 1232 字节的载荷 |
| RFC 7553 | URI DNS 记录 | 完整（存储与查找） |
| RFC 7766 | TCP 上的 DNS 传输 | 连接重用，空闲超时从最后一次活动起算、2 字节长度分帧、逐监听器的连接上限 |
| RFC 7858 | DNS-over-TLS | 完整（以 TLS 封装的 TCP，853 端口）——服务器监听器与上游客户端 |
| RFC 8484 | DNS-over-HTTPS | 完整（GET + POST、application/dns-message、Cache-Control）——服务器监听器与上游客户端 |
| RFC 8555 | ACME | 服务器端（内置证书颁发机构、dns-01 自我验证、EAB） |
| RFC 9250 | DNS-over-QUIC | 完整（QUIC 传输、双向流） |
| RFC 9276 | NSEC3 参数指引 | 迭代次数超过 100 时视为非安全而不去计算 |

## 架构

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

解析顺序（未配置任何网络范围时）：
1. 解析 EDNS OPT 记录（载荷大小、DO 位）
2. 检查本地封锁列表（针对反向 DNS 查询）
3. 检查 DNS 响应缓存
4. 检查本地数据库（分割视域，一律优先）
5. 检查本地数据库中的 CNAME 记录
6. 检查 DNAME 记录（子树改写）
7. 检查 ANAME 记录（在区域顶点解析别名）
8. 若名称位于某个受管区域之下却找不到，返回权威 NXDOMAIN
9. 检查通配符记录
10. 检查本地封锁列表与 DNSBL 提供方（已列入则 NXDOMAIN，优先于任何外部答案）
11. 强制执行 `security.recursion_cidrs`——不在其中的来源会在任何东西离开本机之前就被 REFUSED
12. 按 `resolution.mode` 向外解析（若已启用则随机化 QNAME 大小写，若有配置则经由代理），并在迭代路径上验证 DNSSEC
13. 套用 DNS64 AAAA 合成（若已启用且适用）
14. 缓存响应（伪造的答案永不缓存）
15. 套用 TTL 漂移调整（若有配置）
16. 丢弃属于主机无法路由之地址族的 A/AAAA 答案（若 `address_family.mode: auto`）

若有配置网络范围，扩展的解析顺序请见[网络范围划分](#网络范围划分)。

## 许可证

本项目以 GNU Affero General Public License v3.0（AGPL-3.0）授权。完整许可条款请见 [LICENSE](LICENSE) 文件。
