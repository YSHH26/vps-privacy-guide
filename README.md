# 自建节点与 IP 防泄露指南

买一台海外服务器，让 AI 从你自己的电脑上把它配成只有你在用的代理线路，再一项项确认手机和电脑没有漏出真实 IP。

适合第一次买 VPS、愿意让 AI 助手替你在服务器上执行命令的人。

> 这不是"完全匿名"：运营商能看到你连接了服务器，登录过的网站也能认出你的账号。这份指南帮你做到的是：该走代理的流量不走错路。

## 配好以后你有什么

- **三个节点**：VLESS + Reality、VLESS + TLS、AnyTLS。一个连不上，可以换另一个。
- **按客户端生成的订阅**：电脑和软路由用的 Clash 订阅带分流规则，国内网站直连，AI 服务单独一组。
- **正规 HTTPS 证书**：签给服务器 IP，不需要买域名，客户端保持证书校验。
- **一个只在你电脑上的账号页**：面板地址、各客户端订阅、二维码都在里面，不上传到任何地方。
- **CLIProxyAPI（可选）**：把你自己的 AI 服务账号汇总成一个 API 地址，带网页管理后台。部署后是空的，账号由你自己添加；用不到可以不管它。

## 第一步：准备三样东西

1. **一台服务器**：需要独立公网 IPv4，系统用 Ubuntu 24.04。还没有的话，看下面的推荐。
2. **你自己的电脑**：上面装一个能执行命令的 AI 助手（例如 Claude Code、Codex），由它通过 SSH 帮你配置服务器。
3. **要用的客户端**：手机和电脑各装一个，见后面的表格。

### 推荐套餐

如果还没有服务器，可以直接选搬瓦工的这个套餐。写这份指南时（2026 年 11 月），它是搬瓦工在售套餐里最便宜的一款：

**[直接购买这个套餐](https://bandwagonhost.com/aff.php?aff=82641&pid=88)**：SPECIAL 40G KVM PROMO V5 - CN2 GIA ECOMMERCE

| 项目 | 配置 |
| --- | --- |
| 内存 / 硬盘 | 2 GB / 40 GB SSD |
| 每月流量 | 2000 GB |
| 机房 | 洛杉矶 CN2 GIA，可以在后台免费迁移到其他机房 |
| 网络 | 1 个独立 IPv4，另有 IPv6 /64 |

> 这是我的推广链接，通过它购买，我可能获得佣金。价格、库存和计费周期以官网下单页为准；不同网络下的速度也会不一样，这里不承诺某个速度。

已经有 VPS 的话不用换。上面跑着其他网站或服务时，先让 AI 只读检查一遍，确认端口不冲突再部署。

买好以后，在服务商后台记下这几样，留在自己电脑上，**不要发到聊天或 Issue 里**：

- 服务器 IP、SSH 端口、root 密码（或密钥文件）
- 搬瓦工用户再记下 KiwiVM 后台「API」页的 **VEID 和 API Key**：部署后会读取后台的官方流量数据，客户端显示的用量和后台同步；需要重装系统时也用得上

更详细的准备步骤见 [买服务器前看这几件事](docs/buy-vps.md)。

## 第二步：让 AI 帮你部署

把下面这段话发给你电脑上的 AI 助手，括号里的内容换成你自己的：

```text
请按这个仓库帮我部署服务器：
https://github.com/makerkitt/vps-privacy-guide

先读 AGENTS.md 和里面列出的文档，
然后用仓库的 python3 scripts/vps.py --state private/target.json 入口操作。

SSH 别名：（例如 bwg，以后输入 ssh bwg 就能登录）
服务器 IP、SSH 端口和密码：我会自己写进本机 private/target.json，需要时提醒我，不要让我发到聊天里
服务器上现有的业务：（没有就写"新服务器"）
能否重装系统：（新服务器写"可以，没有要保留的数据"；有业务写"不可以"）
我的设备和客户端：（例如 Mac + Clash Verge Rev，iPhone + Shadowrocket）

密码、私钥、订阅地址和 Key 不要出现在聊天、日志或 Git 里。
没测过的项目如实写"未测试"。
```

AI 会依次检查服务器、安装配置、跑服务检查和节点测试，最后在你电脑上生成账号页。用时取决于服务器状态，刚重装的系统要先等服务商的初始化脚本跑完，会更久一些。中途重启服务会断开已有连接。

某一步失败时，部署会停在那一步：先修正原因，再重跑同一步，不要跳过检查。每一步做什么、失败后怎么处理，见 [把服务器配起来](docs/deployment.md)。想自己动手，也按这份文档一步步来。

## 第三步：导入客户端

部署完成后，AI 会告诉你账号页在本机的路径。账号页里有明文的面板密码和订阅地址，不要截图分享，也不要上传到任何地方。

打开账号页，找到和你客户端对应的那一栏，复制订阅地址导入：

| 设备 | 推荐客户端 | 用哪个订阅 | 真机测试 |
| --- | --- | --- | --- |
| Windows / macOS / Linux | Clash Verge Rev | Clash 订阅：三个节点，带分流规则 | 未测试 |
| 软路由 | OpenClash | Clash 订阅 | 未测试 |
| iPhone / iPad | Shadowrocket | Shadowrocket 订阅：三个节点，没有分流 | 未测试 |
| Mac / iPhone（已在用 Surge） | Surge | Surge 订阅：AnyTLS，全部走代理 | Surge Mac 6.5.0 测过 AnyTLS |
| Windows / Android（已在用 v2rayN / v2rayNG） | v2rayN / v2rayNG | v2ray 订阅：两个 VLESS 节点 | 未测试 |

电脑上用 Clash Verge Rev 时，模式选 **规则**，并打开 **虚拟网卡模式**（TUN）。只开系统代理的话，浏览器的 WebRTC 会暴露你的真实 IP。

各客户端的详细步骤见 [把手机和电脑连上](docs/clients.md)。

## 第四步：检查有没有漏 IP

导入以后先每个节点单独连一次，再按 [连上以后，看看有没有漏 IP](docs/leak-protection.md) 检查这几项：

- 网页显示的出口 IP 是不是服务器
- DNS 有没有走回本地网络
- IPv6 有没有绕出去
- WebRTC 有没有显示本地 IP，有的话看 [WebRTC 泄露怎么修](docs/webrtc.md)
- 节点断开、客户端退出时，流量会不会悄悄改成直连

要出差去网络受限的地方，**出发前**按 [出门前再检查一遍](docs/clients.md#出门前再检查一遍) 把手机和电脑都测好。

## 现在验证到哪一步

最近一次是 2026-11-18：在一台搬瓦工 VPS 上重装系统、从零部署，服务器上的服务检查全部通过。三个节点都用固定版本的 sing-box（节点程序）实测过：HTTPS 能访问、出口是服务器、错误凭据被拒绝。Clash 订阅用固定版本的 Mihomo 加载测试通过，Shadowrocket 订阅能正常下载。再次重装系统后，部署复用了重装前保存的证书。Surge Mac 6.5.0 的 AnyTLS 在更早一轮实测通过。

**还没测**：Clash Verge Rev、OpenClash、Shadowrocket、v2rayN、v2rayNG 真机，以及整机的 DNS、IPv6、WebRTC 和断线检查。每一项的方法和结果见 [检查清单与验证记录](docs/verification.md)。

## 以后怎么维护

备份、证书续期、订阅令牌轮换、流量校准和升级，见 [维护说明](docs/maintenance.md)。

<details>
<summary>文档目录</summary>

| 文档 | 讲什么 |
| --- | --- |
| [买服务器前看这几件事](docs/buy-vps.md) | 选服务器、开通后要记下什么 |
| [把服务器配起来](docs/deployment.md) | 部署入口每一步做什么、出错怎么办 |
| [从零部署检查](docs/pilot.md) | 首次接入、重装系统、主机身份核验 |
| [TLS、IP 证书与 Reality](docs/tls.md) | 证书怎么签、怎么续期，Reality 怎么回落 |
| [把手机和电脑连上](docs/clients.md) | 各客户端导入、分流规则、出门前检查 |
| [连上以后，看看有没有漏 IP](docs/leak-protection.md) | DNS、IPv6、WebRTC、断线逐项检查 |
| [WebRTC 泄露怎么修](docs/webrtc.md) | 只开系统代理会漏的原因和修法 |
| [维护说明](docs/maintenance.md) | 日常查看、备份恢复、更新 |
| [用提供商 API 核验主机](docs/provider-api.md) | 重装前后怎么确认是同一台机器 |
| [不使用面板](docs/standalone.md) | 自己运行裸 sing-box 的写法 |
| [检查清单与验证记录](docs/verification.md) | 每一层检查的方法和实测结果 |

</details>

<details>
<summary>技术细节与开发检查</summary>

服务器用 S-UI 管理 sing-box，面板和订阅后端只监听本机回环地址，通过 Nginx 在 TCP 9443 提供 HTTPS；CLIProxyAPI 用 TCP 9444。节点端口是 TCP 443、2443、8443，证书校验需要 TCP 80。所有镜像和下载文件都按 [版本清单](versions.json) 固定版本和摘要。

[部署配置](deploy/compose.yaml) · [服务端模板](examples/server.json) · [客户端模板](examples/client.json)

`examples/` 是原生 sing-box 格式，不能直接导入 S-UI。客户端模板只用来测试节点，没有 TUN、分流或断线保护。

```sh
python3 -m unittest discover -s tests -v
docker compose -f deploy/compose.yaml config --quiet
VALIDATE_CORE=1 python3 -m unittest discover -s tests -v
```

最后一条需要 Docker 和 OpenSSL，会用固定版本的 sing-box 和 Mihomo 解析配置。自动检查见 [GitHub Actions](https://github.com/makerkitt/vps-privacy-guide/actions/workflows/validate.yml)。

</details>

[MIT 许可证](LICENSE) · [第三方许可](NOTICE.md)
