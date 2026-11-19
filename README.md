# 自建节点与 IP 防泄露指南

这份指南教你买一台海外服务器，让电脑上的 AI 助手把它配成你自己专用的代理，配完再逐项检查手机和电脑有没有漏出真实 IP。

第一次买 VPS 也能跟着做，服务器上的命令由 AI 助手替你执行。

> 用了代理也不等于匿名。运营商看得到你在连这台服务器，你登录的网站也认得你的账号。这份指南只负责让该走代理的流量都走代理，不从你自己的网络漏出去。

## 配好以后你会有

- 三个节点：VLESS + Reality、VLESS + TLS 和 AnyTLS。一个连不上，就换另一个。
- 每种客户端一个订阅地址。电脑和软路由用的 Clash 订阅带分流规则，国内网站直连，AI 服务单独一组。
- 一张签给服务器 IP 的正规 HTTPS 证书。不用买域名，客户端也不用关掉证书校验。
- 一个只存在你电脑上的账号页，面板地址、订阅地址和二维码都在里面。
- 可选的 CLIProxyAPI，能把你自己的 AI 账号汇总成一个 API 地址，带网页后台。刚装好时是空的，用不上就不用管它。

## 第一步：准备三样东西

1. **一台服务器**：要有独立的公网 IPv4，系统选 Ubuntu 24.04。还没有的话，看下面的推荐。
2. **你自己的电脑**：Mac、Windows、Linux 都行，装一个能执行命令的 AI 助手，比如 Claude Code 或 Codex。它会通过 SSH 登录服务器帮你配置，缺什么软件它会自己装。
3. **客户端**：手机和电脑各装一个，装哪个看后面的表格。

### 推荐套餐

还没有服务器的话，可以直接买搬瓦工的这个套餐。写这份指南时（2026 年 11 月），它是搬瓦工在售套餐里最便宜的：

**[直接购买这个套餐](https://bandwagonhost.com/aff.php?aff=82641&pid=88)**：SPECIAL 40G KVM PROMO V5 - CN2 GIA ECOMMERCE

| 项目 | 配置 |
| --- | --- |
| 内存 / 硬盘 | 2 GB / 40 GB SSD |
| 每月流量 | 2000 GB |
| 机房 | 洛杉矶 CN2 GIA，可以在后台免费迁移到其他机房 |
| 网络 | 1 个独立 IPv4，另有 IPv6 /64 |

> 这是我的推广链接，你通过它下单，我可能拿到佣金。价格、库存和计费周期以下单页为准。速度跟你自己的网络有关，我没法保证。

已经有 VPS 就不用再买。如果上面跑着别的网站或服务，先让 AI 只看不改地检查一遍，确认端口不冲突再部署。

买好以后，去服务商后台记下这几样。IP、端口和 VEID 下一步要填进发给 AI 的那段话里；root 密码和 API Key 等部署时在弹出的输入框里填，**别发到聊天、Issue、群聊或截图给别人**：

- 服务器 IP、SSH 端口、root 密码（或密钥文件）
- 用搬瓦工的话，再记下 KiwiVM 后台「API」页里的 **VEID 和 API Key**。有了它们，客户端显示的流量用量会跟后台一致

更细的准备步骤在 [买服务器前看这几件事](docs/buy-vps.md)。

## 第二步：让 AI 帮你部署

打开你电脑上的 AI 助手（Codex、Claude Code，或者其他能在你电脑上执行命令的工具），复制下面这段话，把 `<>` 里的内容换成你自己的，再发给它：

```text
请按这个仓库配置我新买的服务器：
https://github.com/YSHH26/vps-privacy-guide

请先把仓库下载到本机，读 AGENTS.md，用仓库里的脚本部署。
这是新买的服务器，直接部署就行。
三个节点都配上，所有客户端的订阅都生成好，配完告诉我账号页在哪。
如果你不能在我的电脑上执行命令，直接告诉我，不要让我一条条手动敲。

我的服务器：
- IP：<服务器 IP>
- SSH 端口：<SSH 端口，不知道就写 22>
- 登录方式：<root 密码；已经能用密钥登录就写密钥文件的位置，比如 ~/.ssh/id_ed25519>
- 以后想用这个名字登录：<服务器名字，比如 bwg>
- 搬瓦工 VEID：<VEID，不是搬瓦工就删掉这行>

root 密码和搬瓦工 API Key 我不发在聊天里。
需要的时候，请用 python3 scripts/vps.py --state private/target.json ask-secrets 弹出输入框让我自己填。
如果我用的是密钥登录，就不要问 root 密码。
```

要改的地方：

- **IP 和端口**：从服务商后台复制过来。搬瓦工的在 KiwiVM 首页（Main controls），端口不一定是 22，以页面为准。
- **登录方式**：新买的服务器一般只有 root 密码，就写"root 密码"，密码本身不要写进来。你已经能用密钥登录这台服务器的话，写密钥文件的位置。
- **名字**：比如写 `bwg`，以后输入 `ssh bwg` 就能登录服务器。
- **VEID**：在 KiwiVM 左侧菜单的「API」页。填了以后，客户端显示的流量会跟后台一致。不是搬瓦工的，删掉这一行。

替换的时候把 `<>` 一起删掉，比如 `<服务器 IP>` 改成 `192.0.2.1`。

部署开始后，电脑上会弹出一个输入框，root 密码和 API Key 在同一个框里一起填（不是搬瓦工就只有密码）。用密钥登录的不会问密码，只问 API Key；不是搬瓦工又用密钥登录的，不会弹窗。root 密码在搬瓦工的开通邮件里；找不到的话，在 KiwiVM 左侧菜单的 **Root password modification** 里生成一个新的。API Key 在 KiwiVM 的「API」页。你在框里输入的内容由脚本直接存进本机 private 文件夹，不经过 AI，也不会出现在聊天里。部署完，服务器会关掉密码登录，只能用你这台电脑上的密钥登录，所以 root 密码之后就没用了。

API Key 会一直存在你电脑的 private 文件夹里，脚本靠它读取流量。有了它就能在后台操作这台服务器，比如关机、清空系统，别把这个文件夹发给别人。哪天觉得它可能泄露了，就去 KiwiVM 的「API」页重新生成一个，再让 AI 运行 `ask-secrets --secret api-key` 弹窗填入新的。

弹窗支持 Mac、Windows 和带图形界面的 Linux，在真机上都还没测试过。Windows 上第一次部署时，AI 可能要先装 Python 和 Git，系统弹出"是否允许"时点"是"。弹不出来时，AI 会告诉你要自己写进哪个文件，用编辑器打开填进去就行。

AI 会先检查服务器，再安装、配置、测试节点，最后在你电脑上生成账号页。花多久要看服务器的情况，新开通的服务器得先等服务商的初始化脚本跑完。部署中途会重启服务，正在用的连接会断一下。

哪一步失败了，部署就停在那一步。把原因修好，重跑这一步就行，别跳过检查。每一步在做什么、失败了怎么办，都写在 [把服务器配起来](docs/deployment.md) 里。想自己动手，也照着它来。

## 第三步：导入客户端

部署完，AI 会告诉你账号页存在电脑的哪个位置。里面有明文的面板密码和订阅地址，别截图发给别人，也别传到网上。

打开账号页，找到你用的客户端那一栏，复制订阅地址导入：

| 设备 | 推荐客户端 | 用哪个订阅 |
| --- | --- | --- |
| Windows / macOS / Linux | Clash Verge Rev | Clash 订阅：三个节点，带分流规则 |
| 软路由 | OpenClash | Clash 订阅 |
| iPhone / iPad | Shadowrocket | Shadowrocket 订阅：三个节点，没有分流 |
| Mac / iPhone（已在用 Surge） | Surge | Surge 订阅：AnyTLS，全部走代理 |
| Windows / Android（已在用 v2rayN / v2rayNG） | v2rayN / v2rayNG | v2ray 订阅：两个 VLESS 节点 |

电脑上用 Clash Verge Rev 时，模式选 **规则**，再打开 **虚拟网卡模式**（TUN）。只开系统代理的话，浏览器会通过 WebRTC 把你的真实 IP 露出去。

每个客户端怎么导入，看 [把手机和电脑连上](docs/clients.md)。

## 第四步：检查有没有漏 IP

导入后，先把每个节点单独连一次，再照 [连上以后，看看有没有漏 IP](docs/leak-protection.md) 检查这几项：

- 网页显示的出口 IP 是不是服务器
- DNS 有没有走回本地网络
- IPv6 有没有绕出去
- WebRTC 有没有显示本地 IP，有的话看 [WebRTC 泄露怎么修](docs/webrtc.md)
- 节点断了或客户端退出时，流量会不会悄悄变成直连

要去网络受限的地方出差，**出发前**照 [出门前再检查一遍](docs/clients.md#出门前再检查一遍) 把手机和电脑都测一遍。

## 现在测到哪一步了

最近一次测试在 2026-11-18：在一台搬瓦工 VPS 上重装系统、从头部署，服务器上的服务检查全部通过。三个节点都用固定版本的 sing-box（节点程序）连过，能打开 HTTPS 网站，出口 IP 是服务器，填错凭据会被拒绝。Clash 订阅用固定版本的 Mihomo 加载过，Shadowrocket 订阅能正常下载。之后又重装了一次系统，部署直接用上了重装前保存的证书。Surge Mac 6.5.0 的 AnyTLS 节点在更早的一轮里测过。

**还没测**：Clash Verge Rev、OpenClash、Shadowrocket、v2rayN、v2rayNG 的真机使用，以及整台设备的 DNS、IPv6、WebRTC 和断线检查。怎么测、测出了什么，都记在 [检查清单与验证记录](docs/verification.md) 里。

## 以后怎么维护

备份、证书续期、更换订阅地址、校准流量和升级，都在 [维护说明](docs/maintenance.md) 里。

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

最后一条需要 Docker 和 OpenSSL，会用固定版本的 sing-box 和 Mihomo 解析配置。自动检查见 [GitHub Actions](https://github.com/YSHH26/vps-privacy-guide/actions/workflows/validate.yml)。

</details>

[MIT 许可证](LICENSE) · [第三方许可](NOTICE.md)
