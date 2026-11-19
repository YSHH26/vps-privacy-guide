# 把服务器配起来

整个部署都在你自己的电脑上操作：运行仓库里的入口脚本，它通过 SSH 去检查和配置 VPS。三个节点由 S-UI 面板管理，不另外单独跑 sing-box。面板、订阅和 CLIProxyAPI 都通过可信的 HTTPS 访问。日常部署不会重装系统。

## 1. 准备本机目标文件

你的电脑可以是 Mac、Linux 或 Windows（Windows 未测试），上面要有 Python 3.9 或更高版本（二维码库对 Python 版本另有要求，见 requirements-local.txt）、OpenSSH（用密码接入要 8.4 以上）、curl，再加上 SSH 密钥或服务商给的初始密码。先看 [服务器准备](buy-vps.md)，确认 SSH 别名连的是你要的那个公网 IP，用户是 root。密码、私钥和 API Key 不要写在命令参数里，也不要发到聊天里。用下面的 `ask-secrets` 弹窗输入，或者自己用编辑器写进 private/。

用初始密码接入时，可以用 `init --password-file` 或 `init --ask-password`。密码靠 OpenSSH 8.4 以上自带的 `SSH_ASKPASS` 机制传给 ssh，不用另外装 `sshpass`。Windows 10 自带的 OpenSSH 是 8.1，要换成 Git for Windows 里的 ssh。已经有密钥的，直接用 `init` 建一个专用的登录方式。两种方式都会先核对 SSH 主机公钥是不是可信的，碰到不认识的指纹不会自动接受。具体怎么准备见 [首次接入步骤](pilot.md)。

建议先在本机建一个虚拟环境，装好账号页要用的二维码库，再运行入口：

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-local.txt
umask 077
mkdir -p private
chmod 700 private
python3 scripts/vps.py --help
```

在本机建一个 `private/target.json`，权限设成 600。最简单的写法：

```json
{
  "ssh_alias": "my-vps",
  "ip": "192.0.2.1",
  "timezone": "UTC"
}
```

这里的 IP 是文档专用的示例地址，要换成你自己的。

如果你用的不是搬瓦工，或者不想提供 API Key，客户端里显示的流量就按服务器网卡收发的字节数来算。目标文件里可以加三个可选字段：

- `traffic_quota_gb`：每月额度，单位 GiB（1024³ 字节），默认 1000。
- `traffic_reset_day`：每月几号重置，填 1–28，默认 1，按服务器时区的零点切换。
- `traffic_count`：服务商怎么计费。`both` 是进出相加，`out` 只算出站，`in` 只算入站，`max` 取两边里大的那个，默认 `both`。

配了搬瓦工的 `provider_file` 时，会改用官方读数，这三个字段就不起作用了。

SSH 别名要指向同一个 IP，并且用 root 登录。不是 root 的话，要先安排好管理权限，否则脚本会拒绝这个目标。目标文件里存的是 SSH 别名、预期 IP、证书身份这类部署资料；服务商的凭据只放在权限受限的私有文件里。用本地编辑器填写，别把带密钥的内容打印到聊天或共享日志里。有哪些字段，以脚本帮助和状态文件校验时的提示为准。

root 密码和搬瓦工 API Key 可以用弹窗输入，不用自己建文件：

```sh
python3 scripts/vps.py --state private/target.json ask-secrets
```

它会弹出一个输入框，密码和 API Key 是同一个框里的两个隐藏输入栏，一次填完（目标文件里没有 `veid` 时只有密码一栏）。任何一栏没填或点了取消，什么都不保存。填好后，它把密码写进 `private/initial-password`，把 API Key 和 VEID 写进 `private/provider.json`，权限都是 600，然后在目标文件里记下这两个路径。只想填其中一个，加 `--secret password` 或 `--secret api-key`。Mac 用系统自带的对话框，Linux 要有图形界面，并装了 zenity 或 Python 的 tkinter。这几种都没有时，在终端里运行会逐项提示输入；不在终端里时，它会停下并提示你用编辑器手动写文件。弹窗在 Mac 和 Linux 桌面上都还未测试。

用搬瓦工、填了 `veid` 和 API Key 的话，第一次接入不用自己找主机公钥：

```sh
python3 scripts/vps.py --state private/target.json provider-proof
```

还没有部署专用密钥时，这条命令只通过搬瓦工的官方 HTTPS API 读出服务器的 boot ID 和 SSH 主机公钥，存成 15 分钟内有效的证明，接着运行 `init` 就行。这份证明只用来第一次接入，不能拿来重装。新开通的搬瓦工服务器不是 Ubuntu 时，AI 会在 `init` 之后按 AGENTS.md 自动换成 Ubuntu 24.04，前提是服务器上没有任何已有业务。这条路径在非 Ubuntu 的新服务器上还未测试。

第一次用密码接入时，先在目标文件里配好 `known_hosts_file`，里面的主机公钥要通过可信渠道核对过，再运行下面的命令。密码文件和目标文件都放在权限 700 的目录里，文件本身权限 600。确认新生成的独立密钥能连上以后，脚本才会删掉密码文件，你现有的 SSH 别名不会被改：

```sh
python3 scripts/vps.py --state private/target.json init --password-file private/initial-password
```

用过 `ask-secrets` 的话，目标文件里已经记了密码文件，直接运行 `init` 就行，不用加 `--password-file`。已经有能用的密钥，也不用加。别拿没核对过的 `ssh-keyscan` 输出当可信主机信息。

## 2. 先只看不改，确认目标

```sh
python3 scripts/vps.py --state private/target.json preflight
```

这一步会查实际连上的 SSH 目标、公网 IP、系统、架构、Docker 服务、正在监听的端口和防火墙，什么都不改。检查结果跟服务器的 boot ID、目标配置和源文件摘要绑在一起：服务器重启过、改了配置或源文件、或者超过一小时，都要重跑。目标对不上就停下。有服务已经占着端口时，先弄清楚是谁的，别直接停掉或覆盖。

| 用途 | 默认入口 |
| --- | --- |
| VLESS Reality | TCP 443 |
| VLESS TLS | TCP 2443 |
| AnyTLS | TCP 8443 |
| HTTPS 面板、订阅 | TCP 9443 |
| CLIProxyAPI HTTPS | TCP 9444 |
| IP 证书 HTTP 校验 | TCP 80 |
| S-UI 面板 / 原生订阅后端 | 127.0.0.1:2095 / 2096 |

你实际在用的 SSH 端口会保留。默认没有 Hysteria2，也不开 UDP 443。节点能不能转发 UDP 应用，要在客户端上测。Docker 发布的端口不受 UFW 普通规则管，要从外部确认它到底对谁开放，光看 UFW 状态不够。

## 3. 开始部署

现在的自动部署会申请签给公网 IP 的证书，所以公网 TCP 80 要能访问到。用域名的做法见 [TLS 说明](tls.md)，自动签发目前不走那条路。证书必须能在客户端正常通过验证；申请失败时，别靠关掉验证来继续。

```sh
python3 scripts/vps.py --state private/target.json deploy
```

刚重装好的系统，服务商的首次启动脚本可能还在后台跑 `apt-get`（搬瓦工的镜像会装 qemu guest agent 等组件），占着软件包锁。`base` 阶段会先等它跑完，最多等 15 分钟。超时就停下，让你过一会儿再重跑，不会强行打断它。

部署用的是 [固定版本清单](../versions.json) 里的版本。它会单独生成管理员、节点和订阅的凭据，存进权限受限的状态目录。哪一步失败就停在哪一步：先把原因修好，再重跑同一步，别手动跳过检查。重启 S-UI 或更新证书时，正在用的代理连接会断。

已经部署过、源文件又有变化时，脚本会先用服务器上装着的旧脚本备份旧配置、版本和数据库，再上传新代码。备份会短暂停机，连接也会断一下。备份失败就停下，不会接着覆盖。

用户、TLS 和入站配置都以 S-UI 为准。别直接改它的数据库，也别把 [服务端模板](../examples/server.json) 当面板的导入文件。那个模板只用来说明原生配置长什么样，以及用固定版本的 sing-box 做检查。面板里的对象之间还有关联：用户、TLS、发布地址和客户端模板是连在一起的。

| 节点 | S-UI 类型 | TLS 与认证 |
| --- | --- | --- |
| `reality` | vless，443/TCP | Reality 独立密钥、short ID、匹配的握手目标；UUID，Vision |
| `vless-tls` | vless，2443/TCP | 可信证书；同一用户 UUID，Vision |
| `anytls` | anytls，8443/TCP | 可信证书；独立随机密码 |

面板和原生订阅后端只在服务器本机监听，外面通过 Nginx 的 HTTPS 9443 访问。CLIProxyAPI 的后端也只在本机监听，部署完时不带任何上游账号。别另外开没加密的管理端口。

## 4. 检查，再生成账号页

```sh
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
python3 scripts/vps.py --state private/target.json export
```

`network` 默认在你自己电脑上的 Docker 里，用固定版本的 sing-box 依次连三个节点，检查能不能打开 HTTPS、出口 IP 对不对、填错凭据会不会被拒、断开后能不能重新连上。它还会通过每个节点去访问一个只有 IPv6 地址的网站和一个直接写成 IPv6 的地址，两个都必须连不上，以此确认服务器代理出去的流量只走 IPv4。

这一步需要本机有 Docker，并且会向外部的 HTTPS 测试网站发请求。它不测真实客户端，也不测 UDP 和防泄露。结果存在 `private/network.json`。`export` 会重新下载当前的节点信息，只把节点认证、服务器部署和版本指纹都对得上的网络报告合并进去；节点或部署变了以后，旧报告不会再显示通过。

本机没法用 Docker 的话，可以改用原生的 sing-box。前提是你已经从 [版本清单](../versions.json) 里找到适合你电脑平台的官方版本，单独下载到私有目录，并核对过压缩包和程序本身的 SHA256：

```sh
python3 scripts/vps.py --state private/target.json network --network-backend native --core-bin private/native-client/sing-box
```

用原生方式时，脚本照样会核对版本和清单里的摘要。它不会自动下载，不会信任随便一个程序，Docker 出问题时也不会偷偷换成原生方式。它只从你指定的私有路径临时跑一个客户端，不装全局程序，不改服务器，也不用重启你电脑上的其他虚拟机。两种方式都只是用固定版本的 sing-box 检查节点，代替不了 Surge、v2rayN/NG 的真机测试和防泄露检查。报告同样要跟当前节点和部署指纹对得上。

`verify` 的服务检查报告存在本机 `private/verification.json`，日志在同一个目录的 `stage-verify.log`，其他部署阶段的日志也写成 `stage-阶段名.log`。这些文件可能带着敏感的诊断信息，别公开。没覆盖到或没跑过的检查，仍然算未测试。

然后打开 `export` 生成的本机 HTML，也就是账号页。里面有面板地址和账号、每种客户端各自的订阅、节点信息，以及 CLIProxyAPI 的管理和调用信息。这个文件不放在服务器上，权限应该是 600。里面是明文的密钥，页面上的遮挡只能防旁边有人看。

公网面板的地址是 `https://你的证书身份:9443/app/`，订阅在同一个端口的 `/s/` 路径下。CLIProxyAPI 单独用 HTTPS 9444，管理中心在 `/management.html`，API Base URL 用 `/v1`。完整的订阅地址带着令牌，从本机账号页复制，别自己拼。证书身份要和证书里的 SAN 一致。别把订阅地址贴到公开的检测网站或第三方转换服务上。

接着按 [客户端说明](clients.md) 一个个导入，再过一遍 [完整检查清单](verification.md)。能打开后台，不代表节点能用；节点能用，也不代表设备不会漏 IP。

## 5. 日常维护命令

下面这些命令用的是服务器上已经装好的脚本，不会上传新代码，也不要求一小时内跑过 preflight，但还是会核对目标和 SSH 主机。服务器上装的版本太旧、没有对应的命令时，先按完整部署流程检查和更新，别在服务器上临时绕开脚本：

```sh
python3 scripts/vps.py --state private/target.json backup
python3 scripts/vps.py --state private/target.json cert-dry-run
python3 scripts/vps.py --state private/target.json cert-sync
python3 scripts/vps.py --state private/target.json restore-check
python3 scripts/vps.py --state private/target.json rotate-subscriptions --client all
python3 scripts/vps.py --state private/target.json rules
python3 scripts/vps.py --state private/target.json traffic-calibrate --used-gb 123.4
```

- `backup`：备份，会短暂停机。
- `cert-sync`：同步证书，可能会重启服务。
- `cert-dry-run`：试着走一遍续期签发，代替不了正式的证书同步和服务加载检查。
- `restore-check`：在隔离的位置试着恢复备份，不动正在运行的服务。
- `rotate-subscriptions`：更换订阅令牌，可以选 `surge`、`v2ray`、`clash`、`shadowrocket` 或 `all`。换完以后，每个客户端都要更新订阅，再跑一次 `export` 拿新地址。
- `rules`：马上刷新一次 Clash 规则数据。平时每天自动刷新，失败时继续用上一份。
- `traffic-calibrate`：把本机统计的本周期已用流量改成服务商后台显示的数（单位 GiB），之后接着往上加。用了搬瓦工官方读数时，这个命令会拒绝执行。

具体限制见 [维护说明](maintenance.md)。

要把已有的备份恢复到正在运行的服务器上，先跑 `restore-check`，确认选的备份、目标和旧版本都对得上。服务器上装的脚本要支持恢复，然后运行：

```sh
python3 scripts/vps.py --state private/target.json restore --archive /var/backups/sui-vps/__SELECTED_BACKUP__.tar.gz --confirm-target 192.0.2.1
```

把示例 IP 换成你的服务器公网 IP，备份路径要填服务器 `/var/backups/sui-vps/` 里真实存在的文件。恢复会中断服务，并替换这个项目的所有状态。它代替不了从零重装后的完整检查。这个命令用的也是服务器上装好的脚本，不会先上传新版本。恢复完，重新跑 `verify`、本机的 `network` 和真机客户端检查，再导出本机账号页。试着恢复和真正恢复是两步，没真正恢复过，就不能算这一项通过。

## 6. 要手动排查面板时

[Compose 模板](../deploy/compose.yaml) 里保留了 2095/2096 的本机映射。内部的 HTTP 只能通过 SSH 隧道临时访问，用来排查问题；平时都走 HTTPS。

```sh
ssh -N -L 12095:127.0.0.1:2095 -L 12096:127.0.0.1:2096 my-vps
```

把 `my-vps` 换成你自己的别名，然后在电脑浏览器里打开 `http://127.0.0.1:12095/app/`。终端要一直连着。这个地址只在你这台电脑上有效，别发给手机当远程订阅。

要手动调 S-UI 的话，照 [上游的配置对象说明](https://github.com/alireza0/s-ui/wiki/Configuration-Objects) 和你实际装的版本来操作，改完同步更新订阅和本机账号页。别靠猜去拼 API 请求。
