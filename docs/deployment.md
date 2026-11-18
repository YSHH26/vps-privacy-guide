# 把服务器配起来

你在自己的电脑运行仓库入口，由它通过 SSH 检查和配置 VPS。三个节点由 S-UI 管理，不另外运行裸 sing-box；面板、订阅和 CLIProxyAPI 通过可信 HTTPS 访问。日常部署不会重装操作系统。

## 1. 准备本机目标文件

本机需要 Python 3.9 或更高版本（二维码库还要满足 requirements-local.txt 的 Python 版本）、OpenSSH、curl，以及 SSH 密钥或服务商提供的初始密码。先读 [服务器准备](buy-vps.md)，确认 SSH 别名指向预期公网 IP 和 root 用户。不要把密码、私钥、API Key 放进命令参数或聊天。

初始密码可以经 `init --password-file` 或 `init --ask-password` 引导，需要本机 `sshpass`；已有密钥也可直接用 `init` 建立专用接入。两种方式都先核验可信 SSH 主机公钥，不自动接受未知指纹。具体准备见 [首次接入步骤](pilot.md)。

建议在本机虚拟环境安装账号页需要的二维码库，再执行入口：

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-local.txt
umask 077
mkdir -p private
chmod 700 private
python3 scripts/vps.py --help
```

在本机建立 `private/target.json`，权限设为 600。最小目标示例：

```json
{
  "ssh_alias": "my-vps",
  "ip": "192.0.2.1",
  "timezone": "UTC"
}
```

这里的地址是文档保留地址，必须替换。

不是搬瓦工、或者不想给 API Key 时，客户端里显示的流量按服务器网卡的收发字节统计。可以在目标文件里加三个可选字段：`traffic_quota_gb` 是每月额度（单位 GiB，即 1024³ 字节，默认 1000），`traffic_reset_day` 是每月重置日（1–28，默认 1，按服务器时区零点切换），`traffic_count` 是服务商的计费方式（`both` 双向相加、`out` 只算出站、`in` 只算入站、`max` 取较大的一边，默认 `both`）。配置了搬瓦工 `provider_file` 时改用官方读数，这三个字段不生效。

SSH 别名需指向相同 IP，并使用 root；非 root 环境要先安排适当的管理权限，脚本会拒绝不符的目标。目标文件保存 SSH 别名、预期 IP、证书身份等本次部署资料；提供商凭据也只保存在受限私有文件中。使用本地编辑器填写，别把含秘密的内容打印到聊天或共享日志。具体字段以脚本帮助及状态文件校验提示为准。

首次用密码接入时，在目标文件配置经可信渠道核验的 `known_hosts_file`，再运行下面命令；密码文件与目标文件都放在权限 700 的目录中，权限为 600。成功确认独立新密钥连接后，密码文件才会删除，现有 SSH 别名不会修改：

```sh
python3 scripts/vps.py --state private/target.json init --password-file private/initial-password
```

已有可用密钥可以省略 `--password-file`。不要拿未经核验的 `ssh-keyscan` 输出充当可信主机信息。

## 2. 先只读确认目标

```sh
python3 scripts/vps.py --state private/target.json preflight
```

检查实际 SSH 目标、公网 IP、系统、架构、Docker 服务、监听端口和防火墙。本次检查绑定服务器 boot ID、目标配置和源文件摘要；重启、改配置、改源文件或超过一小时后需要重跑。目标不一致就停下；已有服务占用端口时，先弄清归属，不直接停掉或覆盖。

| 用途 | 默认入口 |
| --- | --- |
| VLESS Reality | TCP 443 |
| VLESS TLS | TCP 2443 |
| AnyTLS | TCP 8443 |
| HTTPS 面板、订阅 | TCP 9443 |
| CLIProxyAPI HTTPS | TCP 9444 |
| IP 证书 HTTP 校验 | TCP 80 |
| S-UI 面板 / 原生订阅后端 | 127.0.0.1:2095 / 2096 |

保留实际 SSH 端口。默认没有 Hysteria2，也不开放 UDP 443。节点能不能转发 UDP 应用，需要按客户端测试。Docker 发布端口与 UFW 普通规则不同，要从外部确认监听范围，不能只看 UFW 状态。

## 3. 执行部署

当前自动部署申请公网 IP 证书，需要公网 TCP 80 可达；域名方式见 [TLS 说明](tls.md)，不属于当前自动签发分支。证书必须能在客户端正常验证；申请失败时不要关闭验证来继续。

```sh
python3 scripts/vps.py --state private/target.json deploy
```

刚重装好的系统，服务商的首次启动脚本可能还在后台运行 `apt-get`（搬瓦工的镜像会装 qemu guest agent 等组件），占着软件包锁。`base` 阶段会先等它结束，最多等 15 分钟，超时就停下，让你稍后重跑，不会强行打断它。

部署阶段应使用 [固定版本清单](../versions.json)，生成独立管理员、节点与订阅凭据，并保存到受限状态目录。失败会停止；先修正原因，再重跑同一阶段，不能靠手工跳过检查。重启 S-UI 或更新证书会中断现有代理连接。已有部署的源文件摘要变化时，会先用服务器上已安装的旧脚本备份旧配置、版本和数据库，再上传新代码；备份短暂停机，也会中断连接。备份失败就停止，不能继续覆盖。

S-UI 是用户、TLS 和入站配置的唯一来源。不要直接写数据库；不要把 [服务端模板](../examples/server.json) 当作面板导入文件。示例只用来解释原生配置和执行固定核心检查。面板对象之间还有用户、TLS、发布地址和客户端模板关联。

| 节点 | S-UI 类型 | TLS 与认证 |
| --- | --- | --- |
| `reality` | vless，443/TCP | Reality 独立密钥、short ID、匹配的握手目标；UUID，Vision |
| `vless-tls` | vless，2443/TCP | 可信证书；同一用户 UUID，Vision |
| `anytls` | anytls，8443/TCP | 可信证书；独立随机密码 |

面板和原生订阅后端继续回环监听，Nginx 在 HTTPS 9443 提供外部访问。CLIProxyAPI 后端也只监听回环；初始不配置上游账号。不要额外开放未加密的管理端口。

## 4. 检查与生成账号页

```sh
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
python3 scripts/vps.py --state private/target.json export
```

`network` 默认在你自己的电脑上用 Docker 中的固定核心逐条连接三个节点，检查 HTTPS、出口 IP、错误凭据拒绝和恢复后的连接。它还会经每个节点访问一个只有 IPv6 地址的站点和一个 IPv6 字面地址，两个都必须连不上，用来确认服务器的代理出站只走 IPv4。它需要本机 Docker，可向外部 HTTPS 测试站点发请求；它不测试真实客户端、UDP 或防泄露。结果保存在 `private/network.json`。`export` 重新下载当前节点后，只合并与节点认证、服务器部署和版本指纹相符的本机网络报告；节点或部署变更后，旧报告不会继续显示通过。

如果本机 Docker 不可用，而你已将 [版本清单](../versions.json) 中匹配本机平台的官方核心单独下载到私有目录并核对了压缩包和二进制的 SHA256，可显式选择原生核心：

```sh
python3 scripts/vps.py --state private/target.json network --network-backend native --core-bin private/native-client/sing-box
```

原生后端仍会核对固定版本与清单中的摘要，不会自动下载、信任任意二进制或在 Docker 失败后悄悄切换。它只从指定私有路径运行临时客户端，不安装全局核心、不修改服务器，也不需要重启你本机其他虚拟机。两种后端都属于固定核心节点检查，不能代替 Surge、v2rayN/NG 或防泄露测试。报告继续按当前节点与部署指纹匹配。

`verify` 的服务检查报告保存到本机 `private/verification.json`，阶段日志保存在同目录的 `stage-verify.log`；其他部署阶段日志也写入 `stage-阶段名.log`。这些文件可能含敏感诊断，不要公开。未覆盖或未执行的检查仍然是未测试。再打开 `export` 输出的本机 HTML，里面有面板地址/账号、按客户端区分的订阅、节点、CLIProxyAPI 管理与调用信息。HTML 不在服务器托管，权限应为 600；它包含明文秘密，默认遮挡只防旁观。

公网面板使用 `https://你的证书身份:9443/app/`，订阅使用同端口的 `/s/` 路径。CLIProxyAPI 单独使用 HTTPS 9444，管理中心路径是 `/management.html`，API Base URL 使用 `/v1`。完整订阅地址含令牌，从本机账号页取用，不自行猜测。证书身份必须与证书 SAN 对应。不要把订阅 URL 粘到公开检查站点或第三方转换服务。

按 [客户端说明](clients.md) 逐个导入，再执行 [完整检查清单](verification.md)。能打开后台不能证明节点可用；节点可用也不能证明设备防泄露。

## 5. 日常维护入口

下面的命令使用服务器已经安装的脚本，不上传新代码，也不要求一小时内的 preflight。目标和 SSH 主机校验仍会执行。安装了较旧版本的服务器若没有对应阶段，先按完整部署流程检查和更新，不能现场绕过脚本：

```sh
python3 scripts/vps.py --state private/target.json backup
python3 scripts/vps.py --state private/target.json cert-dry-run
python3 scripts/vps.py --state private/target.json cert-sync
python3 scripts/vps.py --state private/target.json restore-check
python3 scripts/vps.py --state private/target.json rotate-subscriptions --client all
python3 scripts/vps.py --state private/target.json rules
python3 scripts/vps.py --state private/target.json traffic-calibrate --used-gb 123.4
```

备份会短暂停机；证书同步可能重启服务。`cert-dry-run` 检查续期签发，不能代替正式证书同步与服务加载检查。`restore-check` 只在隔离位置检查备份恢复，不覆盖现网。令牌轮换可选 `surge`、`v2ray`、`clash` 或 `all`，完成后需要各客户端更新订阅，再运行 `export` 获取新地址。`rules` 立即刷新一次 Clash 规则数据（平时每天自动刷新，失败时保留上一份）。`traffic-calibrate` 把本机流量统计的本周期已用量设成服务商后台显示的值（单位 GiB），之后接着累加；用了搬瓦工官方读数时会拒绝执行。具体限制见 [维护说明](maintenance.md)。

需要把已有备份恢复到现网时，先执行 `restore-check`，确认选定备份、目标和旧版本相符，再在已安装支持恢复阶段的服务器上运行：

```sh
python3 scripts/vps.py --state private/target.json restore --archive /var/backups/sui-vps/__SELECTED_BACKUP__.tar.gz --confirm-target 192.0.2.1
```

将示例地址换成你的预期公网 IP，备份路径必须是服务器 `/var/backups/sui-vps/` 中的实际文件。恢复会中断服务并替换本项目状态；不要用它代替从零重装验收。入口使用服务器已安装脚本，不会先上传新版本。恢复后重新执行 `verify`、本机 `network` 和真实客户端检查，再导出本机账号页。恢复检查与实际恢复是不同步骤，未执行实际恢复前不能标记通过。

## 6. 需要手工排查面板时

[Compose 模板](../deploy/compose.yaml) 保留 2095/2096 的回环映射。只有 SSH 隧道可以临时访问内部 HTTP，用于排查；正常使用走 HTTPS。

```sh
ssh -N -L 12095:127.0.0.1:2095 -L 12096:127.0.0.1:2096 my-vps
```

把 `my-vps` 换成自己的别名，在本机浏览器打开 `http://127.0.0.1:12095/app/`。保留终端连接，不要把这个本机地址发给手机当成远程订阅。

若需要手工调整 S-UI，按 [上游配置对象说明](https://github.com/alireza0/s-ui/wiki/Configuration-Objects) 和实际版本操作，并同步后续订阅及本机交付；不凭猜测构造 API 请求。
