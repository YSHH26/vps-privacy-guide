# 自建节点与 IP 防泄露指南

你需要一台能 SSH 登录、带独立公网 IPv4 的 VPS，一台自己的电脑，以及要使用的客户端。教程按 Ubuntu 24.04 写；没有域名也可以申请可信的 IP 证书。

把这个仓库交给 AI，让它从你自己的电脑运行部署入口。S-UI 管理 **VLESS + Reality、VLESS + TLS、AnyTLS** 三种连接方式；电脑和软路由用 Clash Verge Rev / OpenClash（三个节点，带国内直连和 AI 分流），Surge 用 AnyTLS，v2rayN / v2rayNG 用 VLESS。完成后，你会拿到公网 HTTPS 面板、按客户端区分的在线订阅，以及只保存在本机的账号 HTML。CLIProxyAPI 和管理中心也保留，初始没有上游账号，需要你之后添加。

> 已在一台 Ubuntu 24.04 VPS 上重装两轮，并实测三个节点。Surge Mac 6.5.0 的 AnyTLS 连通与出口通过，v2rayN、v2rayNG 和整机防泄露仍待测试。[查看验证记录](docs/verification.md)

## 先准备服务器

已经有 VPS，就先检查现有服务，不必换机器。还没有的话，可以 [查看搬瓦工套餐](https://bandwagonhost.com/aff.php?aff=82641)。这是我的推广链接，通过它购买，我可能获得佣金。价格、库存、线路和每月流量以官网及你的实例信息为准；教程不承诺某个套餐的速度。

购买和 SSH 准备见 [服务器准备](docs/buy-vps.md)。把 SSH 别名、预期公网 IP、系统和客户端版本记下来。密码、私钥、提供商 API Key 只放在本机权限受限的文件里，别贴进聊天或 Issue。

## 让 AI 帮你配置

可以把下面这段话交给 AI，替换括号内容：

```text
请按此仓库帮我部署：
https://github.com/makerkitt/vps-privacy-guide

先阅读 AGENTS.md、README.md、docs/deployment.md、docs/tls.md、docs/verification.md 和 docs/pilot.md。
SSH 别名：（填写）
预期公网 IP：（只存到本机 private/target.json，不要输出到聊天）
设备和客户端：（填写系统、应用和版本）
证书：使用公网 IP 证书（当前自动部署方式）
服务器现有业务：（填写）

从仓库 python3 scripts/vps.py --state private/target.json 入口先在需要时执行 init，再执行 preflight、deploy、verify、network、export。
使用 S-UI 管理 VLESS Reality、VLESS TLS 和 AnyTLS。
面板和订阅内部监听回环，通过公网可信 HTTPS 访问。
CLIProxyAPI 初始不添加上游账号。交付 HTML 仅保存在本机。
凭据和订阅链接不要出现在聊天、日志或 Git 中。
日常部署不得重装系统。需要重装时，先核对授权目标并使用独立命令。
按客户端逐项测试 DNS、IPv6、WebRTC 和断线行为，没测过的保留“未测试”。
```

你也可以自己操作，按 [部署教程](docs/deployment.md) 建立私有目标文件，再依次运行：

```sh
python3 scripts/vps.py --state private/target.json preflight
python3 scripts/vps.py --state private/target.json deploy
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
python3 scripts/vps.py --state private/target.json export
```

第一次接入可用 `init --password-file private/initial-password` 安装专用密钥；先提供可信 SSH 主机信息，密码不会进入参数或环境变量。具体步骤见 [首次接入](docs/pilot.md)。

`preflight` 先只读检查目标和端口。`deploy` 会安装、配置服务，重启会中断现有连接。`verify` 记录服务检查，`network` 用本机固定 Docker 核心逐条检查节点（需本机 Docker）；`export` 生成本机私有账号页。具体字段、前提条件和失败处理以 [部署教程](docs/deployment.md) 及入口的 `--help` 为准。

## 配好后怎么用

打开本机交付 HTML，找到面板地址、账号、各客户端订阅、CLIProxyAPI 管理入口和调用信息。页面包含明文秘密，遮挡只防旁观；不要上传或转发。二维码在本机生成，页面不向第三方请求二维码。

按 [客户端说明](docs/clients.md) 导入后，每个节点单独连接，再做 [IP 防泄露检查](docs/leak-protection.md)。WebRTC 显示了本地 IP，看 [WebRTC 泄露怎么修](docs/webrtc.md)；要出差的话，出发前按 [出门前再检查一遍](docs/clients.md#出门前再检查一遍) 在手机和电脑上都测好。系统代理、TUN、DNS、IPv6、WebRTC 和断线保护要分别检查。运营商能知道你连接 VPS，登录过的网站也能认出你的账号；这不是完全匿名。

日常查看、备份、证书续期和更新见 [维护说明](docs/maintenance.md)。首次测试流程见 [从零部署检查](docs/pilot.md)。需要自己选择裸核心模式时，另看 [不使用面板](docs/standalone.md)。

<details>
<summary>配置模板与开发检查</summary>

[部署配置](deploy/compose.yaml) · [服务端模板](examples/server.json) · [客户端模板](examples/client.json) · [版本清单](versions.json)

`examples/` 是原生 sing-box 格式，不能直接导入 S-UI。客户端模板只测试节点，没有 TUN、分流或断线保护。S-UI 镜像与单独用于模板校验的 sing-box 镜像分别固定；不要把后者的版本当作面板内置版本。

```sh
python3 -m unittest discover -s tests -v
docker compose -f deploy/compose.yaml config --quiet
VALIDATE_CORE=1 python3 -m unittest discover -s tests -v
```

最后一条需要可用的 Docker 引擎和 OpenSSL。自动检查见 [GitHub Actions](https://github.com/makerkitt/vps-privacy-guide/actions/workflows/validate.yml)。

</details>

[MIT 许可证](LICENSE) · [第三方许可](NOTICE.md)
