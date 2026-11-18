# 把手机和电脑连上

先打开本机账号 HTML，找到与你客户端对应的订阅。每条节点单独试过以后，再做 [IP 防泄露检查](leak-protection.md)。订阅提供节点连接资料。当前默认没有国内直连或 AI 专用规则，Surge 完整配置的 FINAL 指向代理；不要把它理解为已有国内外智能分流。它也不会自动替你配置整台设备的 TUN、DNS 或断线保护。

## 按客户端导入

| 客户端 | 默认使用 | 导入办法 |
| --- | --- | --- |
| Surge | AnyTLS | 取账号页中的 Surge 格式订阅，按当前版本的远程配置/代理列表功能添加 |
| v2rayN | VLESS Reality、VLESS TLS | 在订阅分组添加 HTTPS 地址并更新；也可粘贴 VLESS 分享链接 |
| v2rayNG | VLESS Reality、VLESS TLS | 在订阅设置添加 HTTPS 地址并更新；也可扫描节点二维码或导入链接 |

Surge 不依赖支持 VLESS 的测试版。客户端版本若不识别某个节点，先检查应用与核心能力；不要把未知协议硬塞进配置。AnyTLS 是否适合其他客户端，也以实际版本为准。以上是导入方向，具体菜单及最低实测版本要在真实设备上记录，未测试的版本不能承诺兼容。

节点订阅与完整 Surge 配置不同。如果下载的是代理列表，使用当前客户端对应的列表功能；不要直接覆盖现有整份配置。Clash/Mihomo 或 Shadowrocket 输出即使提供，也不能当作 Surge 配置导入；规则格式和语义需要分别校验。

添加后手动更新一次，逐条选中节点测试受控 HTTPS 地址，确认出口。关闭自动切换，避免一条坏节点被另一条掩盖。再分别记录 Windows / Android / Mac 等实际客户端和核心版本。

## 在线订阅要注意什么

HTTPS 使用 TCP 9443，后端仍在服务器回环。证书验证必须开启，IP 证书要能按 IP SAN 验证。Reality 占用 TCP 443，不能让 Nginx 再占同一端口。订阅地址含高熵随机令牌，能拿到链接的人可能拿到节点；链接外泄后需要轮换。

自动刷新时使用账号页中为该客户端生成的地址，不要把某一种格式改个后缀冒充另一种。订阅只在自己的服务上生成/转换，不使用第三方在线转换。分享链接、二维码和 HTML 同样都含秘密，不要上传。

节点连接地址应该是 VPS 公网 IP 或证书域名，不能是 `127.0.0.1`、Docker 地址或本机 SSH 隧道地址。如果地址不对，回到 S-UI 检查用户关联、入站发布地址、外部端口和客户端出站模板。

来源：[S-UI 订阅说明](https://github.com/alireza0/s-ui/wiki/Subscription-Service)。

## 用 sing-box 单独测试节点

[客户端模板](../examples/client.json) 只开放本机 `127.0.0.1:1080` 的 HTTP/SOCKS 代理，默认选 Reality。它不启用 TUN、自动切换、DNS 分流或故障阻断。

替换全部占位符，将 selector 的 `default` 分别改为 `reality`、`vless-tls`、`anytls`，每次重启后单独测试。两条 VLESS 使用同一 S-UI 用户的 UUID 和 Vision；Reality 填公钥、short ID、server_name 和 Vision，不能把服务端私钥放进客户端。VLESS TLS 和 AnyTLS 的证书身份须正确。

```sh
sing-box check -c private/client.json
sing-box run -c private/client.json
```

另开终端，用自己确认的 HTTPS 地址检查：

```sh
curl --proxy socks5h://127.0.0.1:1080 --max-time 20 https://example.com/
```

`socks5h` 把本次目标域名交给代理侧解析。这只能证明这个请求走了代理，其他程序、DNS、IPv6、WebRTC 和退出客户端后的表现还得各自测试。三个 TCP 节点能否转发 UDP 应用也要单测，不能从没有 UDP 入站监听得出结论。
