# TLS、IP 证书与 Reality

VLESS TLS、AnyTLS、面板、订阅和 CLIProxyAPI 都需要可信证书。自动部署使用签给 VPS 公网 IPv4 的 Let's Encrypt IP 证书，不需要购买域名，客户端保持证书验证。

## 自动部署怎样管理证书

运行 [部署入口](deployment.md) 的 `deploy` 时，脚本会安装固定版本 Certbot，用 Nginx webroot 完成 HTTP 校验，再同步证书和配置 HTTPS。TCP 80 必须能从公网访问；Nginx 只在 `/.well-known/acme-challenge/` 提供校验文件，其他路径返回 404。

IP 证书有效期约 160 小时，因此脚本每六小时检查续期。Certbot 的账号、证书和续期配置都保存在本项目私有目录 `/etc/sui-vps/acme/`，不使用或备份其他站点的全局证书目录。

| 内容 | 位置 |
| --- | --- |
| 正式证书及私钥 | `/etc/sui-vps/acme/live/sui-vps/` |
| 实际证书归档、ACME 账号、续期配置 | `/etc/sui-vps/acme/` 内相应目录 |
| 同步给 S-UI 和 Nginx 的证书 | `/opt/sui-vps/deploy/state/cert/` |
| S-UI 容器中的证书路径 | `/app/cert/fullchain.pem`、`/app/cert/privkey.pem` |
| 续期任务 | `sui-vps-renew.timer`、`sui-vps-renew.service` |

客户端的连接地址与被验证身份都是服务器公网 IP，证书必须在 IP SAN 中包含它。IP 不会像域名一样通过 SNI 发送，不能靠填一个无关域名绕过身份检查。不要设置 `insecure=true` 或 `skip-cert-verify=true`。

## 分别检查续期、同步和实际加载

先演练签发。下面从你自己的电脑运行：

```sh
python3 scripts/vps.py --state private/target.json cert-dry-run
```

这个阶段不运行同步 hook，不把测试证书复制给正在运行的服务。通过只说明测试环境中的续期申请成功。

再同步正式证书并检查服务：

```sh
python3 scripts/vps.py --state private/target.json cert-sync
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
```

同步前会检查有效期、IP 身份以及证书与私钥是否配对。同步后重载 Nginx、重启运行中的 S-UI，再比较各 TLS 入口实际提供的证书；失败时尝试恢复旧证书并重新加载。**重启会中断现有连接。** 失败细节只保存在受限记录中，按 [维护说明](maintenance.md) 排查，不关闭客户端验证来继续。

自动入口当前只实现公网 IPv4 证书。若你要改用域名，需要另行实现 DNS、签发参数、S-UI 发布身份和客户端 SNI，并重新测试；仅把一张域名证书复制进来不能替代这些修改。

来源：[Let's Encrypt IP 证书说明](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)、[Certbot IP 签发说明](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)。

## Reality

自动配置使用 VLESS + Reality + Vision，默认握手目标是 `www.microsoft.com:443`。这需要 VPS 能正常访问该 TLS 站点；其可达性和客户端兼容性仍需逐次网络检查。这里没有使用 Xray 的“回落到自己”配置。

S-UI API 生成独立 Reality 密钥对，脚本另生成 short ID 和 VLESS UUID。私钥保留在服务器，只把公钥写入客户端节点。Reality 不使用本项目普通 TLS 证书路径。

| 参数 | 服务端 | 客户端 |
| --- | --- | --- |
| UUID | S-UI 用户 UUID | 相同 UUID |
| Flow | xtls-rprx-vision | xtls-rprx-vision |
| Reality 密钥 | private_key | 配对的 public_key |
| short ID | short_id 数组 | 数组中一个值 |
| 握手目标 | 实际 TLS 站点与 443 | 匹配的 server_name |

示例中的 `__REALITY_HANDSHAKE_SERVER__` 和 `__REALITY_SERVER_NAME__` 仍是占位符，不能直接当作目标使用。修改握手目标后，同步面板配置与订阅，执行固定核心检查和逐节点网络测试。

来源：[sing-box Reality 配置](https://sing-box.sagernet.org/configuration/shared/tls/#reality-fields)。
