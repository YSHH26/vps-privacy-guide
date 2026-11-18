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

## 重装系统时证书怎么处理

Let's Encrypt 对同一个 IP 有签发上限：**任意 7 天内最多 5 张**。如果每次重装都重新申请，一周重装几次就会被拒绝，要等最早那张满 7 天才能再签。

所以 `reinstall` 在发出重装请求之前，会先把服务器上本项目的 ACME 目录（账号、证书、私钥、续期配置）打包，存到你电脑的 `private/acme-carry.tar.gz`，权限 600。加了 `--discard-existing-data` 也一样，放弃的是其他数据，证书照样保存。

重装后部署时，`deploy` 把这份证书传回服务器的临时目录。`cert` 阶段先检查：证书是签给这个 IP 的、和私钥配对、剩余有效期至少一天、续期配置齐全、文件链接都没有指向目录之外。全部满足才直接启用；有一项不满足就删掉它，照常申请新证书。之后的续期和平时一样。

这份文件里有证书私钥，只能留在本机，不要上传或发给别人。它最多几天就会过期，过期后留着也没用，下次重装前会被新的覆盖。

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

自动配置使用 VLESS + Reality + Vision，**握手目标是这台服务器自己的 HTTPS**（`你的IP:9443`，也就是 Nginx 上挂着 IP 证书的那个入口）。

这样做的原因：Reality 收到没有正确密钥的连接时，会把它原样转给握手目标。以前目标是 `www.microsoft.com`，别人直接探测你的 443 端口，会看到一台普通 VPS 声称自己是微软，这本身就很可疑。现在探测者看到的是这台服务器自己的、签给这个 IP 的正常证书，和 9443 上的网站一致。

要注意的一点：客户端连的是 IP，TLS 规范不会把 IP 地址当作 SNI 发送，服务器收到的 SNI 是空的。所以服务端的 Reality 不设 `server_name`（等于只接受空 SNI），客户端的 `server_name` 填服务器 IP。我们用固定的 sing-box 1.14.4 和 Mihomo 1.19.33 当客户端测过这种组合；v2rayN / v2rayNG 用的 Xray 核心还没有测，导入后先单独试一次 Reality 节点。

已经用 `www.microsoft.com` 部署的旧服务器，重跑部署时保留原来的握手目标，不会悄悄改掉客户端配置。想换成回落到自己，需要重新部署一台（本项目的做法是先重装系统）。

S-UI API 生成独立 Reality 密钥对，脚本另生成 short ID 和 VLESS UUID。私钥保留在服务器，只把公钥写入客户端节点。Reality 节点本身不用证书，但回落目标用的是本项目的 IP 证书；证书续期后 Nginx 重新加载，回落看到的也随之更新。`verify` 的 `reality_self_fallback` 会检查：不带凭据连 443 时拿到的证书，必须和磁盘上的当前证书一致。

| 参数 | 服务端 | 客户端 |
| --- | --- | --- |
| UUID | S-UI 用户 UUID | 相同 UUID |
| Flow | xtls-rprx-vision | xtls-rprx-vision |
| Reality 密钥 | private_key | 配对的 public_key |
| short ID | short_id 数组 | 数组中一个值 |
| 握手目标 | 服务器 IP 与 9443 | — |
| server_name | 不设置（接受空 SNI） | 服务器 IP |

示例中的 `__SERVER_IP__` 是占位符，部署时替换成你的公网 IP。修改握手目标后，同步面板配置与订阅，执行固定核心检查和逐节点网络测试。

来源：[sing-box Reality 配置](https://sing-box.sagernet.org/configuration/shared/tls/#reality-fields)。
