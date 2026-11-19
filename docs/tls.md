# TLS、IP 证书与 Reality

VLESS TLS、AnyTLS、面板、订阅和 CLIProxyAPI 都要用可信证书。自动部署会申请一张签给 VPS 公网 IPv4 的 Let's Encrypt IP 证书，不用买域名，客户端也照样开着证书验证。

## 自动部署怎么管证书

运行 [部署入口](deployment.md) 的 `deploy` 时，脚本会装好固定版本的 Certbot，通过 Nginx webroot 完成 HTTP 校验，再同步证书、配好 HTTPS。TCP 80 必须能从公网访问到。Nginx 只在 `/.well-known/acme-challenge/` 下提供校验文件，其他路径都返回 404。

IP 证书的有效期大约只有 160 小时，所以脚本每六小时检查一次要不要续期。Certbot 的账号、证书和续期配置都存在本项目自己的私有目录 `/etc/sui-vps/acme/` 里，不用、也不备份其他网站的全局证书目录。

| 内容 | 位置 |
| --- | --- |
| 正式证书及私钥 | `/etc/sui-vps/acme/live/sui-vps/` |
| 实际证书归档、ACME 账号、续期配置 | `/etc/sui-vps/acme/` 内相应目录 |
| 同步给 S-UI 和 Nginx 的证书 | `/opt/sui-vps/deploy/state/cert/` |
| S-UI 容器中的证书路径 | `/app/cert/fullchain.pem`、`/app/cert/privkey.pem` |
| 续期任务 | `sui-vps-renew.timer`、`sui-vps-renew.service` |

客户端连的是服务器公网 IP，验证的也是这个 IP，所以证书的 IP SAN 里必须有它。IP 不会像域名那样通过 SNI 发出去，填一个不相干的域名也绕不过身份检查。别设 `insecure=true` 或 `skip-cert-verify=true`。

## 换系统时证书怎么处理

Let's Encrypt 对同一个 IP 有签发上限：**任意 7 天内最多 5 张**。每次换系统都重新申请的话，一周换系统几次就会被拒，得等最早那张满 7 天才能再签。

所以 `reinstall` 在发出换系统请求之前，会先把服务器上本项目的 ACME 目录（账号、证书、私钥、续期配置）打包，存到你电脑上的 `private/acme-carry.tar.gz`，权限 600。加了 `--discard-existing-data` 也一样：放弃的是其他数据，证书照样会存下来。

换系统后部署时，`deploy` 会把这份证书传回服务器的临时目录。`cert` 阶段先检查几件事：证书是签给这个 IP 的，和私钥配对，至少还剩一天有效期，续期配置齐全，文件链接没有指到目录外面。全都满足才直接用它；有一项不满足就删掉，照常申请新证书。之后的续期和平时一样。

这个文件里有证书私钥，只能留在本机，别上传，也别发给别人。它最多几天就过期，过期了留着也没用，下次换系统前会被新的覆盖。

## 分别检查续期、同步和实际加载

先演练一遍签发。在你自己的电脑上运行：

```sh
python3 scripts/vps.py --state private/target.json cert-dry-run
```

这一步不跑同步 hook，也不会把测试证书复制给正在运行的服务。它通过了，只说明在测试环境里续期申请成功。

再同步正式证书，检查服务：

```sh
python3 scripts/vps.py --state private/target.json cert-sync
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
```

同步之前会检查有效期、IP 身份，以及证书和私钥是否配对。同步以后重新加载 Nginx、重启正在运行的 S-UI，再对比每个 TLS 入口实际给出的证书；失败的话会尝试换回旧证书并重新加载。**重启会断开现有连接。** 失败的细节只存在权限受限的记录里，照 [维护说明](maintenance.md) 排查，别靠关掉客户端验证来继续。

自动部署目前只支持公网 IPv4 证书。想改用域名的话，DNS、签发参数、S-UI 的发布身份和客户端 SNI 都要另外改，改完重新测。光把一张域名证书复制进来是不够的。

来源：[Let's Encrypt IP 证书说明](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)、[Certbot IP 签发说明](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)。

## Reality

自动配置用的是 VLESS + Reality + Vision，**握手目标是这台服务器自己的 HTTPS**（`你的IP:9443`，就是 Nginx 上挂着 IP 证书的那个入口）。

Reality 收到没带正确密钥的连接时，会把它原样转给握手目标。以前的目标是 `www.microsoft.com`，别人直接探测你的 443 端口，会看到一台普通 VPS 说自己是微软，这本身就很可疑。现在探测的人看到的是这台服务器自己的、签给这个 IP 的正常证书，和 9443 上的网站对得上。

有一点要注意：客户端连的是 IP，按 TLS 规范，IP 地址不会当成 SNI 发出去，服务器收到的 SNI 是空的。所以服务端的 Reality 不设 `server_name`（也就是只接受空 SNI），客户端的 `server_name` 填服务器 IP。这种组合用固定版本的 sing-box 1.14.4 和 Mihomo 1.19.33 当客户端测过；v2rayN / v2rayNG 用的 Xray 内核还没测，导入后先单独试一下 Reality 节点。

以前用 `www.microsoft.com` 部署的旧服务器，重跑部署时会保留原来的握手目标，不会偷偷改掉你的客户端配置。想换成回落到自己，要重新部署（本项目的做法是先换成全新系统）。

Reality 的密钥对由 S-UI API 单独生成，short ID 和 VLESS UUID 由脚本另外生成。私钥留在服务器上，客户端节点里只写公钥。Reality 节点本身不用证书，但回落目标用的是本项目的 IP 证书；证书续期后 Nginx 重新加载，回落时看到的证书也跟着更新。`verify` 的 `reality_self_fallback` 会检查：不带凭据连 443 拿到的证书，必须和磁盘上当前的证书一样。

| 参数 | 服务端 | 客户端 |
| --- | --- | --- |
| UUID | S-UI 用户 UUID | 相同 UUID |
| Flow | xtls-rprx-vision | xtls-rprx-vision |
| Reality 密钥 | private_key | 配对的 public_key |
| short ID | short_id 数组 | 数组中一个值 |
| 握手目标 | 服务器 IP 与 9443 | — |
| server_name | 不设置（接受空 SNI） | 服务器 IP |

示例里的 `__SERVER_IP__` 是占位符，部署时换成你的公网 IP。改了握手目标以后，要同步面板配置和订阅，用固定版本的 sing-box 检查配置，再逐个节点做网络测试。

来源：[sing-box Reality 配置](https://sing-box.sagernet.org/configuration/shared/tls/#reality-fields)。
