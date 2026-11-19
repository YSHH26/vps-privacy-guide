# 维护、备份与排障

平时先在自己电脑上跑一次 `python3 scripts/vps.py --state private/target.json verify`，看私有检查结果再决定怎么处理。下面手动排障的命令默认面板装在 `/opt/sui-vps`。你的服务器以实际的状态目录为准，换路径之前先核对一下现有服务。

## 查看状态

```sh
cd /opt/sui-vps
sudo docker compose -f deploy/compose.yaml ps
sudo docker compose -f deploy/compose.yaml exec -T s-ui ./sui healthcheck
sudo docker compose -f deploy/compose.yaml logs --tail 100 s-ui
```

日志里可能有连接信息，只在你信得过的终端里看。健康检查只能说明面板在监听；代理程序启动出错、TLS 出错和客户端出错，要分别去看。

## 备份

更新之前先备份。数据库、证书、节点和 CLIProxyAPI 的上游账号都是机密。下面的命令在你自己电脑上运行。脚本会短暂停掉正在运行的 S-UI 和 CLIProxyAPI，现有连接会断。不管备份成功还是失败，它都会把这两个服务恢复到原来的状态；原本就停着的服务，继续停着。

```sh
python3 scripts/vps.py --state private/target.json backup
```

服务器把备份放在 `/var/backups/sui-vps/`，目录权限 700、文件权限 600，保留最近 7 份。备份里有：本项目的配置、S-UI 数据库、固定版本清单、本项目自己目录 `/etc/sui-vps/acme/` 里的证书和 ACME 账号、CLIProxyAPI 的状态和对应的服务配置。其他网站用的全局 Certbot 目录不会备份。备份命令成功退出，只说明快照存好了，不代表这份备份已经恢复过、一定能用。

至少再在别的机器上存一份加密的副本。可以先在私有终端里看一下备份文件名，再用你的 SSH 别名和文件名下载，别把占位符原样拿去运行。下载前先在本机执行 `umask 077`，文件放进权限 700 的私有目录。用 `age -p` 这类工具交互输入加密口令，别把口令写进命令参数、聊天或 Git。加密以后，临时的明文副本也要保管好；确认加密副本能解开，再把明文删掉。

### 检查这份备份能不能读

接着检查服务器上最新的那份备份。这一步只在一个新建的、权限 700 的临时目录里解包，不覆盖服务器上的文件，也不启停服务：

```sh
python3 scripts/vps.py --state private/target.json restore-check
```

结果写在服务器的 `/etc/sui-vps/restore-check.json`。你也可以把备份下载到本机，用当前固定版本的仓库检查指定的文件。把示例 IP 换成你私有记录里的真实服务器 IP：

```sh
python3 scripts/recovery.py --archive private/backup.tar.gz \
  --expected-ip 192.0.2.1 --output private/restore-check.json
```

它会检查这些：

- 归档里只有本项目的路径，没有越界的路径、硬链接、重复条目或特殊设备文件。
- Certbot 的相对链接只指向归档里本项目的证书文件。
- 归属标记、目标 IP 和固定版本都一致。
- SQLite 数据库完整。
- 部署用的证书和续期用的证书一致；证书和私钥配对，IP 身份正确，至少还有一小时有效期，能通过本机 OpenSSL 的信任链检查。
- 续期配置里的账号 ID 在项目目录里有对应的私钥、注册信息和元数据 JSON，证书路径也没有指到别的项目。

账号文件在，不代表证书机构现在还认这个账号，真正能不能续期要另外测。短期证书过期了，这项检查就会失败。这时要重新签一张可信证书，不能关掉验证。

看到 `valid: true`，只说明上面这些在临时目录里的检查通过了。`restore-check` 报告里的 `restore_applied` 永远是 `false`，完整的生命周期检查仍然是"未测试"。别光凭这一步就把 `backup_restore_verified` 标成真，也别直接把归档解压到 `/`。

### 用备份恢复

只有确定要用备份里的账号、数据库、证书和配置替换当前这台服务器的内容时，才做恢复。恢复会中断现有的代理和 API 连接。先给当前状态再备份一份，然后核对服务器上的备份文件名、目标 IP，以及备份和当前仓库的固定版本。版本不一样会被拒绝。

在你自己电脑上运行下面的命令，把示例 IP 和备份文件名换成你自己的：

```sh
python3 scripts/vps.py --state private/target.json restore \
  --archive /var/backups/sui-vps/__BACKUP__.tar.gz --confirm-target 192.0.2.1
```

要在服务器的私有终端里操作，也有一个单独的入口。它默认读服务器上的 `/etc/sui-vps/state.json` 来核对 IP，只有加了 `--apply` 并且确认 IP 完全一致，才会替换文件：

```sh
sudo python3 /opt/sui-vps/scripts/recovery.py \
  --archive /var/backups/sui-vps/__BACKUP__.tar.gz --apply --confirm-target 192.0.2.1
```

恢复时脚本会按这个顺序做：

1. 检查归档、归属标记、IP、版本和证书。
2. 在同一个文件系统上，给每个要替换的目标准备一份私有的新副本。
3. 停掉本项目的定时任务和服务，确认真的停了，再一项项替换本项目的目录和带归属标记的配置文件。
4. 恢复文件权限，重新加载 Nginx、SSH 等配置，只启动之前在运行的服务；之前停着的服务继续停着。

它不会替换全局的 Nginx、SSH 主配置，也不动其他网站的目录。

如果替换失败，或者替换完检查没过，脚本会先确认新版本的服务已经停了，再把替换过的项目一个个退回去，加载旧配置，恢复到之前的运行状态。**如果确认不了服务已经停下，或者回退文件失败，脚本就不再继续替换和重启，把新文件、旧副本和私有日志都留着，等你来检查**，免得正在跑的程序配上另一份数据库。

成功时报告 `restore_applied: true`；失败但已经退回去时报告 `rolled_back: true`。每次恢复的进度存在 `/var/backups/sui-vps/restore-transactions/`。旧副本放在报告里记录的各个目标旁边的隐藏目录里，权限 700，不会自动删除。这些副本里有机密，也占磁盘空间；确认恢复没问题、另存了加密备份以后再处理。进程被强制杀掉或者机器断电时，没法保证多个目录都已经自动退回去，要照着私有的进度记录逐项核对，别盲目再覆盖一次。

本机测试已经覆盖了这些情况：替换成功、健康检查失败后回退、文件系统中途出错、停不下新服务时保留原副本。这些测试不代表你的 VPS 已经恢复过。真正恢复以后，还要检查三个节点、真机客户端、防泄露和正式证书续期，再把这台机器的结果记下来。

## 升级与回滚

1. 先读 S-UI 和 sing-box 的发布说明，备份当前状态、镜像摘要和证书。
2. 在测试环境里更新镜像 tag 和摘要，同步改 versions.json，跑仓库检查，三个协议都实际连一遍。
3. 在正式环境执行 `docker compose -f deploy/compose.yaml up -d` 切换，再重新检查一遍。
4. 失败了先别动，留着失败的现场好排查。用 `restore-check` 检查备份；要恢复同一套固定版本的配置和数据库，可以用上面的恢复流程。要降到旧版本，先在隔离环境里确认数据库迁移兼容，别绕过版本检查。
5. 数据库升级可能没法撤销，不能只把镜像降回去还接着用迁移过的数据库。恢复前先确认备份完整、路径正确。

不开 Watchtower，也不自动跟 latest。Docker 的 `restart: unless-stopped` 只在进程退出后重启它，健康状态变成 unhealthy 时不会自动把节点修好。

## 证书续期

Certbot 用的是本项目自己的目录 `/etc/sui-vps/acme/`，工作文件和日志分别在 `/var/lib/sui-vps-acme/`、`/var/log/sui-vps-acme/`。别和全局 `/etc/letsencrypt/` 的账号或 hook 混用。定时续期必须开着，短期的 IP 证书尤其要盯着。续期以后，deploy hook 要做完这几件事：

1. 确认这次续期的是 `sui-vps` 证书，其他网站的证书不管。
2. 检查新证书的有效期，检查公钥和私钥是否配对，把当前的文件备份一份。
3. 把新的 fullchain.pem 和 privkey.pem 同步到 `/opt/sui-vps/deploy/state/cert/`，权限分别是 644 和 600。
4. 重启 S-UI、重新加载 Nginx，再分别检查健康状态、公网 HTTPS，以及客户端的 VLESS TLS 和 AnyTLS。重启会断开连接。
5. 失败的话，换回之前配对的证书和私钥，再检查服务。别关掉客户端的证书校验。

自动部署完以后，要检查实际装好的续期定时任务和同步 hook，别因为部署成功退出了就认定续期一定没问题。在本机运行 `python3 scripts/vps.py --state private/target.json cert-dry-run` 演练签发流程。这一步会禁用目录里的 hook，免得把测试环境（staging）的证书送进正式服务。正式证书有没有同步过去、Nginx 有没有真的加载，要另外用 `cert-sync` 和 `verify` 检查；S-UI 的两个 TLS 节点还要实际连一下。光靠 dry-run 证明不了这些。别把 staging 测试证书复制到正式服务里。

本仓库的自动部署用 Nginx webroot 做校验，续期时公网 TCP 80 和 `/.well-known/acme-challenge/` 要能访问到。别把它改成 standalone 模式，却还留着占用 80 端口的 Nginx 配置。

## 常见问题

| 现象 | 先查什么 |
| --- | --- |
| 面板打不开 | HTTPS 9443、证书身份、Nginx、面板路径、管理员认证；必要时经 SSH 隧道检查回环后台 |
| S-UI 显示健康但节点不通 | 是否已添加入站/用户、核心日志、云安全组、Docker 端口 |
| VLESS TLS/AnyTLS 证书错误 | SAN 与 server_name、有效期、完整证书链、客户端时间、容器内证书路径 |
| 只有 VLESS TLS 不通 | TCP 2443 映射、UUID、Vision、证书链与证书身份，不要套用 Reality 参数 |
| Reality 不通 | UUID、flow、公私钥配对、short ID、SNI/握手目标、双方时间 |
| 订阅缺少节点 | 用户关联、发布地址、出站模板、客户端格式支持 |
| 更换证书后仍显示旧证书 | 容器挂载文件是否更新，核心是否加载新文件 |

要把错误日志发给别人看，先把 IP、用户标识、订阅路径、认证头和密钥删掉。

## 订阅、CLIProxyAPI 与本机账号页

想确认 S-UI 重建以后还能读到原来的配置，先备份。把 `my-vps` 换成你的 SSH 别名，在本机运行下面的命令。重建时节点连接会短暂中断。

```sh
ssh my-vps 'docker compose -f /opt/sui-vps/deploy/compose.yaml up -d --force-recreate s-ui'
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
```

对比重建前后的 S-UI 账号和节点，确认原来的凭据还能用。换了订阅令牌以后，在本机分别请求四种订阅的新旧地址：新地址应该返回正确的配置，旧地址应该返回 404。整个过程中，真实的订阅地址都放在私有文件里。

订阅令牌和管理员密码是分开管的。令牌泄露了，就换令牌，每个客户端都更新一遍，再跑 `export` 更新本机账号页，并确认旧令牌拿不到你的配置了。HTTP 日志里别记带令牌的路径、查询参数和认证头。

CLIProxyAPI 的上游账号由你以后自己添加，备份时同样当机密处理，也别写进公开的示例。管理 Key 和调用 Key 是分开的两个。服务健康不代表上游账号有效；等有了真实账号，流式请求和 WebSocket 还要单独测。

Clash 订阅用的规则数据由 `sui-vps-rules.timer` 每天刷新，存在服务器的 `/var/lib/sui-vps/rules/`，只能通过带 Clash 令牌的路径下载。最近一次成功刷新的记录在 `/etc/sui-vps/rules.json`。下载或 sha256 校验失败时，继续用上一份。`verify` 的 `rules_mirror` 会检查文件在、能正常下载。这份数据是故意跟着上游最新版走的，这点和固定版本的程序不一样。

没配搬瓦工 API 时，流量按默认出口网卡的收发字节累计，状态存在 `/etc/sui-vps/traffic-local.json`，每十分钟更新一次。服务器重启后网卡计数会清零，脚本会接着往上加，之前的用量不会丢；但如果在两次采样之间重启，最后那一小段流量会少算。和服务商后台对不上时，用 `traffic-calibrate --used-gb` 按后台的数字校准。

本机账号页只放在你的私有目录里，文件权限 600，所在目录 700。页面上的遮挡不是加密，备份时要加密。重装系统以后，旧的账号页要标成失效，免得和新的弄混。官方流量暂时读不到时，页面会显示读取失败或缓存时间，不会填一个固定额度假装是官方数据。
