# 维护、备份与排障

日常先从本机运行 `python3 scripts/vps.py --state private/target.json verify`，根据私有检查结果处理。以下手工排障命令假设面板部署目录是 `/opt/sui-vps`；以本轮实际状态目录为准，替换路径前先核对现有服务。

## 查看状态

```sh
cd /opt/sui-vps
sudo docker compose -f deploy/compose.yaml ps
sudo docker compose -f deploy/compose.yaml exec -T s-ui ./sui healthcheck
sudo docker compose -f deploy/compose.yaml logs --tail 100 s-ui
```

日志可能包含连接信息，只在可信终端查看。健康检查仅验证面板监听；代理核心启动错误、TLS 错误和客户端错误要分别查看。

## 备份

先备份再更新。数据库、证书、节点和 CLIProxyAPI 上游账号都包含秘密。下面从你的电脑调用仓库入口；脚本会短暂停止原本运行中的 S-UI 和 CLIProxyAPI，现有连接会中断，完成或失败后都会尝试恢复它们之前的运行状态。原本停止的服务保持停止。

```sh
python3 scripts/vps.py --state private/target.json backup
```

服务器把备份放在 `/var/backups/sui-vps/`，目录权限 700、文件权限 600，保留最近 7 份。备份包含本项目配置、S-UI 数据库、固定版本清单、本项目独立目录 `/etc/sui-vps/acme/` 中的证书与 ACME 账号、CLIProxyAPI 状态和对应服务配置；不会备份其他站点的全局 Certbot 目录。备份退出成功只表示快照已保存，不代表已经恢复过。

至少另存一份加密的异机副本。你可以在私有终端查看备份文件名，再用自己的 SSH 别名和文件名下载；不要把占位符原样运行。先在本机执行 `umask 077`，把文件放在权限 700 的私有目录。使用 `age -p` 等工具交互输入加密口令，不把口令写进命令参数、聊天或 Git。加密后仍应妥善保管临时明文副本；确认加密副本可以解密后再清理。

### 检查这份备份能否读取

接着检查服务器上最新一份备份。这个步骤只在新建的权限 700 临时目录里解包，不覆盖服务器文件，也不启动或停止服务：

```sh
python3 scripts/vps.py --state private/target.json restore-check
```

结果写入服务器 `/etc/sui-vps/restore-check.json`。你也可以把备份下载到本机，在当前固定版本的仓库中检查指定文件；把文档保留地址换成你本机私有记录中的实际目标 IP：

```sh
python3 scripts/recovery.py --archive private/backup.tar.gz \
  --expected-ip 192.0.2.1 --output private/restore-check.json
```

检查内容包括：归档只包含本项目路径，没有路径越界、硬链接、重复条目或特殊设备；Certbot 的相对链接只指向归档里本项目的证书文件；归属标记、目标 IP 和固定版本一致；SQLite 完整性正常；部署证书和续期证书一致，证书与私钥匹配、IP 身份正确、至少还有一小时有效期，并能通过本机 OpenSSL 信任链检查；续期配置中的账号 ID 在项目目录内有对应的私钥、注册与元数据 JSON，证书路径也没有指向其他项目。账号文件存在并不证明提供方目前仍接受该账号，真实续期需另测。过期的短期证书会使检查失败，你需要重新签发可信证书，不能关闭验证。

看到 `valid: true` 只代表这些暂存检查通过。`restore-check` 的 `restore_applied` 始终是 `false`，生命周期检查仍为“未测试”。不要仅凭这一步把 `backup_restore_verified` 标成真，也不要直接把归档解压到 `/`。

### 应用备份

只有确认要让备份中的账号、数据库、证书和配置替换当前实例时，才执行恢复。恢复会中断现有代理和 API 连接。先保留一份当前备份，再核对服务器上的备份文件名、目标 IP，以及备份和当前仓库的固定版本；版本不同会被拒绝。

从你的电脑调用下面入口，把保留地址和备份文件名换成自己的记录：

```sh
python3 scripts/vps.py --state private/target.json restore \
  --archive /var/backups/sui-vps/__BACKUP__.tar.gz --confirm-target 192.0.2.1
```

如需在服务器的私有终端操作，同一功能也有独立入口；它默认读取本机 `/etc/sui-vps/state.json` 来核对 IP，只有加上 `--apply` 和完全匹配的确认 IP 才会替换文件：

```sh
sudo python3 /opt/sui-vps/scripts/recovery.py \
  --archive /var/backups/sui-vps/__BACKUP__.tar.gz --apply --confirm-target 192.0.2.1
```

脚本先检查归档、归属标记、IP、版本和证书，再为每个目标准备同文件系统的私有新副本。它会暂停本项目定时器和服务，确认服务确实停止后，逐项替换本项目目录与有归属标记的配置文件。之后恢复文件权限、重新加载 Nginx/SSH 等配置，并只启动之前运行的服务；之前停止的服务保持停止。它不替换全局 Nginx、SSH 主配置或其他站点目录。

如果替换或恢复后检查失败，脚本会先确认候选服务已经停止，再把已替换项目逐一回退，加载旧配置并恢复之前的运行状态。**如果无法确认服务停止，或者文件回退失败，脚本会停止继续替换和重启，保留候选文件、旧副本和私有日志，等待你检查**，避免运行中的进程搭配另一份数据库。

成功时报告 `restore_applied: true`；失败并完成回退时报告 `rolled_back: true`。每次事务的进度保存在 `/var/backups/sui-vps/restore-transactions/`，旧副本位于报告记录的各目标旁边的权限 700 隐藏目录中，不会自动删除。这些副本含秘密，会占用额外磁盘空间；确认恢复结果并另存加密备份后再处理。进程被强制终止或机器断电时，不能保证多目录事务已经自动回退，应按私有事务记录逐项核对，不能盲目再次覆盖。

本机测试已经覆盖文件替换成功、健康失败回退、文件系统中途失败，以及无法停止候选服务时保留原副本的行为。它们不代表你的 VPS 已经恢复过。真实恢复后仍要检查三个节点、实际客户端、防泄露与正式证书续期，再记录本台机器的生命周期结果。

## 升级与回滚

1. 阅读 S-UI 和 sing-box 的发行说明，备份当前状态、镜像摘要及证书。
2. 在测试环境更新镜像 tag 与摘要，同步 versions.json，执行仓库检查和三协议实测。
3. 正式环境执行 `docker compose -f deploy/compose.yaml up -d` 切换，重新验收。
4. 失败时先保留失败状态作诊断。用 `restore-check` 检查备份，恢复同一组固定版本的配置与数据库时可以使用上面的事务恢复；跨版本降级需先在隔离环境验证迁移兼容性，不要绕过版本检查。
5. 数据库升级可能不可逆，不能只降级镜像而继续使用迁移后的数据库。恢复前先确认备份完整且路径正确。

不启用 Watchtower 或自动追踪 latest。Docker 的 `restart: unless-stopped` 负责进程退出后的重启，不会因为健康状态变为 unhealthy 自动修复节点。

## 证书续期

Certbot 使用项目独立目录 `/etc/sui-vps/acme/`，工作和日志分别放在 `/var/lib/sui-vps-acme/`、`/var/log/sui-vps-acme/`。不要混用全局 `/etc/letsencrypt/` 的账号或 hook。定时续期必须启用，短期 IP 证书尤其需要监控。续期后的 deploy hook 应完成以下动作：

1. 确认此次续期对应 `sui-vps` 证书；其他站点的证书不处理。
2. 检查新证书有效期，检查公钥与私钥配对，保留当前文件备份。
3. 将新 fullchain.pem 与 privkey.pem 同步到 `/opt/sui-vps/deploy/state/cert/`，权限分别 644 和 600。
4. 重启 S-UI 并重载 Nginx，分别检查健康状态、公网 HTTPS 与客户端 VLESS TLS/AnyTLS。重启会断开连接。
5. 如果失败，恢复之前匹配的证书/私钥并检查服务；不要关闭客户端证书校验。

自动部署后应检查实际安装的续期定时任务和同步 hook，不能只因部署退出成功就假定续期可靠。从本机运行 `python3 scripts/vps.py --state private/target.json cert-dry-run` 验证签发流程；脚本禁用目录 hook，避免把 staging 证书送到生产服务。另用 `cert-sync` 和 `verify` 检查正式证书同步与 Nginx 的实际加载，S-UI 两个 TLS 节点仍需网络实测；dry-run 本身不能证明这些结果。不要把 staging 测试证书复制到生产服务。

本仓库自动部署使用 Nginx webroot 校验，续期时保持公网 TCP 80 和 `/.well-known/acme-challenge/` 可达。不要把它改成 standalone 后仍沿用占用 80 端口的 Nginx 配置。

## 常见问题

| 现象 | 优先检查 |
| --- | --- |
| 面板打不开 | HTTPS 9443、证书身份、Nginx、面板路径、管理员认证；必要时经 SSH 隧道检查回环后台 |
| S-UI 显示健康但节点不通 | 是否已添加入站/用户、核心日志、云安全组、Docker 端口 |
| VLESS TLS/AnyTLS 证书错误 | SAN 与 server_name、有效期、完整证书链、客户端时间、容器内证书路径 |
| 只有 VLESS TLS 不通 | TCP 2443 映射、UUID、Vision、证书链与证书身份，不要套用 Reality 参数 |
| Reality 不通 | UUID、flow、公私钥配对、short ID、SNI/握手目标、双方时间 |
| 订阅缺少节点 | 用户关联、发布地址、出站模板、客户端格式支持 |
| 更换证书后仍显示旧证书 | 容器挂载文件是否更新，核心是否加载新文件 |

如果共享错误日志，先移除 IP、用户标识、订阅路径、认证头和密钥。

## 订阅、CLIProxyAPI 与本机账号页

要验证 S-UI 重新创建后仍能读到原来的配置，先备份。把 `my-vps` 换成你的 SSH 别名，在本机执行下面的命令。重建会短暂中断节点连接。

```sh
ssh my-vps 'docker compose -f /opt/sui-vps/deploy/compose.yaml up -d --force-recreate s-ui'
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
```

比较重建前后的 S-UI 账号和节点，确认原凭据仍然有效。订阅令牌轮换后，分别从本机请求两种新旧订阅，检查新链接返回正确配置，旧链接返回 404。整个过程都把真实链接放在私有文件中。

订阅令牌与管理员密码分开管理。令牌泄露后轮换并逐客户端更新，再运行 `export` 更新本机 HTML；确认旧令牌不再返回私人配置。HTTP 日志不要记录带令牌的路径、查询参数或认证头。

CLIProxyAPI 上游账号由你后续添加，备份时同样当作秘密；不要把它们写进公开示例。管理 Key 和调用 Key 独立。服务健康不能证明上游账号有效，流式请求和 WebSocket 也要在有实际账号后单独测试。

本机 HTML 只存在你的私有目录，文件权限 600，父目录 700。页面遮挡不是加密，备份时应加密；重装后的旧账号页要标为失效，避免混用。官方流量暂时读取失败时显示失败或缓存时间，不填固定额度冒充官方结果。
