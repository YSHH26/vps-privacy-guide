# 在新服务器上从头试一遍

这一页讲怎么在一台测试 VPS 上从零部署一遍。先把仓库代码和本机检查都做完，再到指定的测试 VPS 上操作。要做到的是：下一个人只用仓库里的入口就能部署完，不靠上一轮留下的工具、数据库，也不靠现场临时敲的命令。

## 开始前先准备

- SSH 别名、预期的公网 IP、实际端口和密钥路径，都写在 `private/target.json` 里。
- 系统和架构、服务商那边的实例标识，以及这一轮你被允许做哪些操作。
- 要测的真实客户端：系统、应用和内核版本。
- 证书身份（域名或公网 IP），以及申请证书用的联系信息。
- 需要用到的服务商 API 凭据、旧实例的配置和上游授权的加密备份，放在权限受限的目录里。别把其他运维工作区整个复制过来。

先想好换系统以后怎么拿到新的登录信息、怎么装 SSH 密钥。别以为换系统会保留 `authorized_keys`。新的主机指纹要通过可信渠道核对，只更新这个目标的 known_hosts，别全局关掉主机检查。

## 第一次接入：先核对主机，再装专用密钥

目标文件里保留你已有的 SSH 别名和预期 IP。脚本会核对这个别名实际连到的是不是 root 和这个 IP，不会改你的全局 SSH 配置。用密码接入的话，本机还要装 `sshpass`，先用 `sshpass -V` 确认能用。

先从服务商可信的控制台里读出服务器的 SSH 主机公钥，或者用你已经通过可信渠道核对过的 `known_hosts` 文件，把需要的公钥复制到本项目一个权限 600 的文件里，再在目标文件里填上 `known_hosts_file`。没核对过的 `ssh-keyscan` 输出不能当证据。这个文件要写上实际的 IP 和端口；端口不是 22 的话，主机那一栏写成 `[IP]:端口`。

有初始密码的话，用本机编辑器把它单独存进一个文件，文件权限 600、所在目录 700，比如 `private/initial-password`。别写进命令参数。然后运行：

```sh
python3 scripts/vps.py --state private/target.json init --password-file private/initial-password
```

也可以在自己的终端里运行 `init --ask-password`，直接输入密码，不存成文件。密码通过 `sshpass -d` 继承的文件描述符传过去，不会出现在环境变量或进程参数里。终端没法隐藏输入时，命令会停下，这时改用权限受限的文件。

已经能用密钥登录的，直接运行 `init`，把现在的登录方式换成这次部署专用的密钥。目标状态里没指定 `identity_file` 时，脚本会在状态文件同一目录的 `ssh/` 里新建一把 Ed25519 密钥，目录权限 700、文件 600；指定了就用你指定的。服务器上原有的公钥会保留，脚本另外建一条只允许用这把密钥登录的新 SSH 连接。**新连接成功以后**，才会保存密钥路径、删掉初始密码文件；失败的话状态和密码文件都还在，查清原因再重试。关掉服务器的密码登录，是后面部署阶段的事。

你也可以用 `bootstrap_proof_file` 代替现成的 `known_hosts_file`。第一次接入用的证明文件需要下面示例里的 `source`、`ip`、`boot_id`、`ssh_port` 和 `host_public_keys`，不需要换系统时间和 VEID。换系统后用的证明文件，所有字段都要跟这一轮的实例对上。

## 换系统前，先把旧实例保存好

如果你被允许测试的这台服务器上已经跑着旧的部署，先确认本机能用 `age` 和 `age-keygen`，准备好权限 600 的目标文件和服务商凭据。然后在仓库里运行：

```sh
python3 scripts/legacy_backup.py --state private/target.json
```

脚本先核对 SSH 别名、目标 IP 和服务商实例，再确认旧的备份入口确实指向已经装好的工具。它只调用旧工具的 `backup`，不会装或启动另一套代理。服务器上的归档通过 SSH 直接送进 age 加密。本机私有目录里会存下密文、权限 600 的 age 身份文件、检查报告和文件清单；这些都别提交，也别贴进聊天。身份文件要另外安全保管，光有密文是恢复不了的。

加密完，脚本会真的把它解密到系统临时目录里一个权限 700 的隔离目录，恢复出来，逐个文件核对内容，检查 3x-ui 的 SQLite 数据库、旧部署资料、CLIProxyAPI 的配置和授权目录（授权目录是空的也行）。证书这类指向归档内文件的链接，会改成隔离目录里的相对链接。指向归档外面的链接（比如 systemd 的），只在私有清单里记下原路径、目标和权限，不会真的建出能访问本机系统的链接。原始的加密归档里这些链接照样保留。检查完，临时的明文会自动删掉。

成功后，目标状态里的 `encrypted_backup` 指向这份密文，`backup_restore_verified` 是 `true`，`backup_restore_scope` 里写清楚做到了哪一步：只完成了解密、在隔离目录里恢复普通文件和检查 SQLite；外部链接只保留了元数据，业务服务没有恢复验证。**这份旧实例的保存，不代表 S-UI 的备份恢复、业务服务或整个生命周期检查通过了。** 任何一步失败，都不会留下这次换系统需要的恢复确认。

## 用仓库入口执行

常规的几个阶段都在本机运行：

```sh
python3 scripts/vps.py --state private/target.json preflight
python3 scripts/vps.py --state private/target.json deploy
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
python3 scripts/vps.py --state private/target.json export
```

1. `preflight` 只看不改，检查 SSH 目标、IP、系统、架构、端口、Docker 和防火墙，同时记下这一轮的 boot ID、目标配置指纹和要上传的源文件摘要。部署前会再对比一次；服务器重启过、改了目标配置、改了仓库文件，或者超过一小时，都要重跑。上传的就是检查时那一份源文件，检查完不会重新打包。记下仓库提交号和这是第几轮测试。
2. 照 [部署教程](deployment.md) 配好可信证书、S-UI 的三个入站、HTTPS 面板和订阅、CLIProxyAPI。面板和 API 用各自独立的认证，CLIProxyAPI 先不加上游账号。
3. 照 [检查清单](verification.md) 检查服务，再一个个测 Reality、VLESS TLS 和 AnyTLS，包括填错凭据会不会被拒。
4. 在真实客户端里导入对应的订阅。Surge 先测 AnyTLS，v2rayN/NG 分别测两个 VLESS。
5. 照 [防泄露步骤](leak-protection.md) 分别测 TUN、DNS、IPv6、WebRTC、节点故障、客户端退出、切换网络、休眠和重启。
6. 检查证书续期、同步和加载，容器重建后数据还在不在，备份恢复、升级回滚、订阅刷新和重跑部署。`restore-check` 只在隔离目录里检查；真正恢复要明确选一份服务器上的备份，用 `restore --archive … --confirm-target 预期IP` 执行，恢复完重新测服务和节点。检查旧备份代替不了真正做一次恢复演练。
7. 把修复和额外做的操作写回仓库，最后再从零完整测一遍。

日常的 `deploy` 不管换系统。**要从零测一遍时，必须先拿到针对这台服务器的明确换系统授权，再用单独的换系统命令。** 目标文件里还要有：

- `veid`
- `provider_file`：一个权限受限的 JSON 文件的路径，里面是服务商的 `veid` / `api_key`
- `identity_file`：本机私钥路径
- `encrypted_backup`：age 加密备份的路径

还要记下 `backup_restore_verified: true` 和写清楚范围的 `backup_restore_scope`。旧实例保存到哪一步见上一节；S-UI 的生命周期检查还是要真正恢复一次、重新测服务。光检查文件格式，证明不了能恢复。

换系统前先运行 `provider-proof`。它读服务商的官方 API，把这次的随机标记、boot ID、主机公钥和现有的可信 SSH 连接互相核对，生成一份一小时内有效、绑定这台服务器的能力记录。不需要你去编一个"官方文档已审核"的标记。系统模板从 API 实际返回的列表里选，具体读哪些字段、各种状态是什么意思，见 [提供商证明说明](provider-api.md)。如果目标状态里已经有 `encrypted_backup_sha256`，换系统前还会边读边校验整份加密备份的摘要。

```sh
python3 scripts/vps.py --state private/target.json provider-proof
python3 scripts/vps.py --state private/target.json reinstall --os-template __OFFICIAL_OS_TEMPLATE__ --confirm-target __SSH_ALIAS__:__EXPECTED_IP__:__VEID__
```

如果你确定服务器上的旧数据不要了（比如是上一轮的测试部署），可以在 `reinstall` 后面加 `--discard-existing-data`。加了它，脚本就不再要求加密备份和恢复记录，但会在目标状态里写一条 `backup_waived`，记下你放弃了旧数据。IP 证书不算在放弃的范围里：换系统前会存到本机，换系统后还有效就直接拿来用，免得撞上 Let's Encrypt 每周的签发上限，详见 [换系统时证书怎么处理](tls.md#换系统时证书怎么处理)。其他核对一项都不少：服务商证明、目标确认、旧 boot ID 照常检查。只有你真的愿意丢掉整台服务器的数据时才用这个开关。`legacy_backup.py` 目前只能备份旧版的 3x-ui 实例，备份不了本项目的 S-UI 部署。

上面的确认参数里没有密码，但还是只在本机终端里用。换系统前，脚本会通过服务商 API 再核对一遍实例标识、公网 IP 和 SSH 别名是不是对得上，对不上马上停。换系统会中断代理、面板和 CLIProxyAPI，清掉系统上的数据。

换系统请求发出去了，不等于新系统已经能登录。等服务商显示机器在运行了，再跑 `provider-proof`，通过官方的 HTTPS API 拿到这一轮新的 boot ID、公钥和端口，然后跑 `bootstrap`。这份 API 证明只有十五分钟有效，绑定这台服务器和这一次换系统，旧系统的资料不能拿来复用：

```sh
python3 scripts/vps.py --state private/target.json provider-proof
python3 scripts/vps.py --state private/target.json bootstrap
```

API 暂时用不了的话，可以从服务商可信的控制台里读新主机的资料。脚本不会相信没核对过的 `ssh-keyscan`，也不会随便接受新指纹。手动的做法是把资料存进一个权限 600 的 `private/bootstrap-proof.json`：

```json
{
  "source": "provider-console",
  "ip": "192.0.2.1",
  "veid": "__VEID__",
  "reinstall_at": "__COPY_NUMERIC_VALUE_FROM_TARGET_STATE__",
  "boot_id": "__NEW_BOOT_ID__",
  "ssh_port": 22,
  "host_public_keys": ["ssh-ed25519 __PUBLIC_KEY_BASE64__"]
}
```

`reinstall_at` 要填这一轮目标状态文件里原样的那个数字，不是上面那串字符。在服务商控制台里运行 `cat /proc/sys/kernel/random/boot_id`、`ss -lntp` 和 `cat /etc/ssh/ssh_host_ed25519_key.pub` 就能读到这些资料；只取公钥，别取私钥。确认目标状态里的 `bootstrap_proof_file` 指向这个文件，然后运行：

```sh
python3 scripts/vps.py --state private/target.json bootstrap
```

脚本会把可信的主机公钥写进本项目私有的 `known_hosts`，用实际端口另开一条严格校验的 SSH 连接，并对比新的 boot ID。

- 服务商已经把你的密钥装回去了：直接运行 `bootstrap`。
- 服务商只给了初始密码：把密码放进权限受限的文件，运行 `bootstrap --password-file private/initial-password`，或者在本机终端里用 `bootstrap --ask-password`。

核对完主机证明以后，它会装好公钥，用新的独立密钥连一次确认能登录，再删掉密码文件。全局 SSH 别名和其他主机的 known_hosts 都不会动。服务商原始的换系统响应里可能有一次性密码，只存到 `private/reinstall-response.json`，不会打印出来。

目前，读取服务商信息这一步已经有这一轮官方 API 的响应，也和可信的旧 SSH 连接对照过。停机、换系统、写入公钥库和新系统引导这几步，真正执行之前都还算待测试。能力记录会把这些观察结果分开存；读取成功或者本机模拟测试通过，都不能当成完整的换系统流程已经通过。

每一轮完整的"从零"测试都要真的换系统。删容器、清数据库、恢复旧快照，都不能冒充全新系统上的部署。普通阶段失败了，先查原因、修仓库、再重跑；所有修复都合进去以后，还要在全新的系统上再部署一次。只在被授权的测试实例上做，不能扩到其他服务器。

## 卡住了就记下来

记下卡在哪个阶段、可以公开的错误摘要、根本原因，以及仓库里怎么修的。真实地址、凭据和原始日志只放在私有记录里。需要你去登录服务商或者做别的交互时，把那一步写成待完成，能独立做的检查接着做。

## 每轮结果怎么记

| 项目 | 记录内容 |
| --- | --- |
| 日期、仓库提交、测试轮次 | 实际值 |
| 提供商换系统、系统镜像、架构 | 实际执行与接入结果；不公开完整目标标识 |
| S-UI 与内置核心版本 | 分别读取，不用模板校验镜像版本代替 |
| 静态 / Compose / 固定核心解析 | 各自通过、失败或未测试 |
| HTTPS、订阅、CLIProxyAPI | 服务结果；无上游时不写上游调用通过 |
| Reality / VLESS TLS / AnyTLS | 每条单独认证与出口结果 |
| Surge / v2rayN / v2rayNG | 分别记录版本、系统和结果 |
| TUN / DNS / IPv6 / WebRTC | 各自的方法和结果 |
| 故障 / 退出 / 切网 / 重启 | 是否出现意外直连 |
| 续期 / 同步 / 加载 | 分别记录 |
| 备份恢复 / 回滚 / 重跑 | 实际结果 |
| 本机 HTML | 与本轮新实例一致；旧资料已标为失效 |
| 所有修复后重新装 OS 复验 | 实际轮次与结果 |

没测过的项目写"未测试"，并注明缺了什么设备或者哪个动作没做。公开的结果只发去掉机密的摘要，别上传账号页 HTML。
