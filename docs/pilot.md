# 在新服务器上从头试一遍

先把仓库实现和本机检查做完，再在指定测试 VPS 上执行。目标是让下一位使用者从仓库入口完成部署，不依赖上轮遗留的工具、数据库或现场临时命令。

## 开始前先准备

- SSH 别名、预期公网 IP、实际端口与密钥路径，保存在 `private/target.json`。
- 系统与架构、提供商实例标识及本轮获授权的操作范围。
- 实际客户端系统、应用与核心版本。
- 域名或公网 IP 证书身份，以及 ACME 联系资料。
- 必要提供商 API 凭据、旧实例配置及上游授权的加密备份，放在受限目录；不整份复制其他运维工作区。

先确认重装后如何接收新登录信息并安装 SSH 密钥。不要假设重装会保留 `authorized_keys`。新指纹需要可信核验，只更新该目标的 known_hosts，不全局关闭主机检查。

## 第一次接入：先核验主机，再安装专用密钥

目标文件中保留已有的 SSH 别名与预期 IP；脚本核对这个别名解析出的 root/IP，不改全局 SSH 配置。密码接入额外需要本机安装 `sshpass`，先用 `sshpass -V` 确认命令可用。

先从服务商可信控制台读取服务器 SSH 主机公钥，或使用你已通过可信渠道核验过的 `known_hosts` 文件，复制必要公钥到本项目权限 600 的文件，在目标文件填写 `known_hosts_file`。不能把未经核对的 `ssh-keyscan` 输出当作证明。该文件应包含实际 IP 和端口；非 22 端口的主机字段使用 `[IP]:端口`。

若你有初始密码，在本机编辑器将它单独保存在权限 600、父目录 700 的文件中，例如 `private/initial-password`；不要放进命令参数。然后运行：

```sh
python3 scripts/vps.py --state private/target.json init --password-file private/initial-password
```

也可以在自己的终端运行 `init --ask-password`，安全输入密码而不落盘。密码通过 `sshpass -d` 的继承文件描述符提供，不写进环境变量或进程参数。没有可隐藏输入的终端时会停止，改用受限文件。

已有密钥登录可直接执行 `init`，把现有接入迁移到这次部署的专用密钥。没有在目标状态指定 `identity_file` 时，会在状态文件同目录的 `ssh/` 内创建 Ed25519 密钥，目录权限 700、文件 600；已有指定密钥则继续使用。脚本保留服务器已有公钥，并独立建立一条只允许所选密钥认证的新 SSH 连接。**新连接成功以后**才保存密钥路径、删除初始密码文件；失败时状态和密码文件保留，可排查后重试。关闭服务器密码登录由后续部署阶段执行。

你也可以提供 `bootstrap_proof_file` 代替现成的 `known_hosts_file`。首次接入证明需要下面示例中的 `source`、`ip`、`boot_id`、`ssh_port` 和 `host_public_keys`；首次不需要重装时间或 VEID。重装后的证明仍需全部字段绑定本轮实例。

## 重装前先保全已有的旧实例

如果获授权的测试目标已经运行旧部署，先确认本机的 `age`、`age-keygen` 可用，并准备好权限 600 的目标文件及提供商凭据。再从仓库运行：

```sh
python3 scripts/legacy_backup.py --state private/target.json
```

脚本先核对 SSH 别名、目标 IP 和提供商实例，再检查旧备份入口确实指向已安装的工具。它只调用旧工具的 `backup`，不会安装或启动另一套代理。服务器归档经 SSH 直接送入 age 加密，本机私有目录保存密文、权限 600 的 age 身份文件、检查报告和文件清单；不要把它们提交或贴进聊天。请另行安全保管身份文件，只有密文无法恢复。

加密完成后，脚本实际解密到系统临时目录内权限 700 的隔离目录，恢复并逐文件核对内容，检查 3x-ui SQLite 数据库、旧部署资料和 CLIProxyAPI 配置及授权目录；授权目录为空也允许。证书等指向归档内文件的链接会改成隔离目录内的相对链接。指向归档外的 systemd 等链接只在私有清单中保留原路径、目标和权限，不会创建能访问本机系统的链接。原始加密归档仍保留这些链接。临时明文检查结束后自动删除。

成功后目标状态中的 `encrypted_backup` 指向密文，`backup_restore_verified` 为 `true`，并用 `backup_restore_scope` 明确记录：仅完成解密、隔离普通文件恢复和 SQLite 检查；外部链接只保留元数据，业务服务未恢复验证。**这份旧实例保全不代表 S-UI 的备份恢复、业务服务或生命周期验收通过。** 任一步失败都不留下本次重装所需的恢复确认。

## 从仓库入口执行

所有常规阶段从本机运行：

```sh
python3 scripts/vps.py --state private/target.json preflight
python3 scripts/vps.py --state private/target.json deploy
python3 scripts/vps.py --state private/target.json verify
python3 scripts/vps.py --state private/target.json network
python3 scripts/vps.py --state private/target.json export
```

1. `preflight` 只读检查 SSH 目标、IP、系统、架构、端口、Docker 和防火墙，同时记录本轮 boot ID、目标配置指纹与待上传源文件摘要。部署前会再比对；重启、改目标配置、改仓库文件或超过一小时后需重跑。上传使用本次检查的同一份源文件字节，不在检查后重新拼包。记录仓库提交及测试轮次。
2. 对照 [部署教程](deployment.md) 完成可信证书、S-UI 三个入站、HTTPS 面板和订阅、CLIProxyAPI。面板与 API 使用独立认证，CLIProxyAPI 暂无上游账号。
3. 对照 [检查清单](verification.md) 检查服务，再逐条测试 Reality、VLESS TLS、AnyTLS，包括错误凭据拒绝。
4. 在真实客户端导入对应订阅；Surge 先测 AnyTLS，v2rayN/NG 分别测 VLESS。
5. 按 [防泄露步骤](leak-protection.md) 分别测试 TUN、DNS、IPv6、WebRTC、节点故障、客户端退出、切网、休眠与重启。
6. 检查证书续期、同步与加载、容器重建持久化、备份恢复、升级回滚、订阅刷新和部署重跑。`restore-check` 只做隔离检查；实际恢复须显式选择服务器备份并用 `restore --archive … --confirm-target 预期IP` 执行，之后重新测服务与节点。检查旧备份不能代替真正恢复演练。
7. 将修复和额外操作写回仓库，再做最终从零复验。

日常 `deploy` 不负责重装。**需要从零复验时，必须先有针对该目标的明确重装授权，再用独立显式重装命令。** 目标文件另需 `veid`、`provider_file`（含提供商 `veid` / `api_key` 的受限 JSON 文件路径）、`identity_file`（本机私钥路径）和 `encrypted_backup`（age 加密备份路径），并记录 `backup_restore_verified: true` 与明确的 `backup_restore_scope`。旧实例保全的范围见上一节；S-UI 生命周期检查仍需真正恢复并重测服务。仅检查文件格式不能证明可恢复。重装前先运行 `provider-proof`，它读取官方 API 并把本次随机标记、boot ID、主机公钥和已有可信 SSH 连接核对，生成一小时内有效、绑定目标的能力记录。它不要求你编造一个官方文档审核标记。系统模板从实际 API 返回的列表选择，具体读取字段和状态见 [提供商证明说明](provider-api.md)。若已有 `encrypted_backup_sha256`，重装前还会流式验证整份加密备份的摘要。

```sh
python3 scripts/vps.py --state private/target.json provider-proof
python3 scripts/vps.py --state private/target.json reinstall --os-template __OFFICIAL_OS_TEMPLATE__ --confirm-target __SSH_ALIAS__:__EXPECTED_IP__:__VEID__
```

如果服务器上的旧数据你确定不要了（例如上一轮的测试部署），可以在 `reinstall` 后面加 `--discard-existing-data`。加了它，脚本就不再要求加密备份和恢复记录，但会在目标状态里写入 `backup_waived`，记下你放弃了旧数据。IP 证书不在放弃范围内：重装前会存到本机，重装后还有效就直接复用，避免撞上 Let's Encrypt 每周的签发上限，详见 [重装系统时证书怎么处理](tls.md#重装系统时证书怎么处理)。其他核对一项不少：提供商证明、目标确认、旧 boot ID 都照常检查。这个开关只用在你真的愿意丢掉整台服务器数据的时候；`legacy_backup.py` 目前只能备份旧版 3x-ui 实例，不能备份本项目的 S-UI 部署。

上面的确认参数不含密码，但仍应只在本机终端使用。重装前通过提供商 API 重新核对实例标识、公网 IP 与 SSH 别名映射；不一致立即停止。重装会中断代理、面板和 CLIProxyAPI，清除系统数据。

重装请求发出不代表新系统已经能登录。等提供商显示运行后，再执行 `provider-proof`，通过官方 HTTPS API 获取本轮新 boot ID、公钥和端口，然后执行 `bootstrap`。API 证明仅十五分钟有效，绑定目标与本轮重装，不能复用旧系统的资料：

```sh
python3 scripts/vps.py --state private/target.json provider-proof
python3 scripts/vps.py --state private/target.json bootstrap
```

API 暂时不可用时，可从提供商可信控制台读取新主机资料。脚本不会相信未经核验的 `ssh-keyscan` 或盲目接受新指纹。手工方式在权限 600 的 `private/bootstrap-proof.json` 保存：

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

`reinstall_at` 要填本轮目标状态文件中的原始数字，不能填上面的字符串。提供商控制台内运行 `cat /proc/sys/kernel/random/boot_id`、`ss -lntp` 和 `cat /etc/ssh/ssh_host_ed25519_key.pub` 可以读取这些资料；只取公钥，不取私钥。确认目标状态中的 `bootstrap_proof_file` 指向这份文件，然后运行：

```sh
python3 scripts/vps.py --state private/target.json bootstrap
```

脚本把可信主机公钥写到本项目私有 `known_hosts`，用实际端口发起独立严格校验的 SSH 连接，并比较新 boot ID。如果提供商已恢复密钥，直接运行 `bootstrap`；如果只给了初始密码，将它放在受限文件后运行 `bootstrap --password-file private/initial-password`，或在本机终端使用 `bootstrap --ask-password`。它会在可信主机证明核验后安装公钥，并用独立新密钥连接确认，再移除密码文件。全局 SSH 别名和其他主机的 known_hosts 不会修改。原始重装响应可能含一次性密码，只保存到 `private/reinstall-response.json`，不会输出。

提供商读取能力已有本轮官方 API 响应与可信旧 SSH 对照记录；停止、重装、写入公钥库和新系统引导在各自实际执行前仍为待测试。能力记录会分别保存这些观察结果；不能把读取成功或本机模拟测试当作完整重装通过。

每轮完整“从零”验收都要真正重装操作系统；删除容器、清数据库、恢复旧快照不能冒充全新系统部署。普通阶段失败先查原因、修仓库并重跑；最终含全部修复的版本仍需再做一次全新 OS 部署。仅对已授权的测试实例执行，不能扩展到其他服务器。

## 卡住了就记下来

记录所在阶段、可公开的错误摘要、根因与仓库修复。实际地址、凭据和原始日志仅放私有记录。需要用户完成提供商登录或其他交互时，把那一步写成待完成；其他能独立完成的检查继续做。

## 每轮结果怎么记

| 项目 | 记录内容 |
| --- | --- |
| 日期、仓库提交、测试轮次 | 实际值 |
| 提供商重装、系统镜像、架构 | 实际执行与接入结果；不公开完整目标标识 |
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

未经测试的项目保留“未测试”，注明缺少的设备或动作。公开结果只发去除秘密的摘要，不上传账号 HTML。
