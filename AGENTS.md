# 给 AI 助手的约定

## 这个仓库是做什么的

这是一份教程：教个人用户买了 VPS 以后，自己部署代理，并检查有没有漏出真实 IP。服务器用 S-UI + sing-box 管理三种协议：VLESS Reality、VLESS TLS 和 AnyTLS。

部署前先读 README、docs/deployment.md、docs/tls.md 和 docs/verification.md。用户明确要哪种方式，就按用户的来；没说的话默认用 S-UI，不另外单独跑 sing-box。

## 部署时怎么做

1. 先只看不改：确认 SSH 连的是哪台机器，查清发行版、架构、已有的 Docker 服务、正在监听的端口、防火墙和公网 IP。确认目标没错再动手。
2. 端口和证书按服务器现有的情况来选。别直接覆盖其他项目的 Compose、Nginx、SSH 配置或防火墙规则。
3. 镜像只用 versions.json 里核对过的版本。真实凭据在部署时单独生成，写进权限受限的 private/ 或服务器的状态目录；不要出现在聊天、日志、Git 或 Issue 里。用户按 README 在聊天里给出的 IP、端口和 VEID 写进 private/target.json。root 密码和 API Key 用 `ask-secrets` 弹窗让用户自己输入，别让用户发在聊天里；弹不出来时，告诉用户要写进哪个文件。不要读出、打印或复述 private/ 里的密码文件、provider.json 和账号页。
4. 面板模式下，配置以 S-UI 为准。examples/ 里是原生 sing-box 格式，不能导入 S-UI。没核实过，别直接写数据库，也别猜 API。
5. 面板和订阅后端只在服务器本机监听，公网通过 Nginx 的 TCP 9443 提供可信 HTTPS。面板用单独生成的随机管理员账号。节点默认开 TCP 443、2443、8443，默认不开 UDP 443。用 IP 证书时证书验证照样开着，不能为了绕过报错就设 insecure=true。
6. 更新前先备份，记下旧镜像的摘要。重启会断开连接，实际部署时要跟用户说清楚。别默认跟 latest，也别让 sing-box 无人值守地自动升级。
7. 日常操作都用 `python3 scripts/vps.py --state private/target.json` 的 preflight、deploy、verify、export。
   按 README 部署新买的服务器时，顺序是：写好 target.json 和 `~/.ssh/config` 里的别名 → 本机没有 `sshpass` 就先装上（Mac 用 Homebrew）→ `ask-secrets` → `provider-proof`（第一次接入时只从服务商 API 读主机公钥）→ `init` → `preflight`。preflight 显示系统不是 Ubuntu 22.04/24.04/26.04，并且服务器是空的（没有 Docker 容器、除 SSH 外没有在监听的业务端口、/opt 和 /srv 里没有别人的东西），就直接用 API 换成 ubuntu-24.04-x86_64：`provider-proof` → `reinstall --discard-existing-data` → 等服务器运行 → `provider-proof` → `bootstrap` → `preflight`，然后继续部署。这一步不用问用户，完成后用一句话告诉他换过系统。看到任何已有业务，或者没有 API Key，就停下来问用户。
   其他情况下，用户明确要求重装时，才用单独的重装命令，先核对服务商那边的实例和 SSH、IP 对得上，并且要有用户对这台机器的明确授权。最后从零验证时必须真的重装系统，删容器不算。
8. CLIProxyAPI 的后端只在本机监听，通过 TCP 9444 的 HTTPS 提供 /management.html 管理页和 /v1 API，不预先填任何上游账号。账号页 HTML 只写到本机私有目录，不能放到公网上，也不能用第三方的二维码服务。
9. 跑 tests/ 和检查清单。静态检查、sing-box 配置解析、容器健康、端到端网络测试是不同的层，哪一层真做完了，才能说哪一层通过。

## 改仓库时

- 示例里一律用 `__PLACEHOLDER__` 或文档专用的示例地址，不能出现真实服务器的信息。
- 改了协议配置，客户端示例要跟着改，并用固定版本的 sing-box 检查。
- 改了文档要核对相对链接；改了部署相关的东西要跑 docker compose config。
- 别把现有运维工作区里的 .secrets、订阅、日志、截图或其他项目复制进来。
- 别改用户的全局 Git 身份；新仓库的身份只在本仓库里设置。

## 教程的立场

- 搬瓦工推广链接统一用 https://bandwagonhost.com/aff.php?aff=82641。要直接跳到某个套餐时，可以在后面加 `&pid=套餐编号`（比如 `aff=82641&pid=88`），`aff` 参数不能改。链接旁边要说明这是推广链接。用户没要求的话，不加参考项目或致谢。
- 别把自建节点写成"绝不泄露 IP"或"完全匿名"。TUN、DNS、IPv6、WebRTC 和断线时的表现要分别检查。
- 新 VPS 照 docs/pilot.md 一步步部署。做了教程里没写的操作，要写回教程；没做的项目不能标成通过。
- 客户端防泄露的步骤在 docs/leak-protection.md。公开的实测记录要去掉 IP、凭据等敏感信息。

## 教程怎么写

- 当成在带一个第一次配服务器的人：先说这一步要做什么，再给操作，最后说怎么看结果。
- 直接叫"你"。少用"主路径、核心解析、验收边界、脱敏交付"这类项目汇报的词；必须用术语时，就在原地解释一句。
- 首页先讲读者要准备什么，技术版本、文件清单和自动检查放到后面。
- 问题和提醒写在会遇到它的那一步旁边，别在开头堆一整页注意事项。
- 推广关系直接说。别编造个人使用经历、测速、口碑，或者没做过的实测。
- 测试状态要写准。别为了读起来轻松，就省掉会影响操作的条件。
