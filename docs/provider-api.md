# 用提供商 API 核验重装前后的主机

KiwiVM 的公开官网说明 API 文档在登录后的控制面板中。公开页面没有完整端点契约，不能把第三方副本当成当前官方文档。这里把**实际观察到的 API 行为**和**尚未执行的操作**分开记录。

来源：[官方 API 介绍](https://bandwagonhost.com/dubai-vps.php)、[官方 API 服务](https://api.64clouds.com/)。请求使用 `https://api.64clouds.com/v1/`，凭据通过 curl 标准输入配置传递，不进入进程参数或聊天。提供商实例标识与 API Key 只存在私有文件中。

## 已观察到的读取能力

2026-11-17，在获授权测试实例上，官方 `basicShell/exec` 对缺少 `command` 的请求返回 `error=255` 与 `No command supplied`；提供只读命令时返回 `error=0`，`message` 为包含命令输出的字符串。读取的 boot ID 与 Ed25519 主机公钥和已有可信 SSH 连接取得的值一致。`getLiveServiceInfo` 返回 `ve_status=running` 及实际 `ssh_port`。

这些是该实例本次的实际响应，不代表所有虚拟化环境或所有系统模板都有相同能力。尤其不能因为读取成功，就提前声称停止、重装或新系统恢复接入通过。

## 重装之前先留下可信基准

从本机运行：

```sh
python3 scripts/vps.py --state private/target.json provider-proof
```

入口先核对 API 凭据中的 VEID 与目标一致，再检查 `getServiceInfo` 中的公网 IP 和 KVM 类型，检查 `getLiveServiceInfo` 中的 IP、运行状态和 SSH 端口，读取可安装系统列表和提供商 SSH 公钥库。

随后，它为本次调用生成随机标记，通过官方 `basicShell/exec` 只读获取标记、boot ID 与主机公钥。返回内容必须恰好匹配本次标记和预期格式，再与已有严格校验的 SSH 连接取得的值比较。旧系统上无法建立可信 SSH 基准时，这一步会停止，不能自行接受一个未知指纹。

成功后，它把以下资料写入权限 600 的私有文件：

- `provider-proof.json`：API 来源、目标指纹、采集时间、随机标记摘要、boot ID、实际端口和公钥。
- 目标状态中的 `provider_capabilities`：哪些读取端点及字段实际验证过、可信 SSH 基准，以及停止、重装、写入公钥库的独立状态。
- `available-os.json`：提供商本次返回的系统列表。

读取证明只在一小时内作为重装前提；目标不符、来源不符、过期、随机标记不匹配或主机资料不同都会停止。系统模板必须从实际返回的列表选择。加密备份仍需确认可恢复；若保存了备份 SHA256，重装前会流式核对完整文件，文件变化就停止。

## 重装之后再获取新的证明

重装仍是单独、显式确认目标的命令，见 [从零部署步骤](pilot.md)。停止、重装和写入公钥库在首次执行前均记录为 `pending-live-test`；只在对应请求实际成功后记录观察结果。重装请求被接受也只表示提供商接受了任务，还不能算新系统或节点已经可用。

获授权的测试实例已完成两轮实际重装。第一次验证了 `updateSshKeys` 写入该实例的公钥、`stop` 进入停止状态以及 `reinstallOS` 接受镜像参数。两轮都通过提供商读回新系统并严格校验 SSH。第二轮重装期间 API 返回错误码 `788888`，表示实例暂时锁定，待提供商完成工作后重新执行读取证明即可。不要在锁定时重复发送重装请求。

等提供商显示新系统运行后，再运行一次：

```sh
python3 scripts/vps.py --state private/target.json provider-proof
python3 scripts/vps.py --state private/target.json bootstrap
```

第二次证明通过可信的提供商 HTTPS API 取得新 boot ID 和新主机公钥，不先建立未经核验的 SSH 连接。它必须绑定同一目标和本轮重装时间，boot ID 必须与旧系统不同。`bootstrap` 只接受十五分钟内的 API 主机证明，再使用该公钥和实际端口独立核验 SSH。公钥登录尚未恢复时，可使用受限密码文件或本机安全输入，见 [首次接入与密码引导](pilot.md)。

若提供商 API 暂时不可用，可以按 [手工证明格式](pilot.md) 从可信控制台读取资料；不能退回盲目信任 `ssh-keyscan`、关闭主机验证或复用旧公钥冒充新系统。

仓库入口使用本轮私有 `known_hosts`。如果你用平时的 SSH 别名直连时仍看到旧公钥警告，先用仓库入口确认本轮主机证明和密钥连接，再仅替换该目标在日常 SSH 所用文件中的旧记录。新的记录来自本轮验证过的私有主机文件，保留其他服务器记录。
