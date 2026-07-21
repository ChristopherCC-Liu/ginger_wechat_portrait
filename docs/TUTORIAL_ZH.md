# Ginger Personal Agent v2 详细使用教程（macOS）

本文对应固定预发布版本 `v0.2.0-rc.2`，目标是让一台新的 Mac 从安装开始，
完成微信数据库接入、Shadow 运行、草稿审核、量化蒸馏、定时任务和日常运维。

本教程的验收边界是 **Shadow + 可选的 typing-only 验证**。默认配置不会点击发送，
也不会在安装时授权真实发送。首次真实点击必须脱离本教程单独确认。

## 1. 先理解运行边界

运行链路如下：

```text
launchd
  -> 只读发现微信数据库新增消息（不调用模型）
  -> 稳定游标、重叠扫描和事件去重
  -> 本地规则判断是否可能需要回复
  -> 当前联系人画像 + 个人蒸馏模型
  -> 结构化 ReplyDecision
  -> 风险、承诺、置信度、费用和频率闸门
  -> 加密草稿
  -> 人工审核或受控 UI 验证
```

四种模式的区别：

| 模式 | 模型 | 草稿 | 微信 UI |
|---|---|---|---|
| `observe` | 不调用 | 不生成 | 不操作 |
| `shadow`（默认） | 规则筛选后按需调用 | 生成加密草稿 | 不操作 |
| `approve` | 按需调用 | 人工批准后可 typing-only | 只验证，不点击发送 |
| `autopilot` | 按需调用 | 只处理极低风险候选 | 仍需全部闸门和一次性 canary |

永久转人工的内容包括：金钱、合同、医疗或法律、验证码、账号凭证、隐私披露、
争执和重大关系决定。情绪周期只能改变语气、长度和延迟，不能提高权限。

## 2. 环境要求

准备以下环境：

- macOS，已登录当前用户；
- 微信 macOS 4.x，至少登录一次并产生本地数据库；
- Python 3.10 或更新版本；
- Xcode Command Line Tools；
- Homebrew（仅在需要安装 `sqlcipher` 时使用）；
- 约 500 MB 可用空间，数据库副本另计。

检查命令：

```bash
sw_vers
python3 --version
xcode-select -p
```

若没有 Command Line Tools：

```bash
xcode-select --install
```

需要解密数据库或直接读取 SQLCipher 时安装：

```bash
brew install sqlcipher
```

### macOS 权限

在 **系统设置 > 隐私与安全性** 中处理权限：

1. 给执行数据库工具的 Terminal（或所用终端）授予“完全磁盘访问权限”。
2. 密钥提取时，按系统提示允许 Terminal 使用“开发者工具”。
3. 仅当进入 `approve` 的 typing-only 验证时，给对应终端/代理授予“辅助功能”。

Shadow 模式不要求辅助功能权限。项目不会自动关闭 SIP、重签名微信或使用 root。

## 3. 从固定 Release 安装

在一个新的临时目录执行：

```bash
mkdir -p "$HOME/Downloads/ginger-agent-install"
cd "$HOME/Downloads/ginger-agent-install"

VERSION=v0.2.0-rc.2
REPO=ChristopherCC-Liu/ginger_wechat_portrait

curl -fsSLO \
  "https://github.com/${REPO}/releases/download/${VERSION}/ginger-personal-agent-${VERSION}.tar.gz"
curl -fsSLO \
  "https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"

grep "  ginger-personal-agent-${VERSION}.tar.gz$" SHA256SUMS \
  | shasum -a 256 -c -

tar -xzf "ginger-personal-agent-${VERSION}.tar.gz"
cd "ginger-personal-agent-${VERSION}"
./install-macos.sh
```

校验和成功时应看到：

```text
ginger-personal-agent-v0.2.0-rc.2.tar.gz: OK
```

安装器会创建私有虚拟环境和配置，但不会加载定时服务。设置后续命令变量：

```bash
AGENT_HOME="$HOME/Library/Application Support/GingerAgent"
AGENT="$AGENT_HOME/bin/ginger-agent"
CONFIG="$AGENT_HOME/config.toml"

"$AGENT" --help
ls -l "$CONFIG"
```

`config.toml` 的权限必须是 `-rw-------`，否则执行：

```bash
chmod 600 "$CONFIG"
```

## 4. 找到微信数据库目录

先运行只读检查工具：

```bash
DB_DOCTOR="$AGENT_HOME/bin/ginger-wechat-db-doctor"
"$DB_DOCTOR"
```

工具会自动检查稳定版和 Beta 版常见位置，包括：

```text
~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/*/db_storage
~/Library/Containers/com.tencent.xinWeChatBeta/Data/Documents/xwechat_files/*/db_storage
```

存在多个账号时，自动发现会选择最近活跃的目录。生产配置中应写入明确路径，避免换号后
无意读到另一个账号。可用下面的方式再次核验指定目录：

```bash
WECHAT_DB="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/账号目录/db_storage"
"$DB_DOCTOR" --db-dir "$WECHAT_DB"
```

不要把数据库路径、账号目录名或数据库文件提交到 Git。

## 5. 提取数据库密钥

本步骤只在你自己的 Mac、自己的微信账号上执行。保持微信正在运行，并先打开若干最近
会话，使对应数据库处于打开状态。

```bash
KEY_TOOL="$AGENT_HOME/bin/ginger-wechat-find-keys"
PRIVATE_KEYS="$HOME/Library/Application Support/GingerAgent/private/wechat_keys.json"
mkdir -p "$(dirname "$PRIVATE_KEYS")"
chmod 700 "$(dirname "$PRIVATE_KEYS")"
```

如果微信出现多个进程，先列出候选：

```bash
PYTHONPATH="$(lldb -P)" "$KEY_TOOL" \
  --db-dir "$WECHAT_DB" \
  --list-processes
```

输出会显示每个 PID 打开的数据库数量。选择打开当前 `db_storage` 文件最多的 PID：

```bash
WECHAT_PID=12345
PYTHONPATH="$(lldb -P)" "$KEY_TOOL" \
  --db-dir "$WECHAT_DB" \
  --pid "$WECHAT_PID" \
  --output "$PRIVATE_KEYS"
chmod 600 "$PRIVATE_KEYS"
```

成功信号类似：

```text
[*] Saved 26/26 verified salt keys to .../wechat_keys.json
```

部分密钥缺失时，打开微信中相关消息、收藏或联系人页面后重跑。工具会复用已经验证过的
salt/key，不需要从头丢弃结果。

### LLDB 无法导入时

先确认：

```bash
lldb -P
/Library/Developer/CommandLineTools/usr/bin/python3 --version
```

若已安装命令的 Python 与 Apple LLDB 模块不兼容，可直接使用解压后的 Release 源文件，
由 Command Line Tools 的 Python 执行：

```bash
RELEASE_SRC="$HOME/Downloads/ginger-agent-install/ginger-personal-agent-v0.2.0-rc.2"
PYTHONPATH="$(lldb -P):$RELEASE_SRC" \
  /Library/Developer/CommandLineTools/usr/bin/python3 \
  "$RELEASE_SRC/tools/wechat_db/find_keys_macos.py" \
  --db-dir "$WECHAT_DB" \
  --pid "$WECHAT_PID" \
  --output "$PRIVATE_KEYS"
```

若仍提示无法 attach，先检查 Terminal 的开发者工具权限、完全磁盘访问权限和 PID 是否仍
存在。不要为了省事自动关闭 SIP；密钥提取是一次性的人工维护步骤，不应由 launchd 调度。

## 6. 选择数据库读取方式

### 方式 A：解密副本后读取（推荐入门）

优点是排错简单，运行时只使用标准 SQLite。缺点是会生成明文数据库副本，因此目录必须
保持私有，并需要你在微信更新数据库分片后重新解密。

```bash
DECRYPT_TOOL="$AGENT_HOME/bin/ginger-wechat-decrypt"
DECRYPTED_DB="$HOME/Library/Application Support/GingerAgent/private/decrypted-db"

"$DECRYPT_TOOL" \
  --db-dir "$WECHAT_DB" \
  --keys "$PRIVATE_KEYS" \
  --output "$DECRYPTED_DB"

chmod -R go-rwx "$HOME/Library/Application Support/GingerAgent/private"
```

然后编辑 `$CONFIG`：

```toml
[reader]
backend = "plaintext"
db_dir = "~/Library/Application Support/GingerAgent/private/decrypted-db"
sqlcipher_path = "/opt/homebrew/bin/sqlcipher"
keychain_db_key_prefix = "wechat-db-key"
self_id_ref = "wechat-self-id"
overlap_seconds = 300
batch_size = 500
bootstrap_lookback_seconds = 86400
```

注意：明文副本不是持续同步镜像。希望长期低成本自动发现新消息，应使用方式 B，或者在每次
人工更新副本后再运行代理。

### 方式 B：直接读取加密分片（推荐长期运行）

先把密钥导入 macOS Keychain：

```bash
"$AGENT" --config "$CONFIG" import-wechat-keys --keys-file "$PRIVATE_KEYS"
```

成功结果中的 `imported_salts` 应大于 0。该命令不会删除密钥文件；确认导入后，将其离线
归档或安全删除。然后配置：

```toml
[reader]
backend = "sqlcipher"
db_dir = "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/账号目录/db_storage"
sqlcipher_path = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
keychain_db_key_prefix = "wechat-db-key"
self_id_ref = "wechat-self-id"
overlap_seconds = 300
batch_size = 500
bootstrap_lookback_seconds = 86400
```

Intel Mac 的 Homebrew 路径通常是 `/usr/local/opt/sqlcipher/bin/sqlcipher`，用以下命令确认：

```bash
command -v sqlcipher
```

新分片出现新 salt 后，先重新提取并执行一次 `import-wechat-keys`。运行时会每轮重新发现
`message/message_N.db` 和消息表，并用全局首轮截止时间初始化新分片，不会回灌全部历史。

## 7. 初始化 Keychain 密钥

状态加密密钥和匿名化身份密钥由本机随机生成：

```bash
"$AGENT" --config "$CONFIG" secret-set \
  --name state-key --generate-bytes 32
"$AGENT" --config "$CONFIG" secret-set \
  --name identity-key --generate-bytes 32
```

`wechat-self-id` 用于安全区分发入和发出消息，尤其是发送后数据库回读。不要把它写入 TOML
或命令行参数，使用隐藏输入提示：

```bash
"$AGENT" --config "$CONFIG" secret-set --name wechat-self-id
```

终端会显示 `Secret value for wechat-self-id:`，输入或粘贴本机微信内部 ID 后回车。输出只
报告字节数，不显示值。

所有 Keychain 项使用服务名 `com.christophercc.ginger-agent`。不要复用聊天记录中曾经
暴露过的 API key；请在模型提供商控制台创建新的独立密钥。

## 8. 配置模型

数据库轮询、分片发现、游标和本地规则均不调用模型。只有本地规则判断“可能需要回复”时，
运行时才创建模型请求。

### 8.1 本地 OpenAI-compatible 模型

这是最低外部数据暴露的配置。先确保本地服务已经监听，然后配置：

```toml
[model]
provider = "local"
model = "你的本地模型名"
base_url = "http://127.0.0.1:11434/v1"
api_key_ref = ""
timeout_seconds = 30
max_response_bytes = 1000000
max_request_bytes = 524288
max_output_tokens = 900
context_messages = 12
```

本地地址只允许 loopback 主机。运行时会调用
`http://127.0.0.1:11434/v1/chat/completions`，不接受远程 HTTP 地址。

### 8.2 OpenAI

先创建新的 API key，并存入 Keychain：

```bash
"$AGENT" --config "$CONFIG" secret-set --name openai-api-key
```

配置示例：

```toml
[model]
provider = "openai"
model = "填写当前支持 JSON Schema 的模型快照名"
base_url = "https://api.openai.com/v1"
api_key_ref = "openai-api-key"
timeout_seconds = 30
max_response_bytes = 1000000
max_request_bytes = 524288
max_output_tokens = 900
context_messages = 12
```

### 8.3 GLM

```bash
"$AGENT" --config "$CONFIG" secret-set --name glm-api-key
```

```toml
[model]
provider = "glm"
model = "填写当前可用的 GLM 模型名"
base_url = "https://open.bigmodel.cn/api/paas/v4"
api_key_ref = "glm-api-key"
timeout_seconds = 30
max_response_bytes = 1000000
max_request_bytes = 524288
max_output_tokens = 900
context_messages = 12
```

远程提供商必须使用 HTTPS。模型必须返回单一、严格的 `ReplyDecision` JSON；响应格式错误、
重定向、工具调用、重复键或超出字节上限都会 fail closed，不会生成可发送内容。

## 9. 配置费用和调用上限

先采用保守值：

```toml
[cost]
daily_usd_limit = 1.00
daily_call_limit = 20
per_contact_hourly_limit = 3

[cost.model_prices_per_million_tokens]

# 使用付费模型时，取消下面三行注释并填写当前官方价格：
# [cost.model_prices_per_million_tokens."与你在 model 中完全相同的模型名"]
# input = 填写每百万输入 token 的美元价格
# output = 填写每百万输出 token 的美元价格
```

付费模型的 `input` 和 `output` 必须替换为提供商当前官方的每百万 token 美元价格。没有
匹配价格时，付费适配器不会继续；不要用 `0.00` 假装免费。本地模型可以不写价格，费用按
0 美元记录，但仍占每日调用次数。

运行前会按最大输出 token 预留调用和费用。请求失败或超时仍保留最大预留，因为客户端无法
证明服务端没有计费。查看日报：

```bash
"$AGENT" --config "$CONFIG" cost-report
```

重点字段：`calls_remaining`、`cost_remaining_usd`、`reserved_calls` 和
`reserved_cost_usd`。

## 10. 第一次 Doctor 和首轮基线

确保配置保持安全默认值：

```toml
mode = "shadow"
allowlist = []

[sender]
backend = "accessibility"
fallback_backend = ""
computer_use_helper = ""
typing_only = true
real_send_enabled = false
canary_ref = "real-send-canary"
ui_timeout_seconds = 12
```

运行只读检查：

```bash
chmod 600 "$CONFIG"
"$AGENT" --config "$CONFIG" doctor
echo "doctor exit=$?"
```

`ready: true` 的必要条件包括 macOS、Python、0600 配置、微信应用、可读数据库目录、
kill switch 未启用，以及 SQLCipher 模式下可用的可执行文件。Shadow 下辅助功能只是非必需
提示。Doctor 明确报告：

```json
{
  "network_calls": 0,
  "model_calls": 0,
  "send_actions": 0
}
```

首次运行：

```bash
"$AGENT" --config "$CONFIG" run-once
```

第一轮是基线：默认只导入最近 24 小时，标记为已观察，持久化全局 bootstrap cutoff；不会
调用模型，也不会生成发送动作。这是预期行为，不是“没有工作”。随后收到一条新的普通消息后
再次执行：

```bash
"$AGENT" --config "$CONFIG" run-once
```

输出中的常用字段：

- `discovered_databases`：本轮发现的数据库分片数；
- `scanned_rows`：重叠窗口内实际扫描的消息行数；
- `inserted_events`：去重后新写入账本的事件数；
- `processed_events`：进入规则/决策流程的事件；
- `rule_filtered`：被本地规则直接过滤；
- `model_calls`：实际文本模型调用数；
- `drafts`：新建草稿数；
- `send_attempts`、`sends_confirmed`：Shadow 下都应为 0。

同一轮重复执行不应重复创建事件或草稿。游标按 `(create_time, local_id)` 保存，并通过 HMAC
事件 ID 和事务去重抵抗 WAL 延迟及进程重启。

## 11. 查看草稿和结构化判断

默认只看元数据：

```bash
"$AGENT" --config "$CONFIG" drafts
```

需要在本机终端审阅正文时显式请求：

```bash
"$AGENT" --config "$CONFIG" drafts --include-body
```

不要把包含正文的终端输出粘贴到 GitHub issue、ChatGPT Pro 或公共日志。每个决定先产生以下
结构，再渲染语言风格：

- `intent`：消息意图；
- `stance`：拟采取的立场；
- `facts`：只允许有上下文依据的事实；
- `commitments`：承诺列表，非空时禁止自动发送；
- `risk`：风险分类；
- `confidence`：置信度；
- `reply_required`：是否需要回复。

阈值规则：低于 `0.70` 不回复；`0.70` 到低于 `0.92` 只形成待审核草稿；至少 `0.92`
也只是自动化候选，仍需通过白名单、上下文、风险、承诺、费用、频率和发送闸门。

## 12. 使用 approve 做 typing-only 验证

先把配置中的模式改为：

```toml
mode = "approve"
```

保持：

```toml
typing_only = true
real_send_enabled = false
```

Doctor 此时会把辅助功能视为必需项。选取草稿 ID 后创建短期批准：

```bash
DRAFT_ID="从 drafts 输出复制的 draft_id"
"$AGENT" --config "$CONFIG" approve-draft \
  --draft-id "$DRAFT_ID" \
  --expires-seconds 600
```

批准只允许一次 typing-only 验证，不是发送授权。验证命令：

```bash
"$AGENT" --config "$CONFIG" typing-validate --draft-id "$DRAFT_ID"
```

系统会核验唯一联系人、会话名称和编辑框完整正文，但不会按 Return。一次批准消费后不能复用。
验证结束后，手动清空微信输入框，并把模式改回 `shadow`。

## 13. 建立六类量化蒸馏模型

六个不可变领域：

| domain | 作用域 | 自动更新边界 |
|---|---|---|
| `stable_facts` | 全局 | 不自动覆盖 |
| `values_boundaries` | 全局 | 不自动覆盖 |
| `relationship` | 单一联系人 | 只更新非边界风格/延迟 |
| `decision_preferences` | 全局 | 可由纠正样本提议 |
| `language_style` | 全局 | 可由纠正样本提议 |
| `emotion_cycle` | 全局 | 仅非临床情绪代理指标 |

所有版本不可变，保存父版本、证据 ID、置信度、hash 和保护字段。联系人关系必须使用
`contact_...` 匿名键，不能拿备注名、wxid 或手机号代替。

### 13.1 写入稳定自我事实

在 Git 仓库外创建私有文件 `stable-facts.json`：

```json
{
  "timezone": "Asia/Shanghai",
  "preferred_language": "zh-CN",
  "facts": [
    "示例事实：工作日白天通常不立即回复非紧急消息"
  ]
}
```

```bash
chmod 600 stable-facts.json
"$AGENT" --config "$CONFIG" distill-put \
  --domain stable_facts \
  --payload-file stable-facts.json \
  --evidence-id user-confirmed-setup-001 \
  --confidence 1 \
  --protected-field facts \
  --user-confirmed \
  --activate
```

### 13.2 写入价值和边界

`values-boundaries.json` 示例：

```json
{
  "values": ["不替我做财务或重大关系决定"],
  "boundaries": ["不透露验证码、凭证或第三方隐私"]
}
```

```bash
chmod 600 values-boundaries.json
"$AGENT" --config "$CONFIG" distill-put \
  --domain values_boundaries \
  --payload-file values-boundaries.json \
  --confidence 1 \
  --protected-field values \
  --protected-field boundaries \
  --user-confirmed \
  --activate
```

### 13.3 写入全局语言风格

`language-style.json` 示例：

```json
{
  "sentence_ending": "自然、简短，不使用客服腔"
}
```

```bash
chmod 600 language-style.json
"$AGENT" --config "$CONFIG" distill-put \
  --domain language_style \
  --payload-file language-style.json \
  --confidence 0.95 \
  --user-confirmed \
  --activate
```

### 13.4 为每个联系人建立独立关系画像

先从本机 `drafts --include-body` 或蒸馏输出中取得 `contact_...` 匿名键。为一个联系人创建
`relationship.json`：

```json
{
  "preferred_address": "示例称呼",
  "preferred_length": "short",
  "temperature": "warm",
  "initiative": "balanced",
  "emoji_policy": "rare",
  "preferred_emoji": ["🙂"],
  "reply_delay_seconds": 300,
  "boundaries": ["示例禁区：不代替本人确认具体承诺"]
}
```

```bash
CONTACT_KEY="contact_填入本机匿名键"
chmod 600 relationship.json
"$AGENT" --config "$CONFIG" distill-put \
  --domain relationship \
  --contact-key "$CONTACT_KEY" \
  --payload-file relationship.json \
  --confidence 0.95 \
  --protected-field boundaries \
  --user-confirmed \
  --activate
```

每个联系人必须单独执行，父版本、激活版本和回滚范围都按 `contact_key` 隔离。运行时只把
当前联系人的 relationship 放进上下文，不读取其他联系人画像。

### 13.5 查看版本和回滚

```bash
"$AGENT" --config "$CONFIG" distill-list \
  --domain relationship \
  --contact-key "$CONTACT_KEY"
```

默认不输出 payload。仅在本机审计内容时：

```bash
"$AGENT" --config "$CONFIG" distill-list \
  --domain relationship \
  --contact-key "$CONTACT_KEY" \
  --include-payload
```

回滚只能激活同一作用域当前版本的祖先：

```bash
VERSION_ID="要恢复的祖先 version_id"
"$AGENT" --config "$CONFIG" distill-rollback \
  --domain relationship \
  --contact-key "$CONTACT_KEY" \
  --version-id "$VERSION_ID"
```

## 14. 记录纠正并形成学习闭环

准备两个 0600 文本文件：

- `user-edit.txt`：你在模型草稿上的修改；
- `final-reply.txt`：你最终实际采用的回复。

```bash
chmod 600 user-edit.txt final-reply.txt
"$AGENT" --config "$CONFIG" record-correction \
  --draft-id "$DRAFT_ID" \
  --user-edit-file user-edit.txt \
  --final-reply-file final-reply.txt
```

这会在加密账本中记录草稿、修改和最终回复差异，并生成语言、决策偏好及当前联系人非边界
风格的候选。达到默认 3 个样本且满足刷新间隔后，本地刷新会生成新版本：

```bash
"$AGENT" --config "$CONFIG" distill-refresh
```

人工检查时可强制运行一次：

```bash
"$AGENT" --config "$CONFIG" distill-refresh --force
```

刷新不调用文本模型，也不操作 UI。它不会自动覆盖稳定事实、价值、隐私边界、关系边界、
`display_name` 或 `ui_search_token`。

## 15. 安装 launchd 定时任务

先确保手工 `doctor` 和两次 `run-once` 均正常，然后安装用户级 LaunchAgent：

```bash
"$AGENT" --config "$CONFIG" install-service
"$AGENT" --config "$CONFIG" status
```

plist 路径：

```text
~/Library/LaunchAgents/com.christophercc.ginger-agent.plist
```

日志路径：

```text
~/Library/Application Support/GingerAgent/logs/agent.stdout.log
~/Library/Application Support/GingerAgent/logs/agent.stderr.log
```

查看最近日志：

```bash
tail -n 100 "$AGENT_HOME/logs/agent.stdout.log"
tail -n 100 "$AGENT_HOME/logs/agent.stderr.log"
```

日志应只用于操作元数据。若发现正文或标识符，立即启用 kill switch 并停止发布日志。

## 16. 日常运维命令

```bash
# 状态
"$AGENT" --config "$CONFIG" status

# 暂停，不丢状态
"$AGENT" --config "$CONFIG" pause

# 恢复普通暂停
"$AGENT" --config "$CONFIG" resume

# 查看当天模型预算
"$AGENT" --config "$CONFIG" cost-report

# 紧急停止；同时阻止普通 resume
"$AGENT" --config "$CONFIG" kill-switch --enable

# 人工检查后清除紧急停止，再恢复
"$AGENT" --config "$CONFIG" kill-switch --clear
"$AGENT" --config "$CONFIG" resume

# 卸载定时任务，保留配置、Keychain 和账本
"$AGENT" --config "$CONFIG" uninstall-service
```

修改配置前先 `pause`，修改后运行 `doctor` 和一次 `run-once`，确认无误再 `resume`。

## 17. 固定版本升级和回滚

已安装环境使用校验和安装器，不让 launchd 执行 `git pull main`：

```bash
"$AGENT_HOME/bin/install-release" v0.2.0-rc.2
"$AGENT" --config "$CONFIG" doctor
"$AGENT" --config "$CONFIG" install-service
```

升级到新版本时，把标签替换为你已在 GitHub Releases 中核验过的固定标签。安装器校验
`SHA256SUMS`、归档根目录、路径穿越、链接和特殊文件，然后原子切换虚拟环境。配置、Keychain、
账本、暂停/kill switch 和日志不会被覆盖。

代码回滚使用同一命令指定上一个固定标签；蒸馏回滚则使用 `distill-rollback`，两者互不替代。

## 18. 常见故障排查

| 现象 | 直接原因 | 处理 |
|---|---|---|
| `config permissions must be 0600` | 配置可被其他用户读取 | `chmod 600 "$CONFIG"` |
| Doctor 找不到数据库 | 路径错误或缺完全磁盘访问 | 用 `ginger-wechat-db-doctor --db-dir ...` 核验明确路径并重开 Terminal |
| `more than one process named WeChat` | 微信有多个主进程 | 先 `--list-processes`，再传数据库打开数最多的 `--pid` |
| LLDB `Could not attach` | PID 失效、开发者工具权限或系统保护阻止 | 重查 PID，授权 Terminal，保持微信运行；不要自动关闭 SIP |
| 只找到部分 keys | 对应数据库未在微信内存打开 | 打开相关会话/页面后重复提取，复用原 key 文件 |
| SQLCipher 模式缺 key | 新分片 salt 未导入 Keychain | 重提取 keys，再执行 `import-wechat-keys` |
| `sqlcipher ... not found` | 配置路径不匹配架构 | `command -v sqlcipher`，把绝对路径写回 TOML |
| 首次 `run-once` 没草稿 | 首轮只建立 24 小时基线 | 收到一条新消息后再运行；不要删除账本重来 |
| 第二轮仍无模型调用 | 消息被本地规则过滤、方向 unknown 或无需回复 | 看 `rule_filtered`、warnings 和数据库 self ID 配置 |
| 付费模型拒绝启动 | 模型名没有精确定价项 | 用相同模型名添加当前官方 input/output 单价 |
| 本地模型连接失败 | endpoint 未启动或不是 loopback OpenAI-compatible API | 检查本地 `/v1/chat/completions`，保持 `127.0.0.1`/`localhost` |
| `resume` 被拒绝 | kill switch 仍启用 | 先调查原因，再 `kill-switch --clear` 和 `resume` |
| approve 下 Doctor 不 ready | 未授予辅助功能 | 系统设置授权对应终端/代理，退出并重开进程 |
| 重复消息没有重复草稿 | 去重和稳定游标正常工作 | 无需处理，这是预期行为 |

## 19. 隐私和 Git 发布检查

永远不要提交以下内容：

- `outputs/` 报告、聊天导出和聊天正文；
- `wechat_keys.json`、API key、wxid、联系人映射；
- 加密或解密后的 `.db`、`-wal`、`-shm`；
- `~/Library/Application Support/GingerAgent/` 中的状态、日志和配置；
- UI identity enrollment、纠正文本、模型响应；
- 任何真实联系人名、手机号、邮箱或账号目录。

发布前不要使用 `git add .`。应逐个添加源文件，并运行：

```bash
python3 scripts/check-release-tree.py --candidate-tree
git status --short
git diff --cached --stat
git diff --cached
```

ChatGPT Pro 只用于公开仓库、产品体验、脱敏风险题库和回复盲评。不要上传聊天原文、数据库、
wxid、密钥或本地运行状态；网页 ChatGPT 也不是生产模型后端。

## 20. 验收清单

完成安装后逐项确认：

- [ ] Release 压缩包通过 `SHA256SUMS` 校验；
- [ ] `$CONFIG` 权限是 0600，且没有裸 API key；
- [ ] `state-key`、`identity-key` 和 `wechat-self-id` 存在于 Keychain；
- [ ] Doctor 返回 `ready: true`；
- [ ] 首轮基线的 `model_calls`、`send_attempts` 和 `sends_confirmed` 都为 0；
- [ ] 新消息增量轮询不会重复入账；
- [ ] `cost-report` 显示正确的每日上限；
- [ ] 默认模式仍是 `shadow`；
- [ ] `typing_only = true`，`real_send_enabled = false`；
- [ ] LaunchAgent 的状态和日志正常；
- [ ] 每个联系人使用独立 `contact_...` 关系作用域；
- [ ] 已演练 pause、resume 和 kill switch；
- [ ] 未执行真实微信发送 canary。

## 21. 真实发送边界（只读说明）

代码包含受控 autopilot，但本教程不启用它。即使模式改为 autopilot，也必须同时满足：联系人
匿名白名单、用户确认的 UI identity、低风险、无承诺、上下文充分、事实有依据、置信度至少
0.92、未超费用和频率、草稿已到期且仍对应最新入站消息、Accessibility 精确核验联系人与
全文，并存在绑定该草稿和正文 hash 的短时一次性 canary。点击后还必须在数据库中读到同一
联系人、严格全文相等、时间晚于点击前水位的 outbound 消息，才算确认。

Computer Use 只能作为 typing-only 回退，不能点击发送。任何阻断、失败、不确定或未回读确认
的尝试都不会自动重试。首次真实点击必须另开一次明确确认流程，不能把“安装成功”“approve”
或“typing-only 验证成功”解释成发送授权。

进一步的安全合同和实现细节见 [PERSONAL_CHAT_AGENT.md](PERSONAL_CHAT_AGENT.md)，精简安装
说明见 [INSTALL_MACOS.md](INSTALL_MACOS.md)，威胁模型见 [SECURITY.md](SECURITY.md)。
