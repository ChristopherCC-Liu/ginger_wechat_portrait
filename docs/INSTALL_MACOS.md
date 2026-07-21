# Ginger Personal Agent v2: macOS installation and operations

需要从新 Mac 安装、微信数据库密钥提取、模型配置、Shadow 首跑、蒸馏回滚和故障排查的
完整步骤，请阅读 [中文详细教程](TUTORIAL_ZH.md)。

## Safety state after installation

The installed default is `shadow`. Database polling is local and makes no model
request. The sender defaults to `typing_only = true` and
`real_send_enabled = false`. Installing or loading the LaunchAgent does not authorize
a real WeChat send.

Runtime files live under:

```text
~/Library/Application Support/GingerAgent/
├── bin/
├── config.toml          # 0600; Keychain references only
├── logs/                # metadata-only operational logs
├── state/ledger.sqlite3 # encrypted fields + transactional metadata
└── venv/
```

The user LaunchAgent plist is stored at
`~/Library/LaunchAgents/com.christophercc.ginger-agent.plist`. Apple documents that
per-user agents run in the logged-in user's context and are managed by `launchd`:
[Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

## Install from a fixed prerelease

Never install by scheduling `git pull main`. Select an immutable tag and verify its
published checksum:

```bash
VERSION=v0.2.0-rc.2
curl -fsSLO "https://github.com/ChristopherCC-Liu/ginger_wechat_portrait/releases/download/${VERSION}/ginger-personal-agent-${VERSION}.tar.gz"
curl -fsSLO "https://github.com/ChristopherCC-Liu/ginger_wechat_portrait/releases/download/${VERSION}/SHA256SUMS"
grep "  ginger-personal-agent-${VERSION}.tar.gz$" SHA256SUMS | shasum -a 256 -c -
tar -xzf "ginger-personal-agent-${VERSION}.tar.gz"
cd "ginger-personal-agent-${VERSION}"
./install-macos.sh
```

The installer creates a private virtual environment, installs dependencies from
`requirements.lock` with `--require-hashes`, preserves an existing config, and does
not load a service until configuration is complete.

## Configure local state and keys

```bash
AGENT="$HOME/Library/Application Support/GingerAgent/bin/ginger-agent"
CONFIG="$HOME/Library/Application Support/GingerAgent/config.toml"

chmod 600 "$CONFIG"
"$AGENT" --config "$CONFIG" secret-set --name state-key --generate-bytes 32
"$AGENT" --config "$CONFIG" secret-set --name identity-key --generate-bytes 32
"$AGENT" --config "$CONFIG" secret-set --name wechat-self-id
```

For a paid provider, store only its key in Keychain:

```bash
"$AGENT" --config "$CONFIG" secret-set --name openai-api-key
# or
"$AGENT" --config "$CONFIG" secret-set --name glm-api-key
```

Then set `model.api_key_ref` to that Keychain account name. A raw `api_key`,
`password`, `token`, or credential-like value in `config.toml` is rejected.

To import a local legacy database key file into Keychain and leave the source file
untouched:

```bash
"$AGENT" --config "$CONFIG" import-wechat-keys --keys-file /private/path/wechat_keys.json
```

Delete or archive the legacy key file yourself after verifying the import. It is
never copied into the Git repository or runtime config.

## Permissions

The process that reads WeChat's container may need Full Disk Access. Typing-only UI
validation needs Accessibility and Automation approval. Apple requires users to
grant these explicitly in **System Settings > Privacy & Security**:
[Accessibility](https://support.apple.com/guide/mac-help/mh43185/mac),
[Automation](https://support.apple.com/guide/mac-help/mchl108e1718/mac), and
[privacy controls](https://support.apple.com/guide/mac-help/mchl211c911f/mac).

The service does not disable SIP, re-sign WeChat, or run as root. Key extraction is
a separate manual maintenance operation and is not scheduled by the agent.

## Verify and start

```bash
"$AGENT" --config "$CONFIG" doctor
"$AGENT" --config "$CONFIG" run-once
"$AGENT" --config "$CONFIG" status
"$AGENT" --config "$CONFIG" install-service
```

Success signals:

- `doctor` reports config mode `0600`, a readable database source, and real send
  disabled.
- `run-once` reports polling and dedupe counts with `model_calls = 0` when nothing
  requires a reply.
- `status` reports mode `shadow`, no active kill switch, and a loaded LaunchAgent.

## Operational commands

```bash
"$AGENT" --config "$CONFIG" pause
"$AGENT" --config "$CONFIG" resume
"$AGENT" --config "$CONFIG" status
"$AGENT" --config "$CONFIG" cost-report
"$AGENT" --config "$CONFIG" distill-refresh --force
"$AGENT" --config "$CONFIG" kill-switch --enable
"$AGENT" --config "$CONFIG" kill-switch --clear
"$AGENT" --config "$CONFIG" uninstall-service
```

`pause` is reversible. The kill switch also pauses the runtime and must be cleared
explicitly before `resume` succeeds.

## Upgrade or roll back

Run the installer for another fixed tag. It builds a new versioned virtual
environment in place, validates every installed entry point, then switches the
`venv` symlink. The previous target remains available through `venv.previous`;
`config.toml`, Keychain items, ledger, controls, and logs remain in place.

```bash
"$HOME/Library/Application Support/GingerAgent/bin/install-release" v0.2.0-rc.2
```

Rollback uses the same command with the previous release tag. Distillation rollback
is independent and selects an immutable local version; it does not downgrade code.

## Real-send boundary

`approve` and `autopilot` are implemented as decision modes, but a Return-key click
still requires all policy gates, an idempotent send reservation, exact recipient and
body verification, `real_send_enabled = true`, typing-only disabled, and a separate
Keychain canary. This prerelease does not create that canary during installation or
tests. The first real click must be authorized in a separate, explicit user action.
