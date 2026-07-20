# Ginger Personal Agent

**Last updated:** 2026-07-21

Local-first macOS WeChat analysis and personal reply-agent tooling. This fork keeps
Ginger's offline portrait reports and adds Personal Agent v2: read-only incremental
ingestion, encrypted state, versioned self/relationship distillation, strict reply
decisions, persistent budgets, launchd operations, and isolated UI validation.

## Prerelease safety status

The configuration default is `shadow` and the first real send is not pre-enabled:

- `shadow` may create encrypted drafts but never opens or changes WeChat UI.
- First-run history is baselined with zero model calls and zero send actions.
- `sender.typing_only` defaults to `true`; `sender.real_send_enabled` defaults to
  `false`.
- Computer Use can perform typing-only verification and rejects every click request.
- The installer and launchd job never create a canary automatically.
- `arm-send-canary` must be run explicitly at the action point with
  `--confirm SEND_ONCE`; the prerelease has not run that command and this
  documentation claims no real-send execution.

Money, contracts, medical/legal matters, verification codes, credentials, privacy
disclosure, disputes, and major relationship decisions always require a human.

## Runtime architecture

```text
launchd run-once
  -> discover read-only WeChat shards and tables
  -> three-state direction classification
  -> encrypted, deduplicated event ledger + per-table cursors
  -> local reply-needed rules
  -> contact-isolated context + six-domain active distillation
  -> OpenAI / GLM / loopback-local structured decision adapter
  -> strict ReplyDecision + initial deterministic authority gate
  -> bounded current-contact personal-style render
  -> post-render risk, commitment, and autopilot safe-ack gate
  -> encrypted draft + durable relationship/emotion delay
  -> optional action-point approval or one-time canary
  -> Accessibility exact-recipient/exact-body check
  -> exact outbound database readback + terminal audit state
```

### Four modes

| Mode | Model | Draft | UI/send behavior |
|---|---|---|---|
| `observe` | No | No | Read and record only |
| `shadow` (default) | Rules first | Encrypted | No UI action |
| `approve` | Rules first | Approval required | One fresh approval permits one typing-only validation; never a click |
| `autopilot` | Rules first | Candidate only | A click remains inaccessible unless every send gate and a one-time canary pass |

An `approve-draft` approval lasts at most 600 seconds, is consumed once by
`typing-validate`, and returns `send_allowed=false`. It is not a real-send approval.

## Incremental reader and exact readback

Every poll rediscovers the latest `message/message_N.db` shards and validated
`Msg_<md5>` tables. Existing `(shard, table)` cursors resume in
`(create_time, local_id)` order with a bounded overlap for late WAL visibility.
HMAC-derived event identities, canonical collision checks, and transactional
`INSERT OR IGNORE` semantics deduplicate that overlap and survive restarts.

The first run reads only the configured lookback and marks imported inbound events
as observed, without a model or sender. Its completion time is persisted as one
global bootstrap cutoff. A shard or table discovered later starts at that cutoff,
not at the beginning of chat history; an existing runtime refuses to start if the
cutoff is absent or invalid.

Direction is deliberately three-state: `inbound`, `outbound`, or `unknown`.
Unresolved senders and unsafe group-chat cases remain `unknown`; they are never
guessed into an actionable direction and are not processed as inbound replies or
outbound readback. Real-send configuration additionally requires the local self ID
from Keychain so readback can classify direction safely.

After a click, readback accepts only a newly observed outbound event for the same
pseudonymous contact whose entire UTF-8 body equals the draft. Suffix matches,
trimmed variants, old identical events, and events at or below the pre-click
watermark do not confirm a send.

## Models, budget, and ChatGPT Pro boundary

The production runtime supports three adapters: OpenAI, GLM, and a local
OpenAI-compatible endpoint restricted to literal loopback hosts. Remote providers
require HTTPS. Provider keys are Keychain references; raw credentials in TOML are
rejected. Responses must contain one strict `ReplyDecision`; tools, redirects,
duplicate keys, extra choices, malformed JSON, and oversized responses fail closed.

After that structured decision is parsed and initially gated, a deterministic
personal-style layer may render it using only the active current contact's
`preferred_address`, `temperature`, `emoji_policy`, and `preferred_emoji`, plus the
global `language_style.sentence_ending`. It cannot add facts, commitments,
recipients, confidence, or authority. The completed body is then checked again for
risk and commitment language; an autopilot candidate must also remain a fact-free
canned safe acknowledgement. Styling can therefore downgrade a candidate to a
draft or human handling, never promote one.

Before HTTP, the adapter reserves one daily call and a conservative maximum cost.
Daily call/USD limits are encrypted and persistent across launchd runs. Paid models
require explicit pricing; local models default to zero USD but still consume the
call count. A failed or timed-out request consumes its reserved maximum because the
client cannot prove it was unbilled. Per-contact send frequency is a separate gate.

ChatGPT Pro is only an independent review channel for public repository material.
It is not a production backend, receives no local chat/state/secret data, and cannot
approve a draft, arm a canary, or authorize sending. See
[the public-only review](docs/CHATGPT_PRO_REVIEW.md).

## Six-domain distillation and rollback

The immutable domains are `stable_facts`, `values_boundaries`, `relationship`,
`decision_preferences`, `language_style`, and `emotion_cycle`. Each version records
its parent, evidence IDs, confidence, payload hash, protected fields, correction
type, scope, and creation time. Global domains and each contact's `relationship`
scope are isolated. Activation is explicit or restricted to safe automatic
learning; rollback may select only an ancestor in the same scope.

Stable facts and values are fully protected. Relationship boundaries plus
`display_name` and `ui_search_token` are protected and require a
`user_confirmed` version. Automatic learning may update only non-boundary style,
decision, language, relationship observations, and outbound-text emotion proxies.

### Enroll a contact's UI identity

Prepare a private, untracked `ui-identity.enrollment.json` with fictional values
replaced locally:

```json
{
  "display_name": "Example Contact A",
  "ui_search_token": "example-unique-search-token-a"
}
```

The two values must be non-empty and different after trimming. `display_name` is
the exact visible label that must occur once; `ui_search_token` is the different
string pasted into WeChat search. Bind both to the same pseudonymous contact with
explicit user confirmation:

```bash
AGENT_HOME="${GINGER_AGENT_HOME:-$HOME/Library/Application Support/GingerAgent}"
AGENT="$AGENT_HOME/bin/ginger-agent"
CONFIG="$AGENT_HOME/config.toml"
CONTACT_KEY="${CONTACT_KEY:?set a locally generated contact_ pseudonym}"

chmod 600 ui-identity.enrollment.json
"$AGENT" --config "$CONFIG" distill-put \
  --domain relationship \
  --contact-key "$CONTACT_KEY" \
  --payload-file ui-identity.enrollment.json \
  --confidence 1 \
  --protected-field display_name \
  --protected-field ui_search_token \
  --user-confirmed \
  --activate
```

Do not commit the payload. Draft creation records the active identity version;
typing/click paths revalidate that the same version is still active and that a
user-confirmed ancestor contains the identical pair.

## Timing and real-send gates

Relationship latency and emotion controls can increase the delay, never authority.
The chosen delay and `not_before_epoch` are stored with the encrypted draft. At the
due time, the runtime does not call the model again: it revalidates the durable
decision and persisted post-style body, low-risk and no-commitment rules, current
mode, allowlist, budget, frequency, active UI identity, latest inbound event, and
matching canary. Without a valid canary, it records zero send attempts and leaves
the draft pending for explicit arming. Once preflight passes, it records one
terminal send claim; blocked, failed, uncertain, or unconfirmed attempts are not
retried automatically.

Even in `autopilot`, a real-send candidate requires all of the following:

- `real_send_enabled=true`, `typing_only=false`, and Accessibility as primary;
- a hashed allowlist match and a user-confirmed, still-active UI identity pair;
- low risk, no commitments, complete context, verbatim-grounded facts, and
  confidence at least `0.92`;
- the current implementation's narrower fact-free, canned acknowledgement check;
- current daily budget and per-contact frequency capacity;
- a due, authenticated `autopilot_candidate` draft whose source remains the latest
  inbound event;
- one matching, unexpired Keychain canary bound to the deterministic attempt ID,
  contact key, and full-body SHA-256;
- exact unique recipient and full editor-body equality in Accessibility;
- a strictly post-click, exact full-body outbound database readback.

`arm-send-canary` writes that one-time Keychain record but does not itself click:

```bash
DRAFT_ID="${DRAFT_ID:?select a due autopilot_candidate draft}"
"$AGENT" --config "$CONFIG" arm-send-canary \
  --draft-id "$DRAFT_ID" \
  --expires-seconds 120 \
  --confirm SEND_ONCE
```

The command accepts only 1-600 seconds and only an allowlisted, due candidate in
enabled autopilot mode with a verified user-confirmed UI identity and no prior
terminal send claim. The deterministic attempt ID lets the next eligible runtime
cycle consume exactly that canary once. Installation and background scheduling
never arm it automatically; this prerelease has not run the command.

Computer Use rejects `click_send` unconditionally. Only Accessibility can consume a
canary and press Return. The editor check is full equality (`editor == body`), never
suffix matching.

## Fixed Release install and upgrade

Install and upgrade only from an immutable GitHub Release tag plus its published
`SHA256SUMS`; never use `git pull` as an installed update mechanism. The installer
validates the checksum, archive root, path safety, and absence of links/special
files before creating a new versioned virtual environment.

No published Release is asserted here. After choosing a tag that is visibly present
in GitHub Releases, set `RELEASE_TAG` and use the candidate installer contract:

```bash
RELEASE_TAG="${RELEASE_TAG:?set a published fixed vX.Y.Z tag}"
./scripts/install-release.sh "$RELEASE_TAG"
```

For an already installed copy, the same verified flow is installed as:

```bash
"$AGENT_HOME/bin/install-release" "$RELEASE_TAG"
"$AGENT" --config "$CONFIG" doctor
"$AGENT" --config "$CONFIG" install-service
```

Use the same command with the previous fixed tag for rollback. Re-running
`install-service` updates and restarts the user LaunchAgent against the selected
version. Source checkouts are for development and validation, not installed
upgrades.

## Operate the LaunchAgent

```bash
"$AGENT" --config "$CONFIG" doctor
"$AGENT" --config "$CONFIG" run-once
"$AGENT" --config "$CONFIG" install-service
"$AGENT" --config "$CONFIG" status
"$AGENT" --config "$CONFIG" cost-report
"$AGENT" --config "$CONFIG" pause
"$AGENT" --config "$CONFIG" resume
"$AGENT" --config "$CONFIG" kill-switch --enable
"$AGENT" --config "$CONFIG" kill-switch --clear
"$AGENT" --config "$CONFIG" uninstall-service
```

`doctor` is read-only and performs zero network, model, and send actions. It exits
`0` only when all required readiness checks pass, `1` when any required check fails,
and `2` for configuration or command errors. `resume` refuses while the kill switch
is active; clear it explicitly first.

## Test, replay, and publication scan

```bash
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest discover -s tests -v
python -m personal_agent.replay \
  --replay tests/fixtures/shadow_replay.json \
  --risks tests/fixtures/risk_cases.json
python3 scripts/check-release-tree.py --candidate-tree
```

Checked-in fixtures are fictional. The release scanner covers tracked and untracked
candidate files so a code-bearing untracked tree can still be checked before it is
staged. It rejects non-allowlisted paths, databases, local user paths, non-synthetic
identifiers, credential patterns, unsafe binaries, and oversized files.

## Original Ginger and privacy boundary

The original `/analyze-wechat` portrait workflow, charts, personality analysis,
HTML reports, and the v1 manual-review bundle remain available. Personal Agent v2
does not use those reports as runtime authorization. See [SKILL.md](SKILL.md) and
[the detailed v2 contract](docs/PERSONAL_CHAT_AGENT.md).

Only source, tests, fictional fixtures, documentation, installation scripts,
LaunchAgent templates, and dependency locks belong in Git. Never track exports,
reports, databases, WAL/SHM files, key files, application state, logs, model
responses, UI identity payloads, or local contact mappings. Do not use `git add .`.
See [the security model](docs/SECURITY.md).
