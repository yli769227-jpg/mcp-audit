# mcp-audit

[![test](https://github.com/yli769227-jpg/mcp-audit/actions/workflows/test.yml/badge.svg)](https://github.com/yli769227-jpg/mcp-audit/actions/workflows/test.yml)

> 你装了多少个 MCP server？还有几个能用？哪个偷偷在泄漏 key？
>
> *How many MCP servers did you install? How many still work? Which one is quietly leaking a key?*

**mcp-audit** 是一个**只读、离线、偏执**的命令行工具，扫一遍你的 Claude Code 配置（`~/.claude/`、当前项目的 `.mcp.json` 等），把所有 MCP server 列出来，标出**硬编码的密钥、休眠的 server、过宽的权限、跨 scope 的重复定义**。

**mcp-audit** is a **read-only, offline, paranoid** CLI that walks your Claude Code config (`~/.claude/`, the project's `.mcp.json`, etc.), enumerates every MCP server, and flags **hard-coded secrets, dormant servers, over-broad permissions, and cross-scope duplicates**.

---

## Why / 为什么

AI 代理偷偷给你装 MCP server，一年装了 12 个，没人记得哪个还在用、哪个 key 已经被 commit 到 git 历史里。`claude mcp list` 只告诉你"有什么"，不告诉你"哪里有问题"。这就是 mcp-audit 的位置。

Coding agents quietly install MCP servers for you. A year later you have 12 of them, you can't remember which still work, and at least one config has a hard-coded `sk-...` that got committed to git. `claude mcp list` shows you *what you have*; mcp-audit shows you *what's wrong with it*.

**绝不做的事 / Hard rules:**

- **永远不打印密钥实际值** — 命中泄漏只报字段名 + 字符长度 + 文件路径。
  *Never prints the matched secret value — only field name, char count, file path.*
- **永远不写回任何配置文件** — read-only。
  *Never writes to any config file — read-only.*
- **不联网** — 所有规则离线。
  *No network — every rule is offline.*
- **只读 MCP 相关文件，不碰其它** —— 只查固定的几个文件名（`~/.claude.json`、`~/.claude/` 下的 `mcp.json`/`settings.json`/`settings.local.json`、以及项目目录的 `.mcp.json` 和 `.claude/settings*.json`），`~/.ssh/`、`~/.aws/` 一律不碰。
  *Only reads a fixed set of MCP-related filenames; never touches `~/.ssh/`, `~/.aws/`, or anything else.*

---

## What it scans / 扫描范围

mcp-audit 只查下面这几处固定位置的 MCP 配置，**不会**遍历整个磁盘：

mcp-audit only reads MCP config from these fixed locations — it never walks your whole disk:

- `~/.claude.json`（Claude Code 主状态文件：user-scope 在顶层 `mcpServers`，local-scope 在 `projects.<path>.mcpServers`）。
- `~/.claude/` 下的 `mcp.json`、`settings.json`、`settings.local.json`。
- 起始目录（cwd 或 `--path`）**以及最多 5 层父目录**里的 `.mcp.json` 和 `.claude/settings*.json`。

向上遍历父目录是**有意为之**：Claude Code 本身就会从父目录读取项目的 `.mcp.json`，所以一个真正生效的配置可能在 cwd 之上。我们只匹配上面列出的几个文件名，绝不读取其它无关文件。

Walking up to 5 ancestor directories is **intentional**: Claude Code itself reads a project's `.mcp.json` from parent directories, so a config that actually affects your session can live above cwd. Only the filenames listed above are ever matched.

---

## Install / 安装

> 尚未发布到 PyPI——PyPI 发布前请用 git 安装。
> *Not yet published to PyPI — until then, install from git.*

```bash
pipx install git+https://github.com/yli769227-jpg/mcp-audit
# or
pip install git+https://github.com/yli769227-jpg/mcp-audit
```

Python 3.11+。依赖只有 `click` 和 `rich`，无大依赖。

Python 3.11+. Dependencies are just `click` and `rich` — nothing heavy.

---

## Usage / 用法

```bash
# 扫当前项目 + ~/.claude/
mcp-audit scan

# 扫指定项目目录
mcp-audit scan --path ~/projects/my-thing

# JSON 输出（CI 用）
mcp-audit scan --format json

# Markdown 输出（贴到 PR 用）
mcp-audit scan --format markdown
```

CI 集成时可以加 `--fail-on critical`（默认）或 `--fail-on warn` 让脚本在发现问题时返回非零。

For CI integration, `--fail-on critical` (default) or `--fail-on warn` makes the command exit non-zero when findings of that severity exist.

---

## Sample output / 示例输出

下面是一个真实命中的扫描结果（fixture 数据，不是真密钥）：

Below is a real scan (1 critical + 2 warn + 1 info):

```text
╭───────────────────── mcp-audit ─────────────────────╮
│ 2 config file(s) | 3 MCP server(s) | 1 critical |    │
│ 1 warn | 2 info | 0 unknown                          │
╰──────────────────────────────────────────────────────╯

                          Findings
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sev           ┃ Rule               ┃ Server     ┃ Message                       ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ✗ CRITICAL    │ secret_leak        │ github     │ hard-coded credential in      │
│               │                    │            │ 'env.GITHUB_TOKEN'            │
│               │                    │            │ (github_pat, 39 chars).       │
│ ! WARN        │ permission_scope   │ github     │ every tool of 'github' is     │
│               │                    │            │ allowed indiscriminately via  │
│               │                    │            │ permissions rule 'mcp__github'│
│ i INFO        │ permission_scope   │ legacy-bot │ no explicit tool-permission   │
│               │                    │            │ entry — Claude Code prompts   │
│               │                    │            │ each call.                    │
│ i INFO        │ dormant            │ filesystem │ dormancy cannot be determined │
│               │                    │            │ (best-effort; no last_used).  │
└───────────────┴────────────────────┴────────────┴───────────────────────────────┘
```

完整 demo 见 [examples/sample-output.md](examples/sample-output.md)。

Full demo with all four rule categories in [examples/sample-output.md](examples/sample-output.md).

---

## Rules / 检测规则

| Rule | Severity | What it catches |
|---|---|---|
| `secret_leak` | CRITICAL / WARN | 正则精确命中（`sk-...`、`sk-ant-...`、`ghp_...`、`Bearer ...`、AWS key、JWT、URL 里的凭证等）→ **CRITICAL**；仅靠"字段名像密钥 + 值是长不透明串"的启发式命中 → **WARN**（信号较弱）。*Exact regex match (`sk-...`, `sk-ant-...`, `ghp_...`, `Bearer ...`, AWS keys, JWTs, URL-embedded creds) → CRITICAL; the softer heuristic (secret-looking field name + long opaque value) → WARN.* |
| `permission_scope` | WARN / INFO | `allowed_tools` is `"*"` or empty (WARN), or missing (INFO) — every tool the server advertises is callable. 注意：`allowed_tools` 是 mcp-audit 的扩展约定，不是 Claude Code 官方配置字段，因此"字段缺失"只报 INFO，不会让 `--fail-on warn` 的 CI 恒失败。*Note: `allowed_tools` is an mcp-audit extension convention, not an official Claude Code field, so the missing-field case is INFO only and won't permanently fail a `--fail-on warn` CI gate.* |
| `overlap` | WARN | Same server name defined in multiple scopes (user / project / local) — silent shadowing. |
| `dormant` | WARN / INFO | **Best-effort.** Claude Code records no reliable per-server last-used timestamp, so this rule can only act on an explicit `last_used` field in the config: older than 30 days → WARN; fresh → silent. With no such field it emits an **INFO** honestly stating dormancy can't be determined (run `claude mcp list` to check manually). |

---

## What it does NOT do / 边界

- 不联网，不下载漏洞库，不调 API。
  *No network calls. No vuln DB. No API.*
- 不修复，不重写，不删除。建议给你，动手在你。
  *No autofix. We tell you; you decide.*
- 不读 git 历史。如果你的 key 已经被 commit 了，请用 `gitleaks` 之类的工具。
  *Doesn't read git history — that's `gitleaks`' job.*

---

## Show HN

这个工具诞生于 HN 一条吐槽:"AI agent 偷装 MCP, key 漏了, 没人知道自己装了什么"。如果你也遇到过, 跑一遍试试。

This was built after seeing the recurring HN complaint: "AI agents secretly install MCP servers, keys leak, nobody knows what they installed." If that's you, give it 30 seconds.

---

## License

MIT.
