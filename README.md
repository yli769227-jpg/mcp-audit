# mcp-audit

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
- **不扫 MCP 之外的目录** —— `~/.ssh/`、`~/.aws/` 一律不碰。
  *Never scans outside `~/.claude/` and your explicit project directory.*

---

## Install / 安装

```bash
pipx install mcp-audit
# or
pip install mcp-audit
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

Below is a real scan against a fixture with 1 critical + 2 warns:

```text
╭─────────────────────────── mcp-audit ────────────────────────────╮
│ 2 config file(s) | 4 MCP server(s) | 1 critical | 2 warn | 1 unknown │
╰──────────────────────────────────────────────────────────────────╯
              Discovered config files
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┓
┃ Scope ┃ Path                        ┃ Servers ┃ Notes ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━┩
│ user  │ ~/.claude/settings.json     │ 3       │       │
│ proj  │ ./.mcp.json                 │ 1       │       │
└───────┴─────────────────────────────┴─────────┴───────┘

                              MCP servers
┏━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Name        ┃ Scope ┃ Command                 ┃ Source                    ┃
┡━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
┃ github      ┃ user  ┃ npx @modelctx/github    ┃ ~/.claude/settings.json   ┃
┃ filesystem  ┃ user  ┃ npx @modelctx/fs        ┃ ~/.claude/settings.json   ┃
┃ legacy-bot  ┃ user  ┃ /usr/local/bin/legacy   ┃ ~/.claude/settings.json   ┃
┃ github      ┃ proj  ┃ npx @modelctx/github    ┃ ./.mcp.json               ┃
└─────────────┴───────┴─────────────────────────┴───────────────────────────┘

                                 Findings
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sev           ┃ Rule               ┃ Server    ┃ Message                         ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ✗ CRITICAL    │ secret_leak        │ github    │ possible hard-coded credential  │
│               │                    │           │ in field 'env.GITHUB_TOKEN'     │
│               │                    │           │ (github_pat, 40 chars). Use     │
│               │                    │           │ ${YOUR_API_KEY} instead.        │
│ ! WARN        │ overlap            │ github    │ defined in 2 places (user +     │
│               │                    │           │ proj). Narrower scope wins; the │
│               │                    │           │ other is shadowed.              │
│ ! WARN        │ permission_scope   │ legacy-bot│ 'allowed_tools' contains '*' —  │
│               │                    │           │ all tools allowed.              │
│ ? UNKNOWN     │ dormant            │ filesystem│ no last-used signal available.  │
└───────────────┴────────────────────┴───────────┴─────────────────────────────────┘
```

完整 demo 见 [examples/sample-output.md](examples/sample-output.md)。

Full demo with all four rule categories in [examples/sample-output.md](examples/sample-output.md).

---

## Rules / 检测规则

| Rule | Severity | What it catches |
|---|---|---|
| `secret_leak` | CRITICAL | Hard-coded `sk-...`, `sk-ant-...`, `ghp_...`, `Bearer ...`, AWS keys, JWTs, plus heuristic catch of long opaque strings in `api_key`/`token`/`secret` fields. |
| `permission_scope` | WARN | `allowed_tools` is `"*"`, empty, or missing — every tool the server advertises is callable. |
| `overlap` | WARN | Same server name defined in multiple scopes (user / project / local) — silent shadowing. |
| `dormant` | WARN / UNKNOWN | Last activity > 30 days ago, judged via `last_used` field or `~/.claude/cache/mcp_<name>/last_activity` mtime. MCP doesn't standardize this, so UNKNOWN is a real answer. |

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
