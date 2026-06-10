# mcp-audit — sample output / 完整示例

下面是 mcp-audit 在一份**故意做坏**的配置上的真实输出。包含全部规则的命中:

This is mcp-audit's real output against a deliberately-broken config that triggers every rule:

- `secret_leak` (CRITICAL) — 硬编码的 GitHub token
- `permission_scope` (WARN / INFO) — `permissions.allow` 里 `mcp__github` 无差别放开整个 server(WARN);`legacy-bot` 完全没有权限条目(INFO)
- `dormant` (WARN / INFO) — `last_used` > 30 天(WARN);无 `last_used` 字段时诚实报无法判定(INFO)

> 权限判定的真相源是 Claude Code 的 `settings.json` → `permissions.allow` / `permissions.deny`(规则串形如 `mcp__<server>` 或 `mcp__<server>__<tool>`),不是 mcp-audit 自创的 `allowed_tools` 字段。
>
> Permission verdicts come from Claude Code's real source: `settings.json` → `permissions.allow` / `permissions.deny` (rule strings like `mcp__<server>` or `mcp__<server>__<tool>`).

---

## Demo config

`./demo-project/.mcp.json`:

```json
{
  "mcpServers": {
    "github":     { "command": "npx", "args": ["@modelcontextprotocol/server-github"],
                    "env": { "GITHUB_TOKEN": "ghp_REDACTED..." },
                    "last_used": "2025-01-01T00:00:00Z" },
    "filesystem": { "command": "npx", "args": ["@modelcontextprotocol/server-filesystem"] },
    "legacy-bot": { "command": "/usr/local/bin/legacy-bot" }
  }
}
```

`./demo-project/.claude/settings.json`:

```json
{
  "permissions": {
    "allow": [
      "mcp__github",
      "mcp__filesystem__read_file",
      "mcp__filesystem__list_dir"
    ],
    "deny": []
  }
}
```

## Command

```bash
mcp-audit scan --path ./demo-project
```

---

## Findings (text output)

```text
╭───────────────────────────────── mcp-audit ──────────────────────────────────╮
│ 2 config file(s) | 3 MCP server(s) | 1 critical | 2 warn | 3 info | 0 unknown │
╰───────────────────────────────────────────────────────────────────────────────╯
```

| Sev | Rule | Server | Message (abridged) |
|---|---|---|---|
| ✗ CRITICAL | `secret_leak` | github | hard-coded credential in field `env.GITHUB_TOKEN` (github_pat, 39 chars). Use an env-var reference instead. |
| ! WARN | `permission_scope` | github | every tool of `github` is allowed indiscriminately via permissions rule `mcp__github`. Replace with per-tool `mcp__github__<tool>` entries. |
| ! WARN | `dormant` | github | appears dormant: last activity 525 days ago (signal: `config.last_used`). |
| i INFO | `permission_scope` | legacy-bot | no explicit tool-permission entry in settings.json — Claude Code will prompt each call. Add `mcp__legacy-bot__<tool>` rules. |
| i INFO | `dormant` | filesystem | dormancy cannot be determined: Claude Code records no reliable per-server last-used timestamp, and no `last_used` field is set. |
| i INFO | `dormant` | legacy-bot | dormancy cannot be determined (same as above). |

> 注意 `filesystem` 用精确到 tool 的 `mcp__filesystem__read_file` / `__list_dir` 授权,所以 `permission_scope` 对它**不产生任何 finding**(PASS)。
>
> Note `filesystem` is scoped to specific tools (`mcp__filesystem__read_file` / `__list_dir`), so `permission_scope` emits **no finding** for it (PASS).

---

## JSON output (`--format json`)

```json
{
  "summary": {
    "config_files": 2,
    "servers": 3,
    "findings": 6,
    "by_severity": {"CRITICAL": 1, "WARN": 2, "INFO": 3, "UNKNOWN": 0}
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "rule": "secret_leak",
      "server": "github",
      "source_file": "/path/to/demo-project/.mcp.json",
      "message": "possible hard-coded credential in field 'env.GITHUB_TOKEN' (github_pat, 39 chars). Use an env-var reference like ${YOUR_API_KEY} instead.",
      "details": {"field_path": "env.GITHUB_TOKEN", "pattern": "github_pat", "char_count": 39, "line": 6}
    },
    {
      "severity": "WARN",
      "rule": "permission_scope",
      "server": "github",
      "message": "every tool of server 'github' is allowed indiscriminately via permissions rule 'mcp__github'. ...",
      "details": {"allow_rules": ["mcp__github"], "source": "permissions.allow"}
    }
  ]
}
```

注意:即使在 JSON 输出里,**实际的 token 值也从不出现**。只有字段名、模式名、字符数、行号。

Note: even in JSON output, **the actual token value never appears**. Only field name, pattern name, char count, line number.

---

## What to do about each finding / 怎么修

| Rule | Fix |
|---|---|
| `secret_leak` | 把字面量换成 `${YOUR_VAR_NAME}` 引用,把真实 key 放进 shell env / `direnv` / `1Password CLI`。**别忘了 rotate 已经泄漏的那个**。 |
| `permission_scope` (WARN) | 把 `permissions.allow` 里的 `mcp__<server>` 换成精确到 tool 的 `mcp__<server>__<tool>`,只放开你真的会用的工具。 |
| `permission_scope` (INFO) | 如果想免去每次确认,在 `settings.json` 的 `permissions.allow` 里给该 server 加上明确的 `mcp__<server>__<tool>` 条目。 |
| `dormant` (WARN) | 直接 `claude mcp remove <name>`,或者保留但承认这是僵尸条目。 |
| `dormant` (INFO) | 无可靠信号,best-effort。需要确认用量请跑 `claude mcp list` 或看 server 自己的日志。 |
