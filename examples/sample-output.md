# mcp-audit — sample output / 完整示例

下面是 mcp-audit 在一份**故意做坏**的配置上的真实输出。包含 4 类规则全部命中:

This is mcp-audit's real output against a deliberately-broken config that triggers every rule:

- `secret_leak` (CRITICAL) — 硬编码的 GitHub token / OpenAI key / Bearer JWT
- `permission_scope` (WARN) — `allowed_tools: "*"` 或缺失
- `overlap` (WARN) — 同名 server 在 user + project 两处定义
- `dormant` (WARN / UNKNOWN) — `last_used` > 30 天 或缺失 signal

---

## Command

```bash
mcp-audit scan --path ./demo-project
```

---

## Text output (default, with rich colors in a real terminal)

```text
╭───────────────────────────── mcp-audit ──────────────────────────────╮
│ 2 config file(s) | 5 MCP server(s) | 3 critical | 4 warn | 2 unknown │
╰──────────────────────────────────────────────────────────────────────╯
                            Discovered config files
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┓
┃ Scope   ┃ Path                              ┃ Servers ┃ Notes ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━┩
│ user    │ ~/.claude/settings.json           │       3 │       │
│ project │ ./demo-project/.mcp.json          │       2 │       │
└─────────┴───────────────────────────────────┴─────────┴───────┘

                                  MCP servers
┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Name          ┃ Scope   ┃ Command                      ┃ Source                ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ github        │ user    │ npx server-github            │ ~/.claude/settings…   │
│ openai-bridge │ user    │ node bridge.js               │ ~/.claude/settings…   │
│ legacy-bot    │ user    │ /usr/local/bin/legacy-bot    │ ~/.claude/settings…   │
│ github        │ project │ npx server-github@v2         │ ./demo-project/.mc…   │
│ filesystem    │ project │ npx server-filesystem        │ ./demo-project/.mc…   │
└───────────────┴─────────┴──────────────────────────────┴───────────────────────┘

                                          Findings
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sev         ┃ Rule              ┃ Server        ┃ Message                                      ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ✗ CRITICAL  │ secret_leak       │ github        │ possible hard-coded credential in field      │
│             │                   │               │ 'env.GITHUB_TOKEN' (github_pat, 40 chars).   │
│             │                   │               │ Use an env-var reference like ${YOUR_API_KEY}│
│             │                   │               │ instead.                                     │
│ ✗ CRITICAL  │ secret_leak       │ openai-bridge │ possible hard-coded credential in field      │
│             │                   │               │ 'env.OPENAI_API_KEY' (openai_sk, 60 chars).  │
│ ✗ CRITICAL  │ secret_leak       │ legacy-bot    │ possible hard-coded credential in field      │
│             │                   │               │ 'env.AUTH' (bearer_token, 84 chars).         │
│ ! WARN      │ overlap           │ github        │ server 'github' is defined in 2 places. The  │
│             │                   │               │ narrower scope (project) wins; the others    │
│             │                   │               │ are shadowed and silently ignored.           │
│ ! WARN      │ permission_scope  │ legacy-bot    │ 'allowed_tools' contains '*' — all tools     │
│             │                   │               │ allowed. Consider listing only the tools     │
│             │                   │               │ you actually use.                            │
│ ! WARN      │ permission_scope  │ filesystem    │ no 'allowed_tools' field set — every tool    │
│             │                   │               │ the server advertises is callable.           │
│ ! WARN      │ dormant           │ legacy-bot    │ server appears dormant: last activity 412    │
│             │                   │               │ days ago (signal: config.last_used).         │
│             │                   │               │ Consider removing if unused.                 │
│ ? UNKNOWN   │ dormant           │ openai-bridge │ no last-used signal available. MCP does not  │
│             │                   │               │ standardize this; consider running           │
│             │                   │               │ `claude mcp list` or check the server's own  │
│             │                   │               │ logs.                                        │
│ ? UNKNOWN   │ dormant           │ filesystem    │ no last-used signal available. MCP does not  │
│             │                   │               │ standardize this; consider running           │
│             │                   │               │ `claude mcp list` or check the server's own  │
│             │                   │               │ logs.                                        │
└─────────────┴───────────────────┴───────────────┴──────────────────────────────────────────────┘
```

---

## JSON output (`--format json`)

```json
{
  "summary": {
    "config_files": 2,
    "servers": 5,
    "findings": 9,
    "by_severity": {"CRITICAL": 3, "WARN": 4, "INFO": 0, "UNKNOWN": 2}
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "rule": "secret_leak",
      "server": "github",
      "source_file": "/Users/me/.claude/settings.json",
      "message": "possible hard-coded credential in field 'env.GITHUB_TOKEN' (github_pat, 40 chars). Use an env-var reference like ${YOUR_API_KEY} instead.",
      "details": {"field_path": "env.GITHUB_TOKEN", "pattern": "github_pat", "char_count": 40, "line": 12}
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
| `permission_scope` | 在 `allowed_tools` 里显式列出你真的会用的工具名,而不是 `*`。 |
| `overlap` | 如果是故意的(项目要 override user 默认),写个注释。如果是历史遗留,删掉旧的那份。 |
| `dormant` | 直接 `claude mcp remove <name>`,或者保留但承认这是僵尸条目。 |
