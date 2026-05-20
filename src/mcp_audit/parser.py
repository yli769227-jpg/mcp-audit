"""Parse various Claude Code MCP config file formats into a uniform model.

Supported shapes (all JSON):

1. Top-level ``{"mcpServers": {name: {...}}}`` — used by
   ``~/.claude/settings.json`` and ``.mcp.json``.
2. Top-level ``{name: {...}}`` — used by some older ``~/.claude/mcp.json``.

Each server entry can carry arbitrary fields. We deliberately keep ``raw``
attached so downstream rules can inspect anything (e.g. ``allowed_tools``,
``env``, ``args``) without us having to enumerate every key.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("mcp_audit.parser")


@dataclass
class ServerEntry:
    """A single MCP server parsed out of a config file."""

    name: str
    source_file: Path
    scope: str  # "user", "project", "local", "unknown"
    raw: dict[str, Any] = field(default_factory=dict)

    def get_command(self) -> str | None:
        return self.raw.get("command")

    def get_args(self) -> list[str]:
        args = self.raw.get("args", [])
        return list(args) if isinstance(args, list) else []

    def get_env(self) -> dict[str, Any]:
        env = self.raw.get("env", {})
        return dict(env) if isinstance(env, dict) else {}

    def get_allowed_tools(self) -> Any:
        # Could be list, str (e.g. "*"), or absent.
        return self.raw.get("allowed_tools", self.raw.get("allowedTools"))


@dataclass
class ConfigFile:
    """A parsed config file with the servers we found inside it."""

    path: Path
    scope: str
    servers: list[ServerEntry] = field(default_factory=list)
    parse_error: str | None = None


def _classify_scope(path: Path) -> str:
    """Heuristic: scope from file location."""
    p = str(path)
    home = str(Path.home())
    if p.startswith(home + "/.claude/"):
        if path.name == "settings.local.json":
            return "local"
        return "user"
    if ".claude" in path.parts:
        return "project"
    if path.name == ".mcp.json":
        return "project"
    return "unknown"


def parse_config_file(path: Path) -> ConfigFile:
    """Parse one config file into a ConfigFile object.

    Never raises — broken files produce ConfigFile.parse_error and an empty
    server list. We log every step (CLAUDE.md §3 — observability).
    """
    log.info("[parser] reading %s", path)
    scope = _classify_scope(path)
    cf = ConfigFile(path=path, scope=scope)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        log.warning("[parser] cannot read %s: %s", path, e)
        cf.parse_error = f"read error: {e}"
        return cf

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.warning("[parser] invalid JSON in %s: %s", path, e)
        cf.parse_error = f"json error: {e.msg} (line {e.lineno})"
        return cf

    if not isinstance(data, dict):
        cf.parse_error = "top-level is not an object"
        return cf

    # Shape 1: {"mcpServers": {...}}
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        servers_dict = data["mcpServers"]
        log.info("[parser] %s: shape=mcpServers, count=%d", path, len(servers_dict))
        for name, body in servers_dict.items():
            if not isinstance(body, dict):
                continue
            cf.servers.append(
                ServerEntry(name=name, source_file=path, scope=scope, raw=body)
            )
        return cf

    # Shape 2: looks like a bare dict of servers (heuristic: every value is
    # a dict that has "command" or "args" or "url").
    if data and all(
        isinstance(v, dict)
        and (("command" in v) or ("args" in v) or ("url" in v) or ("type" in v))
        for v in data.values()
    ):
        log.info("[parser] %s: shape=bare-dict, count=%d", path, len(data))
        for name, body in data.items():
            cf.servers.append(
                ServerEntry(name=name, source_file=path, scope=scope, raw=body)
            )
        return cf

    log.info("[parser] %s: no MCP servers detected", path)
    return cf
