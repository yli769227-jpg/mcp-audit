"""Parse various Claude Code MCP config file formats into a uniform model.

Supported shapes (all JSON):

1. Top-level ``{"mcpServers": {name: {...}}}`` — used by
   ``~/.claude/settings.json`` and ``.mcp.json``.
2. Top-level ``{name: {...}}`` — used by some older ``~/.claude/mcp.json``.
3. ``~/.claude.json`` — Claude Code's main state file: user-scope servers in
   top-level ``mcpServers``, local-scope servers in
   ``projects.<abs-path>.mcpServers``. Everything else in it is ignored.

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
    if path.name == ".claude.json":
        return "user"
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

    # Special case: ~/.claude.json. Claude Code stores user-scope servers at
    # the top-level ``mcpServers`` and local-scope ones under
    # ``projects.<abs-path>.mcpServers``. The file is large and full of
    # unrelated state — we extract ONLY those two spots, tolerantly.
    if path.name == ".claude.json":
        return _parse_claude_json(path, data, cf)

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


def _parse_claude_json(path: Path, data: dict[str, Any], cf: ConfigFile) -> ConfigFile:
    """Extract mcpServers from ~/.claude.json (user scope at top level,
    local scope under projects.*.mcpServers).

    Never raises — this is a read-only audit tool, one malformed file must
    not take down the whole run. Unexpected shapes are logged and skipped.
    """
    try:
        # User scope: top-level mcpServers
        top = data.get("mcpServers")
        if isinstance(top, dict):
            log.info("[parser] %s: top-level mcpServers count=%d", path, len(top))
            for name, body in top.items():
                if isinstance(body, dict):
                    cf.servers.append(
                        ServerEntry(name=name, source_file=path, scope="user", raw=body)
                    )
        elif top is not None:
            log.warning("[parser] %s: top-level mcpServers is not an object, skipping", path)

        # Local scope: projects.<abs-path>.mcpServers
        projects = data.get("projects")
        if isinstance(projects, dict):
            for proj_path, proj_body in projects.items():
                if not isinstance(proj_body, dict):
                    continue
                proj_servers = proj_body.get("mcpServers")
                if not isinstance(proj_servers, dict):
                    continue
                log.info(
                    "[parser] %s: projects[%s].mcpServers count=%d",
                    path, proj_path, len(proj_servers),
                )
                for name, body in proj_servers.items():
                    if isinstance(body, dict):
                        cf.servers.append(
                            ServerEntry(name=name, source_file=path, scope="local", raw=body)
                        )
        elif projects is not None:
            log.warning("[parser] %s: 'projects' is not an object, skipping", path)
    except Exception as e:  # defensive: never crash the audit on one bad file
        log.exception("[parser] error while extracting from %s: %s", path, e)
        cf.parse_error = f"claude.json extraction error: {e}"

    log.info("[parser] %s: shape=claude.json, total servers=%d", path, len(cf.servers))
    return cf
