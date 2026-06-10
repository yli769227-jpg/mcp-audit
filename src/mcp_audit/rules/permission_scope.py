"""Flag MCP servers with overly-permissive allowed_tools.

If ``allowed_tools`` is ``"*"``, ``["*"]``, an empty list, or absent
entirely, the server can expose any tool name it wants to Claude. That's the
default in many setups, but it's worth telling the user.

NOTE: ``allowed_tools`` is mcp-audit's own opt-in convention, not an
official Claude Code config field. Real-world configs almost never set it,
so the "field missing" case is reported as INFO (not WARN) — otherwise every
server would fail a ``--fail-on warn`` CI gate.
"""

from __future__ import annotations

import logging
from typing import Iterable

from ..parser import ServerEntry
from . import Finding, Severity

log = logging.getLogger("mcp_audit.rules.permission_scope")


def _is_wildcard(allowed: object) -> bool:
    if allowed is None:
        return True
    if allowed == "*":
        return True
    if isinstance(allowed, list):
        if len(allowed) == 0:
            return True
        if any(item == "*" for item in allowed):
            return True
    return False


def detect_permission_scope(
    server: ServerEntry, all_servers: list[ServerEntry]
) -> Iterable[Finding]:
    allowed = server.get_allowed_tools()
    log.info(
        "[permission_scope] server=%s allowed_tools=%r", server.name, allowed,
    )
    if not _is_wildcard(allowed):
        return

    severity = Severity.WARN
    if allowed is None:
        # 'allowed_tools' is an mcp-audit extension convention, not an
        # official Claude Code field — its absence is normal, so INFO only.
        severity = Severity.INFO
        explanation = (
            "no 'allowed_tools' field set — every tool the server advertises is callable. "
            "Note: 'allowed_tools' is an mcp-audit extension convention, "
            "not an official Claude Code config field"
        )
    elif allowed == "*" or (isinstance(allowed, list) and any(i == "*" for i in allowed)):
        explanation = "'allowed_tools' contains '*' — all tools allowed"
    else:
        explanation = "'allowed_tools' is empty — defaults to all tools allowed"

    yield Finding(
        severity=severity,
        rule="permission_scope",
        server=server.name,
        source_file=server.source_file,
        message=(
            f"{explanation}. "
            "Consider listing only the tools you actually use."
        ),
        details={"allowed_tools": allowed},
    )
