"""Audit how broadly each MCP server's tools are permitted.

PRIMARY SOURCE — Claude Code tool permissions (settings.json):
Claude Code gates MCP tool calls through ``permissions.allow`` /
``permissions.deny`` in ``settings.json`` / ``settings.local.json``. Rule
strings for MCP look like:

- ``mcp__<server>``            → allow/deny the WHOLE server (every tool)
- ``mcp__<server>__<tool>``    → a single specific tool
- ``mcp__<server>__*``         → wildcard over the server's tools

The analyzer aggregates these strings from every discovered settings file and
attaches them to each ServerEntry (``server.allow_rules`` /
``server.deny_rules``). For each server we then decide:

- A bare ``mcp__<server>`` (or ``mcp__<server>__*``) sits in ``allow`` →
  **WARN**: every tool the server advertises is allowed indiscriminately.
- The server appears in ``allow`` only via specific ``mcp__<server>__<tool>``
  entries → **PASS** (no finding): scoped to named tools.
- The server is referenced nowhere in any permissions block → **INFO**: no
  explicit permission config, so Claude Code will prompt at call time.

ADDITIONAL SIGNAL — mcp-audit's own ``allowed_tools`` convention:
Some configs (and our own fixtures) carry a non-official ``allowed_tools``
field. A ``"*"`` / ``["*"]`` / empty value there is still worth surfacing as
a WARN, but it is a secondary signal, not the authority. Absence of the field
is NOT reported on its own (the permissions source above is what matters).
"""

from __future__ import annotations

import logging
from typing import Iterable

from ..parser import ServerEntry
from . import Finding, Severity

log = logging.getLogger("mcp_audit.rules.permission_scope")


def _rules_for_server(rules: list[str], server_name: str) -> dict[str, list[str]]:
    """Classify permission rule strings that target ``server_name``.

    Returns {"whole": [...], "wildcard": [...], "scoped": [...]} where:
      whole    = exact "mcp__<server>" (no tool suffix) → all tools
      wildcard = "mcp__<server>__*"                       → all tools
      scoped   = "mcp__<server>__<tool>" with a concrete tool
    """
    prefix = f"mcp__{server_name}"
    out: dict[str, list[str]] = {"whole": [], "wildcard": [], "scoped": []}
    for r in rules:
        if r == prefix:
            out["whole"].append(r)
        elif r == f"{prefix}__*":
            out["wildcard"].append(r)
        elif r.startswith(f"{prefix}__"):
            out["scoped"].append(r)
    return out


def _legacy_allowed_tools_wildcard(server: ServerEntry) -> bool:
    """Secondary signal: the non-official ``allowed_tools`` field is present
    AND wide-open ("*" / ["*"] / empty list). Absence returns False (we do not
    flag missing — the permissions source is the authority)."""
    allowed = server.get_allowed_tools()
    if allowed is None:
        return False
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
    allow = _rules_for_server(server.allow_rules, server.name)
    deny = _rules_for_server(server.deny_rules, server.name)
    legacy_wide = _legacy_allowed_tools_wildcard(server)
    log.info(
        "[permission_scope] server=%s allow=%r deny=%r legacy_wide=%s",
        server.name, allow, deny, legacy_wide,
    )

    referenced_in_allow = bool(allow["whole"] or allow["wildcard"] or allow["scoped"])

    # --- WARN: whole server allowed indiscriminately --------------------
    if allow["whole"] or allow["wildcard"]:
        rule_str = (allow["whole"] or allow["wildcard"])[0]
        yield Finding(
            severity=Severity.WARN,
            rule="permission_scope",
            server=server.name,
            source_file=server.source_file,
            message=(
                f"every tool of server '{server.name}' is allowed "
                f"indiscriminately via permissions rule '{rule_str}'. "
                "Consider replacing it with per-tool 'mcp__"
                f"{server.name}__<tool>' entries for only the tools you use."
            ),
            details={
                "allow_rules": allow["whole"] + allow["wildcard"],
                "source": "permissions.allow",
            },
        )
        return

    # --- PASS: scoped to specific tools ---------------------------------
    if allow["scoped"]:
        log.info(
            "[permission_scope] %s: scoped to %d specific tool(s) — PASS",
            server.name, len(allow["scoped"]),
        )
        # Still surface the legacy wide-open allowed_tools as a secondary WARN
        # if present and contradictory, but the permissions source dominates.
        if legacy_wide:
            yield _legacy_finding(server)
        return

    # --- INFO: not referenced in any permissions ------------------------
    if not referenced_in_allow:
        # The legacy allowed_tools wildcard is the only signal we have here.
        if legacy_wide:
            yield _legacy_finding(server)
            return
        yield Finding(
            severity=Severity.INFO,
            rule="permission_scope",
            server=server.name,
            source_file=server.source_file,
            message=(
                f"server '{server.name}' has no explicit tool-permission "
                "entry in settings.json (permissions.allow/deny). Claude Code "
                "will prompt for confirmation each time one of its tools is "
                "called. Add 'mcp__"
                f"{server.name}__<tool>' rules to pre-authorize specific tools."
            ),
            details={"source": "permissions"},
        )


def _legacy_finding(server: ServerEntry) -> Finding:
    """Secondary-signal WARN for a wide-open non-official allowed_tools."""
    allowed = server.get_allowed_tools()
    if allowed == "*" or (isinstance(allowed, list) and any(i == "*" for i in allowed)):
        what = "'allowed_tools' contains '*'"
    else:
        what = "'allowed_tools' is empty"
    return Finding(
        severity=Severity.WARN,
        rule="permission_scope",
        server=server.name,
        source_file=server.source_file,
        message=(
            f"{what} — all tools allowed. Note: 'allowed_tools' is an "
            "mcp-audit extension convention, not an official Claude Code "
            "field; the authoritative source is settings.json "
            "permissions.allow. Consider listing only the tools you use."
        ),
        details={"allowed_tools": allowed, "source": "allowed_tools_field"},
    )
