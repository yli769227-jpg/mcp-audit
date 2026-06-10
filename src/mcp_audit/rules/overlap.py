"""Detect same-named MCP server defined in multiple scopes.

If a server named ``foo`` exists in both ``~/.claude/settings.json`` and a
project's ``.mcp.json``, the project copy will shadow the user copy — Claude
Code resolves same-named servers with precedence local > project > user.
This is usually intentional but easy to lose track of, so we WARN once per
server.

We attach the finding to the *first* occurrence so we don't double-report.
"""

from __future__ import annotations

import logging
from typing import Iterable

from ..parser import ServerEntry
from . import Finding, Severity

log = logging.getLogger("mcp_audit.rules.overlap")


def detect_overlap(
    server: ServerEntry, all_servers: list[ServerEntry]
) -> Iterable[Finding]:
    same_name = [s for s in all_servers if s.name == server.name]
    if len(same_name) < 2:
        return

    # Only emit the finding for the first occurrence to avoid N duplicate
    # warnings. "First" = same identity object in the all_servers list.
    if same_name[0] is not server:
        return

    locations = [
        {"file": str(s.source_file), "scope": s.scope} for s in same_name
    ]
    log.info(
        "[overlap] %s defined in %d places: %s",
        server.name, len(same_name), [l["scope"] for l in locations],
    )
    yield Finding(
        severity=Severity.WARN,
        rule="overlap",
        server=server.name,
        source_file=server.source_file,
        message=(
            f"server '{server.name}' is defined in {len(same_name)} places. "
            "The higher-precedence scope (local > project > user) wins; "
            "the others are shadowed and silently ignored."
        ),
        details={"locations": locations},
    )
