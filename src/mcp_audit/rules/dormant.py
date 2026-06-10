"""Detect MCP servers that look dormant (>30 days unused).

HONESTY NOTE (best-effort by design):
Claude Code does NOT record a reliable "last used" timestamp for MCP servers
anywhere we can read. There is no documented per-server last-activity file
under ``~/.claude/``. So this rule cannot truly measure dormancy in a normal
install — it would be lying to claim otherwise.

What we actually do:

1. If the config carries an explicit ``last_used`` / ``lastUsed`` ISO-8601
   string (an mcp-audit opt-in convention, or something a user/tooling
   wrote), trust it and compute age → WARN when older than the threshold,
   silent when fresh.
2. Otherwise we have no signal → emit an INFO that honestly states dormancy
   cannot be determined, rather than a scary UNKNOWN/WARN. The README
   documents this as a best-effort limitation.

We deliberately do NOT invent a filesystem signal that doesn't exist.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from ..parser import ServerEntry
from . import Finding, Severity

log = logging.getLogger("mcp_audit.rules.dormant")

DORMANT_THRESHOLD_DAYS = 30


def _parse_iso(value: str) -> datetime | None:
    try:
        # Accept both "Z" and offset-aware ISO strings.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _last_seen(server: ServerEntry) -> tuple[datetime | None, str]:
    """Return (timestamp, signal_name) or (None, 'none').

    The only signal we trust is an explicit ``last_used`` string in the
    config. Claude Code exposes no reliable last-activity file, so we do not
    pretend to read one.
    """
    raw_last = server.raw.get("last_used") or server.raw.get("lastUsed")
    if isinstance(raw_last, str):
        dt = _parse_iso(raw_last)
        if dt is not None:
            return dt, "config.last_used"

    return None, "none"


def detect_dormant(
    server: ServerEntry, all_servers: list[ServerEntry]
) -> Iterable[Finding]:
    log.info("[dormant] checking server=%s", server.name)
    dt, signal = _last_seen(server)

    if dt is None:
        log.info(
            "[dormant] %s: no last_used signal — INFO (best-effort limitation)",
            server.name,
        )
        yield Finding(
            severity=Severity.INFO,
            rule="dormant",
            server=server.name,
            source_file=server.source_file,
            message=(
                "dormancy cannot be determined: Claude Code does not record a "
                "reliable per-server last-used timestamp, and this config has "
                "no explicit 'last_used' field. To check usage manually, run "
                "`claude mcp list` or inspect the server's own logs."
            ),
            details={"signal": signal},
        )
        return

    now = datetime.now(tz=timezone.utc)
    age_days = (now - dt).days
    log.info(
        "[dormant] %s: signal=%s age_days=%d threshold=%d",
        server.name, signal, age_days, DORMANT_THRESHOLD_DAYS,
    )

    if age_days > DORMANT_THRESHOLD_DAYS:
        yield Finding(
            severity=Severity.WARN,
            rule="dormant",
            server=server.name,
            source_file=server.source_file,
            message=(
                f"server appears dormant: last activity {age_days} days ago "
                f"(signal: {signal}). Consider removing if unused."
            ),
            details={"signal": signal, "age_days": age_days, "last_seen": dt.isoformat()},
        )
