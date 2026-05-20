"""Detect MCP servers that look dormant (>30 days unused).

The MCP spec does NOT standardize "last used" anywhere. We try three signals,
in order of confidence, and we are honest about UNKNOWN when none of them
fire:

1. ``raw.last_used`` (ISO-8601 string) — if the user / Claude wrote it,
   trust it.
2. ``~/.claude/cache/mcp_<server>/last_activity`` mtime — best-effort
   external signal.
3. Nothing → severity UNKNOWN, message explains there's no way to tell.

We deliberately do NOT silently say "looks fine" when we have no data — that
would be lying to the user. UNKNOWN is a real status here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
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


def _cache_last_activity(server_name: str) -> datetime | None:
    """Look for an external mtime signal under ~/.claude/cache/.

    This is the ONLY filesystem read we do outside discovery, and it's still
    confined to ~/.claude/.
    """
    candidates = [
        Path.home() / ".claude" / "cache" / f"mcp_{server_name}" / "last_activity",
        Path.home() / ".claude" / "cache" / "mcp" / server_name / "last_activity",
    ]
    for p in candidates:
        try:
            if p.is_file():
                ts = p.stat().st_mtime
                return datetime.fromtimestamp(ts, tz=timezone.utc)
        except OSError as e:
            log.warning("[dormant] cannot stat %s: %s", p, e)
    return None


def _last_seen(server: ServerEntry) -> tuple[datetime | None, str]:
    """Return (timestamp, signal_name) or (None, 'none')."""
    raw_last = server.raw.get("last_used") or server.raw.get("lastUsed")
    if isinstance(raw_last, str):
        dt = _parse_iso(raw_last)
        if dt is not None:
            return dt, "config.last_used"

    dt = _cache_last_activity(server.name)
    if dt is not None:
        return dt, "cache.last_activity"

    return None, "none"


def detect_dormant(
    server: ServerEntry, all_servers: list[ServerEntry]
) -> Iterable[Finding]:
    log.info("[dormant] checking server=%s", server.name)
    dt, signal = _last_seen(server)

    if dt is None:
        log.info("[dormant] %s: no signal — UNKNOWN", server.name)
        yield Finding(
            severity=Severity.UNKNOWN,
            rule="dormant",
            server=server.name,
            source_file=server.source_file,
            message=(
                "no last-used signal available. MCP does not standardize this; "
                "consider running `claude mcp list` or check the server's own logs."
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
