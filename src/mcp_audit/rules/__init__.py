"""Detection rules for mcp-audit.

Each rule is a callable ``(server, all_servers) -> Iterable[Finding]``.
Rules are pure functions: they may NOT do I/O except read-only stat of
well-known paths (see dormant.py for the one allowed exception).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable

# Forward import-only types — parser imports rules lazily through the
# analyzer, so a direct import here is fine.
from ..parser import ServerEntry


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARN = "WARN"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    """A single audit finding. NEVER contains a secret value."""

    severity: Severity
    rule: str
    server: str
    source_file: Path
    message: str
    # Optional, e.g. line number / field name / char count
    details: dict[str, object] = field(default_factory=dict)


# A rule takes a single server entry plus the full list (so it can do
# cross-server checks like duplicate detection) and yields findings.
Rule = Callable[[ServerEntry, list[ServerEntry]], Iterable[Finding]]


def all_rules() -> list[tuple[str, Rule]]:
    """Return all built-in rules, in display order."""
    # Imported here to avoid circular imports at module load time.
    from .secret_leak import detect_secret_leak
    from .dormant import detect_dormant
    from .overlap import detect_overlap
    from .permission_scope import detect_permission_scope

    return [
        ("secret_leak", detect_secret_leak),
        ("permission_scope", detect_permission_scope),
        ("overlap", detect_overlap),
        ("dormant", detect_dormant),
    ]
