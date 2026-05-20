"""Find MCP config files on disk.

Hard rule: we ONLY look in ``~/.claude/`` and the explicit ``cwd`` argument
(plus up to 5 ancestor dirs of cwd). We never read ``~/.ssh/``, ``~/.aws/``,
etc. — see CLAUDE.md / project spec.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("mcp_audit.discovery")

# Known filenames within ~/.claude/
_HOME_CLAUDE_FILES = (
    "mcp.json",
    "settings.json",
    "settings.local.json",
)

# Project-level filenames we look for at cwd and each ancestor
_PROJECT_FILES = (
    ".mcp.json",
)

# Within a project dir, also check .claude/settings.json etc.
_PROJECT_CLAUDE_FILES = (
    "settings.json",
    "settings.local.json",
)

_MAX_ANCESTORS = 5


def discover_configs(start: Path | None = None) -> list[Path]:
    """Return a list of existing config file paths to audit.

    Parameters
    ----------
    start:
        If provided, this is the path to walk up from for project configs.
        If None, we use ``Path.cwd()`` for project discovery. Either way we
        still check ``~/.claude/``.

    The returned list is deduplicated and sorted for deterministic output.
    """
    found: set[Path] = set()

    # ----- User-level: ~/.claude/ -----
    home_claude = Path.home() / ".claude"
    log.info("[discovery] scanning user config dir: %s", home_claude)
    if home_claude.is_dir():
        for name in _HOME_CLAUDE_FILES:
            p = home_claude / name
            if p.is_file():
                log.info("[discovery] found user config: %s", p)
                found.add(p.resolve())

    # ----- Project-level: cwd and ancestors -----
    base = (start if start is not None else Path.cwd()).resolve()
    log.info("[discovery] scanning project tree starting at: %s", base)

    # If user passed a file directly, just use that and stop.
    if base.is_file():
        log.info("[discovery] explicit file path: %s", base)
        found.add(base)
        return sorted(found)

    # If user passed a non-existent path, treat it as empty (don't crash).
    if not base.exists():
        log.warning("[discovery] path does not exist: %s", base)
        return sorted(found)

    current = base
    for depth in range(_MAX_ANCESTORS + 1):
        log.info("[discovery] checking depth=%d: %s", depth, current)
        for name in _PROJECT_FILES:
            p = current / name
            if p.is_file():
                log.info("[discovery] found project config: %s", p)
                found.add(p.resolve())

        claude_dir = current / ".claude"
        if claude_dir.is_dir():
            for name in _PROJECT_CLAUDE_FILES:
                p = claude_dir / name
                if p.is_file():
                    log.info("[discovery] found project .claude config: %s", p)
                    found.add(p.resolve())

        if current.parent == current:
            break  # reached filesystem root
        current = current.parent

    log.info("[discovery] total configs found: %d", len(found))
    return sorted(found)
