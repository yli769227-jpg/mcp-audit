"""Tests for the discovery module."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.discovery import discover_configs
from mcp_audit.parser import parse_config_file


FIXTURES = Path(__file__).parent / "fixtures"


def test_finds_dot_mcp_in_explicit_dir():
    found = discover_configs(FIXTURES / "clean")
    found_names = [p.name for p in found]
    assert any(p.name == ".mcp.json" for p in found), found_names


def test_walks_up_ancestors(tmp_path: Path):
    # Place .mcp.json at parent, run from child — must be discovered.
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    child = tmp_path / "a" / "b" / "c"
    child.mkdir(parents=True)
    found = discover_configs(child)
    # ~/.claude/ entries may also be present in real env; we only assert ours.
    assert any(str(p).endswith(str(tmp_path / ".mcp.json")) for p in found), found


def test_nonexistent_path_does_not_crash(tmp_path: Path):
    bogus = tmp_path / "no-such-dir"
    # Must not raise.
    discover_configs(bogus)


def test_dedup_and_sorted(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    found = discover_configs(tmp_path)
    assert found == sorted(found)
    assert len(found) == len(set(found))


def test_explicit_file_path_returned(tmp_path: Path):
    f = tmp_path / "custom.json"
    f.write_text('{"mcpServers": {}}', encoding="utf-8")
    found = discover_configs(f)
    assert f.resolve() in found


# ---------- ~/.claude.json (Claude Code main state file) ----------

def _write_claude_json(home: Path) -> Path:
    """Synthesize a realistic ~/.claude.json: user scope at top level,
    local scope under projects.*, plus plenty of unrelated state."""
    p = home / ".claude.json"
    p.write_text(
        json.dumps({
            "numStartups": 42,
            "tipsHistory": {"some-tip": 3},
            "mcpServers": {
                "user-scoped": {"command": "npx", "args": ["@example/user-mcp"]}
            },
            "projects": {
                "/Users/someone/proj-a": {
                    "allowedTools": [],
                    "history": ["irrelevant"],
                    "mcpServers": {
                        "local-scoped": {"command": "uvx", "args": ["local-mcp"]}
                    },
                },
                "/Users/someone/proj-b": {
                    "history": []
                },
            },
        }),
        encoding="utf-8",
    )
    return p


def test_discovers_home_claude_json(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    p = _write_claude_json(tmp_path)
    found = discover_configs(tmp_path)
    assert p.resolve() in found, found


def test_parses_claude_json_user_and_local_scopes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    p = _write_claude_json(tmp_path)
    cf = parse_config_file(p)
    assert cf.parse_error is None
    by_name = {s.name: s for s in cf.servers}
    assert set(by_name) == {"user-scoped", "local-scoped"}
    assert by_name["user-scoped"].scope == "user"
    assert by_name["local-scoped"].scope == "local"


def test_broken_claude_json_does_not_crash(tmp_path: Path, monkeypatch):
    """Read-only audit tool: one bad ~/.claude.json must not take down the run."""
    monkeypatch.setenv("HOME", str(tmp_path))
    p = tmp_path / ".claude.json"
    p.write_text('{"mcpServers": "not-an-object", "projects": [1, 2]}', encoding="utf-8")
    cf = parse_config_file(p)  # must not raise
    assert cf.servers == []
    bad = tmp_path / ".claude.json"
    bad.write_text("{ totally broken", encoding="utf-8")
    cf = parse_config_file(bad)  # must not raise
    assert cf.parse_error is not None
