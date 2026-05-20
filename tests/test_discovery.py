"""Tests for the discovery module."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.discovery import discover_configs


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
