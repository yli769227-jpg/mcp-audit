"""Tests for the CLI --fail-on exit-code policy.

The exit code is the contract CI relies on, so it must be pinned down:

- critical finding + --fail-on critical  -> exit != 0
- clean tree    + --fail-on warn      -> exit 0
- critical finding + --fail-on none      -> exit 0 (never fails)
- warn finding   + --fail-on warn      -> exit != 0

We isolate HOME to an empty temp dir so the user's real ~/.claude/ never
influences the result.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from mcp_audit.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_fail_on_critical_exits_nonzero_when_critical(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--path", str(FIXTURES / "leaky"), "--fail-on", "critical",
         "--format", "json"],
    )
    assert result.exit_code != 0, result.output


def test_fail_on_warn_exits_zero_when_clean(tmp_path, monkeypatch):
    # Point at an empty dir (no .mcp.json anywhere) with an isolated HOME so
    # there are zero findings.
    empty = tmp_path / "empty-project"
    empty.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "fake-home"))
    (tmp_path / "fake-home").mkdir()
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--path", str(empty), "--fail-on", "warn", "--format", "json"],
    )
    assert result.exit_code == 0, result.output


def test_fail_on_none_never_fails_even_with_critical(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--path", str(FIXTURES / "leaky"), "--fail-on", "none",
         "--format", "json"],
    )
    assert result.exit_code == 0, result.output


def test_fail_on_warn_exits_nonzero_when_warn(tmp_path, monkeypatch):
    # wildcard fixture yields WARN (wide-open allowed_tools) but no CRITICAL.
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--path", str(FIXTURES / "wildcard"), "--fail-on", "warn",
         "--format", "json"],
    )
    assert result.exit_code != 0, result.output
