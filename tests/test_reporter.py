"""Tests for the reporter — text/JSON/markdown rendering must be safe."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.analyzer import run_audit
from mcp_audit.reporter import render_json, render_markdown, render_text


FIXTURES = Path(__file__).parent / "fixtures"


def test_text_render_does_not_leak_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "leaky")
    out = render_text(result)
    for secret in [
        "ghp_FIXTUREabc123DEF456ghi789JKL012mn01",
        "sk-proj-FIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]:
        assert secret not in out, f"secret leaked to text output: {secret}"


def test_json_render_does_not_leak_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "leaky")
    out = render_json(result)
    # Should be valid JSON.
    parsed = json.loads(out)
    assert "findings" in parsed
    for secret in [
        "ghp_FIXTUREabc123DEF456ghi789JKL012mn01",
        "sk-proj-FIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]:
        assert secret not in out, f"secret leaked to JSON output: {secret}"


def test_markdown_render_does_not_leak_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "leaky")
    out = render_markdown(result)
    for secret in [
        "ghp_FIXTUREabc123DEF456ghi789JKL012mn01",
        "sk-proj-FIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]:
        assert secret not in out, f"secret leaked to markdown output: {secret}"


def test_text_render_on_clean_fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "clean")
    out = render_text(result)
    assert "filesystem" in out
    assert "fetch" in out


def test_json_summary_counts_match_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "leaky")
    out = render_json(result)
    parsed = json.loads(out)
    by_sev = parsed["summary"]["by_severity"]
    assert by_sev["CRITICAL"] >= 1
    assert parsed["summary"]["servers"] == result.server_count
