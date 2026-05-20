"""Tests for the analyzer pipeline — one fixture-driven test per rule.

Per spec: each rule needs a positive (fires) and a negative (does not fire)
fixture. We get both by running run_audit against each fixture dir and
asserting on the produced Finding set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.analyzer import run_audit
from mcp_audit.parser import parse_config_file
from mcp_audit.rules import Severity
from mcp_audit.rules.dormant import detect_dormant
from mcp_audit.rules.overlap import detect_overlap
from mcp_audit.rules.permission_scope import detect_permission_scope
from mcp_audit.rules.secret_leak import detect_secret_leak


FIXTURES = Path(__file__).parent / "fixtures"


# ---------- secret_leak ----------

def test_secret_leak_fires_on_leaky_fixture():
    cf = parse_config_file(FIXTURES / "leaky" / ".mcp.json")
    findings = []
    for s in cf.servers:
        findings.extend(detect_secret_leak(s, cf.servers))
    rules_hit = {f.server: f for f in findings}
    assert "github" in rules_hit, [f.server for f in findings]
    assert "openai-bridge" in rules_hit, [f.server for f in findings]
    assert "internal-api" in rules_hit, [f.server for f in findings]
    # All three must be CRITICAL.
    assert all(f.severity == Severity.CRITICAL for f in findings if f.rule == "secret_leak")


def test_secret_leak_does_not_print_secret_value():
    """HARD RULE: the leaked value must never appear in any finding output."""
    cf = parse_config_file(FIXTURES / "leaky" / ".mcp.json")
    findings = []
    for s in cf.servers:
        findings.extend(detect_secret_leak(s, cf.servers))
    raw_text = json.dumps([{"msg": f.message, "details": str(f.details)} for f in findings])
    leaked_substrings = [
        "ghp_FIXTUREabc123DEF456ghi789JKL012mn01",
        "sk-proj-FIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "eyJhbGciOiJIUzI1NiJ9.fakefakefakefakefake.signaturepartheretoo",
    ]
    for needle in leaked_substrings:
        assert needle not in raw_text, f"secret leaked to output: {needle}"


def test_secret_leak_does_not_fire_on_clean_fixture():
    cf = parse_config_file(FIXTURES / "clean" / ".mcp.json")
    findings = []
    for s in cf.servers:
        findings.extend(detect_secret_leak(s, cf.servers))
    assert findings == [], findings


# ---------- permission_scope ----------

@pytest.mark.parametrize(
    "server_name,should_fire",
    [
        ("wide-open", True),
        ("wide-open-list", True),
        ("missing-allowed-tools", True),
        ("scoped-ok", False),
    ],
)
def test_permission_scope(server_name: str, should_fire: bool):
    cf = parse_config_file(FIXTURES / "wildcard" / ".mcp.json")
    s = next(s for s in cf.servers if s.name == server_name)
    findings = list(detect_permission_scope(s, cf.servers))
    if should_fire:
        assert findings, f"expected finding for {server_name}"
        assert findings[0].severity == Severity.WARN
    else:
        assert findings == [], findings


# ---------- dormant ----------

def test_dormant_fires_on_old_last_used():
    cf = parse_config_file(FIXTURES / "dormant" / ".mcp.json")
    old = next(s for s in cf.servers if s.name == "old-server")
    findings = list(detect_dormant(old, cf.servers))
    assert findings, "expected dormant finding"
    assert findings[0].severity == Severity.WARN


def test_dormant_silent_on_fresh_last_used(tmp_path: Path):
    """A freshly-used server must NOT trip dormant. We synthesize a current
    timestamp here so the test isn't time-locked to a fixture file."""
    from datetime import datetime, timezone
    now_iso = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    fixture = tmp_path / ".mcp.json"
    fixture.write_text(
        json.dumps({
            "mcpServers": {
                "fresh": {
                    "command": "x",
                    "last_used": now_iso,
                    "allowed_tools": ["t"],
                }
            }
        }),
        encoding="utf-8",
    )
    cf = parse_config_file(fixture)
    s = cf.servers[0]
    findings = list(detect_dormant(s, cf.servers))
    assert findings == [], findings


def test_dormant_unknown_when_no_signal():
    cf = parse_config_file(FIXTURES / "dormant" / ".mcp.json")
    no_sig = next(s for s in cf.servers if s.name == "no-signal-server")
    findings = list(detect_dormant(no_sig, cf.servers))
    assert findings, "expected an UNKNOWN finding when no signal exists"
    assert findings[0].severity == Severity.UNKNOWN


# ---------- overlap ----------

def test_overlap_fires_across_files(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"mcpServers": {"foo": {"command": "x"}}}), encoding="utf-8")
    b.write_text(json.dumps({"mcpServers": {"foo": {"command": "y"}}}), encoding="utf-8")
    cf_a = parse_config_file(a)
    cf_b = parse_config_file(b)
    all_servers = cf_a.servers + cf_b.servers
    findings = []
    for s in all_servers:
        findings.extend(detect_overlap(s, all_servers))
    assert len(findings) == 1, findings  # only first occurrence emits
    assert findings[0].severity == Severity.WARN
    assert findings[0].server == "foo"


def test_overlap_silent_when_unique(tmp_path: Path):
    p = tmp_path / "x.json"
    p.write_text(
        json.dumps({"mcpServers": {"only": {"command": "x"}}}),
        encoding="utf-8",
    )
    cf = parse_config_file(p)
    findings = []
    for s in cf.servers:
        findings.extend(detect_overlap(s, cf.servers))
    assert findings == [], findings


# ---------- end-to-end run_audit ----------

def test_run_audit_smoke_on_leaky(tmp_path: Path, monkeypatch):
    """End-to-end: pointing at leaky fixture must yield at least 1 CRITICAL."""
    # Isolate from user's real ~/.claude/ to keep test deterministic.
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "leaky")
    sev = {Severity.CRITICAL: 0, Severity.WARN: 0, Severity.UNKNOWN: 0, Severity.INFO: 0}
    for f in result.findings:
        sev[f.severity] += 1
    assert sev[Severity.CRITICAL] >= 1, sev
    assert result.server_count >= 3


def test_run_audit_handles_broken_json(tmp_path: Path, monkeypatch):
    """A broken JSON file must not crash the run."""
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_audit(start=FIXTURES / "broken")
    # Must have recorded the parse error, not crashed.
    assert any(cf.parse_error for cf in result.config_files)
