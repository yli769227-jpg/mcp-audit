"""Tests for the analyzer pipeline — one fixture-driven test per rule.

Per spec: each rule needs a positive (fires) and a negative (does not fire)
fixture. We get both by running run_audit against each fixture dir and
asserting on the produced Finding set.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    assert "args-and-url-leaker" in rules_hit, [f.server for f in findings]
    # All must be CRITICAL.
    assert all(f.severity == Severity.CRITICAL for f in findings if f.rule == "secret_leak")


def test_secret_leak_fires_on_args_and_url():
    """Tokens passed via args and credentials embedded in url must be caught."""
    cf = parse_config_file(FIXTURES / "leaky" / ".mcp.json")
    s = next(s for s in cf.servers if s.name == "args-and-url-leaker")
    findings = list(detect_secret_leak(s, cf.servers))
    field_paths = {f.details["field_path"] for f in findings}
    # args token caught by the generic walk
    assert any(fp.startswith("args[") for fp in field_paths), field_paths
    # url userinfo + sensitive query param caught by the dedicated url check
    assert "url" in field_paths, field_paths
    assert "url?apikey" in field_paths, field_paths
    assert all(f.severity == Severity.CRITICAL for f in findings)


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
        "ghp_FIXTUREargsTOKEN999aaaBBBcccDDDee02",
        "FIXTUREurlPass123456",
        "FIXTUREqueryKEY42abcdef",
    ]
    for needle in leaked_substrings:
        assert needle not in raw_text, f"secret leaked to output: {needle}"


def test_secret_leak_does_not_fire_on_clean_fixture():
    """Clean fixture includes ${MY_API_KEY} and the long
    ${PRODUCTION_API_KEY_2026} placeholder in a secret-named field —
    env-var references are the recommended style and must never be flagged."""
    cf = parse_config_file(FIXTURES / "clean" / ".mcp.json")
    findings = []
    for s in cf.servers:
        findings.extend(detect_secret_leak(s, cf.servers))
    assert findings == [], findings


def test_secret_leak_ignores_env_var_references(tmp_path: Path):
    """${VAR} and bare $VAR references in secret-named fields are not leaks."""
    fixture = tmp_path / ".mcp.json"
    fixture.write_text(
        json.dumps({
            "mcpServers": {
                "placeholder-user": {
                    "command": "x",
                    "env": {
                        "TOKEN": "${PRODUCTION_API_KEY_2026_V2}",
                        "SECRET": "$ANOTHER_LONG_KEY_REFERENCE_2026",
                    },
                }
            }
        }),
        encoding="utf-8",
    )
    cf = parse_config_file(fixture)
    findings = []
    for s in cf.servers:
        findings.extend(detect_secret_leak(s, cf.servers))
    assert findings == [], findings


def test_secret_leak_classifies_sk_ant_as_anthropic(tmp_path: Path):
    """An sk-ant- key must be classified as anthropic_sk_ant, NOT openai_sk.

    Regression guard: the openai pattern (^sk-...) also matches sk-ant-...,
    so pattern ordering matters. We never print the value, only the pattern.
    """
    fixture = tmp_path / ".mcp.json"
    fixture.write_text(
        json.dumps({
            "mcpServers": {
                "anthropic-bridge": {
                    "command": "x",
                    "env": {
                        "ANTHROPIC_API_KEY": "sk-ant-FIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    },
                }
            }
        }),
        encoding="utf-8",
    )
    cf = parse_config_file(fixture)
    findings = list(detect_secret_leak(cf.servers[0], cf.servers))
    assert findings, "expected a secret_leak finding for the sk-ant- key"
    patterns = {f.details["pattern"] for f in findings}
    assert "anthropic_sk_ant" in patterns, patterns
    assert "openai_sk" not in patterns, patterns


# ---------- permission_scope ----------
#
# The authoritative source is settings.json permissions.allow/deny, which the
# analyzer aggregates onto each server. We drive these through run_audit (so
# the aggregation actually happens) against the `permissions` fixture:
#   - wide-server         : allowed wholesale via "mcp__wide-server"      -> WARN
#   - scoped-server       : only "mcp__scoped-server__<tool>" entries     -> PASS
#   - unconfigured-server : referenced nowhere in permissions             -> INFO


def _permission_findings_by_server(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))  # isolate from real ~/.claude
    result = run_audit(start=FIXTURES / "permissions")
    out: dict[str, list] = {}
    for f in result.findings:
        if f.rule == "permission_scope":
            out.setdefault(f.server, []).append(f)
    return out


def test_permission_scope_whole_server_allowed_is_warn(tmp_path, monkeypatch):
    by_server = _permission_findings_by_server(monkeypatch, tmp_path)
    assert "wide-server" in by_server, by_server
    f = by_server["wide-server"][0]
    assert f.severity == Severity.WARN
    assert "indiscriminately" in f.message
    assert f.details["source"] == "permissions.allow"


def test_permission_scope_scoped_server_passes(tmp_path, monkeypatch):
    by_server = _permission_findings_by_server(monkeypatch, tmp_path)
    # PASS = no permission_scope finding at all for this server.
    assert "scoped-server" not in by_server, by_server.get("scoped-server")


def test_permission_scope_unconfigured_server_is_info(tmp_path, monkeypatch):
    by_server = _permission_findings_by_server(monkeypatch, tmp_path)
    assert "unconfigured-server" in by_server, by_server
    f = by_server["unconfigured-server"][0]
    assert f.severity == Severity.INFO
    assert "no explicit tool-permission" in f.message
    assert "prompt" in f.message


def test_permission_scope_wildcard_rule_is_warn(tmp_path, monkeypatch):
    """An "mcp__<server>__*" wildcard in allow must WARN like a whole-server grant."""
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"star": {"command": "x"}}}), encoding="utf-8"
    )
    (proj / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["mcp__star__*"], "deny": []}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    result = run_audit(start=proj)
    perm = [f for f in result.findings if f.rule == "permission_scope" and f.server == "star"]
    assert perm, result.findings
    assert perm[0].severity == Severity.WARN


def test_permission_scope_legacy_allowed_tools_wildcard_still_warns():
    """Secondary signal: a wide-open non-official allowed_tools field still
    WARNs even with no settings.json permissions present (isolated parse)."""
    cf = parse_config_file(FIXTURES / "wildcard" / ".mcp.json")
    s = next(s for s in cf.servers if s.name == "wide-open")
    findings = list(detect_permission_scope(s, cf.servers))
    assert findings
    assert findings[0].severity == Severity.WARN
    assert "allowed_tools" in findings[0].message


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


def test_dormant_info_when_no_signal():
    """No reliable last-used source exists in real Claude Code, so the
    honest answer for a server with no explicit last_used is INFO (not a
    scary UNKNOWN/WARN), with a message explaining the limitation."""
    cf = parse_config_file(FIXTURES / "dormant" / ".mcp.json")
    no_sig = next(s for s in cf.servers if s.name == "no-signal-server")
    findings = list(detect_dormant(no_sig, cf.servers))
    assert findings, "expected an INFO finding when no signal exists"
    assert findings[0].severity == Severity.INFO
    assert "cannot be determined" in findings[0].message


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
    # Claude Code precedence for same-named servers is local > project > user.
    assert "local > project > user" in findings[0].message, findings[0].message


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
