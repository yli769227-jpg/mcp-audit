"""Top-level orchestration: discover -> parse -> run rules."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from .discovery import discover_configs
from .parser import ConfigFile, ServerEntry, parse_config_file
from .rules import Finding, all_rules

log = logging.getLogger("mcp_audit.analyzer")


@dataclass
class AuditResult:
    config_files: list[ConfigFile] = field(default_factory=list)
    servers: list[ServerEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def config_count(self) -> int:
        return len(self.config_files)


def run_audit(start: Path | None = None) -> AuditResult:
    """Discover configs, parse them, run all rules, return a result."""
    log.info("[analyzer] starting audit; start=%s", start)
    paths = discover_configs(start)
    log.info("[analyzer] discovered %d config files", len(paths))

    result = AuditResult()
    for p in paths:
        cf = parse_config_file(p)
        result.config_files.append(cf)
        result.servers.extend(cf.servers)

    log.info(
        "[analyzer] parsed %d servers across %d files",
        len(result.servers), len(result.config_files),
    )

    # Aggregate tool-permission rules (settings.json permissions.allow/deny)
    # from ALL discovered config files and attach to every server, so the
    # permission_scope rule — which only gets (server, all_servers) — can see
    # the real Claude Code permission source regardless of which file it came
    # from. Deduplicated, order-preserving.
    all_allow: list[str] = []
    all_deny: list[str] = []
    for cf in result.config_files:
        all_allow.extend(cf.allow_rules)
        all_deny.extend(cf.deny_rules)
    all_allow = list(dict.fromkeys(all_allow))
    all_deny = list(dict.fromkeys(all_deny))
    log.info(
        "[analyzer] aggregated permissions: allow=%d deny=%d",
        len(all_allow), len(all_deny),
    )
    for server in result.servers:
        server.allow_rules = all_allow
        server.deny_rules = all_deny

    rules = all_rules()
    for server in result.servers:
        for rule_name, rule_fn in rules:
            try:
                for finding in rule_fn(server, result.servers):
                    result.findings.append(finding)
            except Exception as e:  # never let one bad rule crash the run
                log.exception(
                    "[analyzer] rule %s crashed on server %s: %s",
                    rule_name, server.name, e,
                )

    log.info("[analyzer] total findings: %d", len(result.findings))
    return result
