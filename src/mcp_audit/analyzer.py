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
