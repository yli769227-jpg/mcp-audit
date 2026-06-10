"""Render an AuditResult as rich text / JSON / markdown."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from io import StringIO
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import AuditResult
from .rules import Finding, Severity
from .rules.secret_leak import value_matches_secret_pattern

log = logging.getLogger("mcp_audit.reporter")


def _redact_args(args: list[str]) -> list[str]:
    """Replace any arg element that looks like a credential with ***(N chars).

    HARD RULE: reports must never contain a secret value, including secrets
    smuggled in via ``args``. We reuse the secret_leak detection so the rule
    and the redaction can never drift apart.
    """
    redacted: list[str] = []
    for a in args:
        if isinstance(a, str) and value_matches_secret_pattern(a):
            log.info("[reporter] redacting credential-looking arg (%d chars)", len(a))
            redacted.append(f"***({len(a)} chars)")
        else:
            redacted.append(a)
    return redacted


_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "cyan",
    Severity.UNKNOWN: "dim",
}

_SEV_GLYPH = {
    Severity.CRITICAL: "✗",
    Severity.WARN: "!",
    Severity.INFO: "i",
    Severity.UNKNOWN: "?",
}


def render_text(result: AuditResult, console: Console | None = None) -> str:
    """Render to a colorized terminal report. Returns the captured string too,
    so tests can assert on it without a real terminal."""
    buf = StringIO()
    if console is None:
        console = Console(file=buf, force_terminal=False, width=100)

    # ----- Header -----
    sev_counts = _count_by_severity(result.findings)
    summary = (
        f"[bold]{result.config_count}[/bold] config file(s) | "
        f"[bold]{result.server_count}[/bold] MCP server(s) | "
        f"[bold red]{sev_counts[Severity.CRITICAL]} critical[/bold red] | "
        f"[bold yellow]{sev_counts[Severity.WARN]} warn[/bold yellow] | "
        f"[dim]{sev_counts[Severity.UNKNOWN]} unknown[/dim]"
    )
    console.print(Panel(summary, title="mcp-audit", expand=False))

    # ----- Config files table -----
    if result.config_files:
        table = Table(title="Discovered config files", show_lines=False)
        table.add_column("Scope", style="cyan", no_wrap=True)
        table.add_column("Path", overflow="fold")
        table.add_column("Servers", justify="right")
        table.add_column("Notes", style="dim")
        for cf in result.config_files:
            notes = cf.parse_error or ""
            table.add_row(
                cf.scope,
                str(_short_path(cf.path)),
                str(len(cf.servers)),
                notes,
            )
        console.print(table)
    else:
        console.print("[dim]No MCP config files found.[/dim]")

    # ----- Servers table -----
    if result.servers:
        srv_table = Table(title="MCP servers", show_lines=False)
        srv_table.add_column("Name", style="bold")
        srv_table.add_column("Scope", style="cyan")
        srv_table.add_column("Command", overflow="fold")
        srv_table.add_column("Source", style="dim", overflow="fold")
        for s in result.servers:
            cmd = s.get_command() or "(none)"
            args = " ".join(_redact_args(s.get_args()))
            full_cmd = f"{cmd} {args}".strip()
            srv_table.add_row(
                s.name, s.scope, full_cmd, str(_short_path(s.source_file)),
            )
        console.print(srv_table)

    # ----- Findings table -----
    if result.findings:
        f_table = Table(title="Findings", show_lines=True)
        f_table.add_column("Sev", no_wrap=True)
        f_table.add_column("Rule", style="cyan", no_wrap=True)
        f_table.add_column("Server", style="bold")
        f_table.add_column("Where", style="dim", overflow="fold")
        f_table.add_column("Message", overflow="fold")
        for f in sorted(
            result.findings,
            key=lambda x: (_sev_sort(x.severity), x.rule, x.server),
        ):
            style = _SEV_STYLE[f.severity]
            glyph = _SEV_GLYPH[f.severity]
            sev_cell = Text(f"{glyph} {f.severity.value}", style=style)
            where = str(_short_path(f.source_file))
            if "line" in f.details and f.details["line"]:
                where += f":{f.details['line']}"
            f_table.add_row(sev_cell, f.rule, f.server, where, f.message)
        console.print(f_table)
    else:
        if result.servers:
            console.print("[green]No findings. Looks clean.[/green]")

    return buf.getvalue()


def render_json(result: AuditResult) -> str:
    payload: dict[str, Any] = {
        "summary": {
            "config_files": result.config_count,
            "servers": result.server_count,
            "findings": len(result.findings),
            "by_severity": {
                k.value: v for k, v in _count_by_severity(result.findings).items()
            },
        },
        "config_files": [
            {
                "path": str(cf.path),
                "scope": cf.scope,
                "server_count": len(cf.servers),
                "parse_error": cf.parse_error,
            }
            for cf in result.config_files
        ],
        "servers": [
            {
                "name": s.name,
                "scope": s.scope,
                "source_file": str(s.source_file),
                "command": s.get_command(),
                "args": _redact_args(s.get_args()),
            }
            for s in result.servers
        ],
        "findings": [
            {
                "severity": f.severity.value,
                "rule": f.rule,
                "server": f.server,
                "source_file": str(f.source_file),
                "message": f.message,
                "details": {
                    k: (str(v) if isinstance(v, Path) else v)
                    for k, v in f.details.items()
                },
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(result: AuditResult) -> str:
    sev_counts = _count_by_severity(result.findings)
    lines: list[str] = []
    lines.append("# mcp-audit report")
    lines.append("")
    lines.append(
        f"**{result.config_count}** config file(s) · "
        f"**{result.server_count}** MCP server(s) · "
        f"**{sev_counts[Severity.CRITICAL]}** critical · "
        f"**{sev_counts[Severity.WARN]}** warn · "
        f"**{sev_counts[Severity.UNKNOWN]}** unknown"
    )
    lines.append("")

    lines.append("## Discovered config files")
    lines.append("")
    if result.config_files:
        lines.append("| Scope | Path | Servers | Notes |")
        lines.append("|---|---|---:|---|")
        for cf in result.config_files:
            lines.append(
                f"| {cf.scope} | `{_short_path(cf.path)}` | {len(cf.servers)} | {cf.parse_error or ''} |"
            )
    else:
        lines.append("_No config files found._")
    lines.append("")

    lines.append("## MCP servers")
    lines.append("")
    if result.servers:
        lines.append("| Name | Scope | Command | Source |")
        lines.append("|---|---|---|---|")
        for s in result.servers:
            cmd = s.get_command() or "(none)"
            args = " ".join(_redact_args(s.get_args()))
            full = f"`{cmd} {args}`".strip()
            lines.append(
                f"| **{s.name}** | {s.scope} | {full} | `{_short_path(s.source_file)}` |"
            )
    else:
        lines.append("_No MCP servers configured._")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("_No findings. Looks clean._")
    else:
        lines.append("| Severity | Rule | Server | Where | Message |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(
            result.findings,
            key=lambda x: (_sev_sort(x.severity), x.rule, x.server),
        ):
            where = f"`{_short_path(f.source_file)}`"
            if "line" in f.details and f.details["line"]:
                where += f":{f.details['line']}"
            lines.append(
                f"| {f.severity.value} | {f.rule} | {f.server} | {where} | {f.message} |"
            )
    lines.append("")
    return "\n".join(lines)


# ----- helpers -----


def _count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _sev_sort(s: Severity) -> int:
    order = {
        Severity.CRITICAL: 0,
        Severity.WARN: 1,
        Severity.INFO: 2,
        Severity.UNKNOWN: 3,
    }
    return order.get(s, 99)


def _short_path(p: Path) -> str:
    """Render path with ~ for home dir when applicable."""
    try:
        home = Path.home()
        if p.is_absolute() and p.is_relative_to(home):
            return "~/" + str(p.relative_to(home))
    except (AttributeError, ValueError):
        pass
    return str(p)
