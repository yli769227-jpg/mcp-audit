"""Command-line interface for mcp-audit.

Entry point ``mcp-audit`` is wired via ``pyproject.toml`` -> ``main``.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .analyzer import run_audit
from .reporter import render_json, render_markdown, render_text
from .rules import Severity


def _configure_logging(verbose: bool) -> None:
    """Configure logging. Default is WARNING (silent unless something is wrong)."""
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


@click.group(
    help="Audit your Claude Code MCP servers: leaked keys, dormant servers, "
         "and overly-permissive configs. Read-only, offline, paranoid by default.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="mcp-audit")
def main() -> None:
    pass


@main.command("scan", help="Scan MCP configs and print an audit report.")
@click.option(
    "--path",
    "path_str",
    type=click.Path(path_type=str),  # don't require existence — we report it
    default=None,
    help="Project path to scan (default: current working directory). "
         "~/.claude/ is always scanned regardless.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "markdown"], case_sensitive=False),
    default="text",
    help="Output format.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "warn", "none"], case_sensitive=False),
    default="critical",
    help="Exit code != 0 when findings of this severity or worse are present.",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging to stderr.")
def scan(path_str: str | None, fmt: str, fail_on: str, verbose: bool) -> None:
    _configure_logging(verbose)
    log = logging.getLogger("mcp_audit.cli")

    start = Path(path_str).expanduser() if path_str else None
    log.info("[cli] scan start=%s format=%s fail_on=%s", start, fmt, fail_on)

    result = run_audit(start=start)

    fmt = fmt.lower()
    if fmt == "json":
        click.echo(render_json(result))
    elif fmt == "markdown":
        click.echo(render_markdown(result))
    else:
        # text: render through a real terminal-aware console
        console = Console()
        render_text(result, console=console)

    # Exit code policy: 0 = clean enough, 1 = fail-on threshold tripped.
    threshold = fail_on.lower()
    sev_counts = {s.value: 0 for s in Severity}
    for f in result.findings:
        sev_counts[f.severity.value] += 1

    if threshold == "none":
        sys.exit(0)
    if threshold == "critical" and sev_counts["CRITICAL"] > 0:
        log.info("[cli] exiting non-zero due to %d CRITICAL findings",
                 sev_counts["CRITICAL"])
        sys.exit(1)
    if threshold == "warn" and (
        sev_counts["CRITICAL"] > 0 or sev_counts["WARN"] > 0
    ):
        log.info("[cli] exiting non-zero due to CRITICAL/WARN findings")
        sys.exit(1)
    sys.exit(0)


@main.command("version", help="Print mcp-audit version and exit.")
def version_cmd() -> None:
    click.echo(f"mcp-audit {__version__}")


if __name__ == "__main__":
    main()
