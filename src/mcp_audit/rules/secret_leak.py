"""Detect hard-coded secrets in MCP server config bodies.

HARD RULE: we never put the matched value in any output. We report only the
field path, character count, and (best-effort) line number in the source
file.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

from ..parser import ServerEntry
from . import Finding, Severity

log = logging.getLogger("mcp_audit.rules.secret_leak")


# Patterns are ordered most-specific first. Each entry is
# (pattern_name, compiled_regex).
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # anthropic_sk_ant MUST precede openai_sk: the openai pattern
    # (^sk-[A-Za-z0-9_\-]{20,}$) also matches "sk-ant-..." because "-" is in
    # its char class, so an Anthropic key would be misclassified as openai_sk
    # if openai came first. Most-specific prefix wins → list it first.
    ("anthropic_sk_ant", re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,}$")),
    ("openai_sk", re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$")),
    ("github_pat", re.compile(r"^ghp_[A-Za-z0-9]{20,}$")),
    ("github_oauth", re.compile(r"^gho_[A-Za-z0-9]{20,}$")),
    ("github_user", re.compile(r"^ghu_[A-Za-z0-9]{20,}$")),
    ("github_server", re.compile(r"^ghs_[A-Za-z0-9]{20,}$")),
    ("github_refresh", re.compile(r"^ghr_[A-Za-z0-9]{20,}$")),
    ("bearer_token", re.compile(r"^Bearer\s+[A-Za-z0-9\-_=\.]{20,}$")),
    ("inline_token_kv", re.compile(r"^[Tt]oken[:\s=]+[A-Za-z0-9\-_=]{20,}$")),
    ("aws_access_key", re.compile(r"^AKIA[A-Z0-9]{16}$")),
    ("generic_jwt", re.compile(r"^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}$")),
]


# Field names that strongly suggest "this is supposed to be a secret" — used
# as a softer signal when no pattern matches but the value is a long opaque
# string. We still don't print the value.
_SECRET_FIELD_HINTS = {
    "api_key", "apikey", "api-key",
    "token", "access_token", "accesstoken",
    "secret", "password", "passwd",
    "key",  # generic
    "auth", "authorization",
}


# Pure env-var references are the *recommended* way to configure secrets,
# so they must never be flagged: "${PRODUCTION_API_KEY_2026}" or "$MY_KEY".
_ENV_REF_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")


def _is_env_placeholder(value: str) -> bool:
    if value.startswith("${") and value.endswith("}"):
        return True
    return bool(_ENV_REF_RE.match(value))


def _looks_like_long_opaque(value: str) -> bool:
    """Soft heuristic: 20+ chars, not whitespace-y, has both letters & digits."""
    if _is_env_placeholder(value):
        return False
    if len(value) < 20 or len(value) > 4096:
        return False
    if any(c.isspace() for c in value):
        return False
    has_alpha = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_alpha and has_digit


def value_matches_secret_pattern(value: str) -> bool:
    """Reusable check: does this string look like a credential?

    True when a strong pattern matches OR the value is a long opaque string.
    Used by the reporter to redact args before printing — callers must only
    ever output field name + char count, never the value itself.
    """
    if _is_env_placeholder(value):
        return False
    for _name, pat in _PATTERNS:
        if pat.match(value):
            return True
    return _looks_like_long_opaque(value)


def _scan_value(field_path: str, value: object) -> list[tuple[str, str, int]]:
    """Return list of (field_path, pattern_name, char_count) matches."""
    if not isinstance(value, str):
        return []
    if _is_env_placeholder(value):
        return []  # ${ENV_VAR} / $ENV_VAR references are the recommended style
    hits: list[tuple[str, str, int]] = []
    for name, pat in _PATTERNS:
        if pat.match(value):
            hits.append((field_path, name, len(value)))
            return hits  # one strong match is enough

    # Soft signal: a secret-named field with a long opaque value
    last_segment = field_path.split(".")[-1].lower()
    if last_segment in _SECRET_FIELD_HINTS and _looks_like_long_opaque(value):
        hits.append((field_path, "field_name_heuristic", len(value)))
    return hits


def _walk(prefix: str, node: object) -> Iterable[tuple[str, str, int]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(f"{prefix}.{k}" if prefix else str(k), v)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(f"{prefix}[{i}]", v)
    else:
        yield from _scan_value(prefix, node)


# Credential embedded as URL userinfo: scheme://user:PASSWORD@host
_URL_USERINFO_RE = re.compile(r"://[^/@]*:([^@]+)@")

# Query parameter names that commonly carry credentials.
_SENSITIVE_QUERY_PARAMS = {"token", "key", "secret", "apikey"}


def _check_url(url: object) -> list[tuple[str, str, int]]:
    """Dedicated URL inspection. Returns (field_path, pattern_name, char_count).

    We never report any part of the URL value itself — only which component
    (userinfo password / query param name) looked like a credential and how
    many characters it has.
    """
    if not isinstance(url, str) or _is_env_placeholder(url):
        return []
    hits: list[tuple[str, str, int]] = []

    m = _URL_USERINFO_RE.search(url)
    if m:
        hits.append(("url", "url_userinfo_credential", len(m.group(1))))

    # Query params: token/key/secret/apikey with a non-placeholder value.
    query = url.split("?", 1)[1] if "?" in url else ""
    for pair in query.split("&"):
        if "=" not in pair:
            continue
        param, _, value = pair.partition("=")
        if param.lower() in _SENSITIVE_QUERY_PARAMS and value and not _is_env_placeholder(value):
            hits.append((f"url?{param}", "url_sensitive_query_param", len(value)))
    return hits


def _line_number_of_field(path: Path, leaf_field: str) -> int | None:
    """Best-effort: find the first line containing the leaf field name as a key.

    This is approximate (we don't parse JSON to AST), but good enough to point
    a human at the right neighborhood. Returns None if we can't read the file.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    needle = f'"{leaf_field}"'
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return None


def detect_secret_leak(
    server: ServerEntry, all_servers: list[ServerEntry]
) -> Iterable[Finding]:
    log.info("[secret_leak] scanning server=%s file=%s", server.name, server.source_file)

    # Only fields that definitionally carry no secret are skipped. ``args``
    # IS scanned (real configs pass tokens as ["--token", "ghp_..."]); ``url``
    # gets a dedicated structural check below instead of the generic walk.
    raw = dict(server.raw)
    for noisy in ("command", "transport", "type"):
        raw.pop(noisy, None)
    url_value = raw.pop("url", None)

    matches = list(_walk("", raw))
    matches.extend(_check_url(url_value))
    for field_path, pattern_name, char_count in matches:
        leaf = field_path.split(".")[-1].split("[")[0].split("?")[0]
        line_no = _line_number_of_field(server.source_file, leaf)
        log.info(
            "[secret_leak] HIT server=%s field=%s pattern=%s chars=%d line=%s",
            server.name, field_path, pattern_name, char_count, line_no,
        )
        sev = Severity.CRITICAL
        if pattern_name == "field_name_heuristic":
            sev = Severity.WARN  # softer signal
        yield Finding(
            severity=sev,
            rule="secret_leak",
            server=server.name,
            source_file=server.source_file,
            message=(
                f"possible hard-coded credential in field '{field_path}' "
                f"({pattern_name}, {char_count} chars). "
                "Use an env-var reference like ${YOUR_API_KEY} instead."
            ),
            details={
                "field_path": field_path,
                "pattern": pattern_name,
                "char_count": char_count,
                "line": line_no,
            },
        )
