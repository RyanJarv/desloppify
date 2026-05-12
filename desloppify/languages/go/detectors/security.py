"""Go-specific security detectors."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from desloppify.engine.detectors.security.rules import (
    SecurityRule,
    make_security_entry,
)
from desloppify.engine.policy.zones import FileZoneMap, Zone

logger = logging.getLogger(__name__)

_SKIPPED_ZONES = frozenset({Zone.TEST, Zone.VENDOR, Zone.GENERATED, Zone.CONFIG})

_UNSAFE_POINTER_RE = re.compile(r"\bunsafe\.Pointer\b")
_SQL_CONCAT_RE = re.compile(
    r"\b(?:Query|QueryRow|Exec|ExecContext|QueryContext)\s*\("
    r"[^)]*(?:fmt\.Sprintf|\"[^\"]*\"\s*\+|\+\s*\")"
)
_SQL_CONCAT_SIMPLE_RE = re.compile(
    r"\b(?:Query|QueryRow|Exec)\s*\(\s*\"[^\"]*\"\s*\+"
)
_WEAK_CRYPTO_RE = re.compile(r"\b(?:md5|sha1)\.(?:New|Sum)")
_MATH_RAND_IMPORT_RE = re.compile(r'"math/rand"')
_SECURITY_CONTEXT_RE = re.compile(
    r"(?:token|secret|password|key|nonce|salt|cipher|crypt|auth)", re.IGNORECASE
)
_HTTP_LISTEN_RE = re.compile(r"\bhttp\.ListenAndServe\s*\(")
_EXEC_COMMAND_VAR_RE = re.compile(r"\bexec\.Command\s*\(\s*[A-Za-z_]\w*")
_EXEC_COMMAND_LITERAL_RE = re.compile(r'\bexec\.Command\s*\(\s*"')
_HARDCODED_CRED_RE = re.compile(
    r'\b(?:password|passwd|secret|token|api_?key)\s*(?::=|=)\s*"[^"]{8,}"',
    re.IGNORECASE,
)
_INSECURE_SKIP_VERIFY_RE = re.compile(r"\bInsecureSkipVerify\s*:\s*true\b")


def _entry(
    filepath: str,
    line_num: int,
    line: str,
    *,
    check_id: str,
    summary: str,
    severity: str,
    confidence: str,
    remediation: str,
) -> dict:
    return make_security_entry(
        filepath,
        line_num,
        line,
        SecurityRule(
            check_id=check_id,
            summary=summary,
            severity=severity,
            confidence=confidence,
            remediation=remediation,
        ),
    )


def _code_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Yield lines outside Go comments.

    This intentionally strips whole-line and inline block comments before applying
    line-oriented regexes. It is not a parser, but avoids the common false
    positives from commented examples and disabled code.
    """
    code_lines: list[tuple[int, str]] = []
    in_block_comment = False

    for line_num, line in enumerate(lines, 1):
        remaining = line
        cleaned = ""
        while remaining:
            if in_block_comment:
                end = remaining.find("*/")
                if end == -1:
                    remaining = ""
                    continue
                remaining = remaining[end + 2 :]
                in_block_comment = False
                continue

            block_start = remaining.find("/*")
            line_start = remaining.find("//")
            if line_start != -1 and (block_start == -1 or line_start < block_start):
                cleaned += remaining[:line_start]
                remaining = ""
                continue
            if block_start == -1:
                cleaned += remaining
                remaining = ""
                continue

            cleaned += remaining[:block_start]
            remaining = remaining[block_start + 2 :]
            in_block_comment = True

        if cleaned.strip():
            code_lines.append((line_num, cleaned))

    return code_lines


def detect_go_security(
    files: list[str],
    zone_map: FileZoneMap | None,
) -> tuple[list[dict], int]:
    """Detect Go-specific security issues. Returns ``(entries, files_scanned)``."""
    entries: list[dict] = []
    scanned = 0

    for filepath in files:
        if not filepath.endswith(".go"):
            continue
        if zone_map is not None and zone_map.get(filepath) in _SKIPPED_ZONES:
            continue

        try:
            content = Path(filepath).read_text(errors="replace")
        except OSError as exc:
            logger.debug(
                "Skipping unreadable Go file %s in security detector: %s",
                filepath,
                exc,
            )
            continue

        scanned += 1
        lines = content.splitlines()
        code_lines = _code_lines(lines)
        code_content = "\n".join(line for _, line in code_lines)

        for line_num, line in code_lines:
            if _UNSAFE_POINTER_RE.search(line):
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="unsafe_pointer",
                        summary="unsafe.Pointer usage bypasses Go type safety",
                        severity="high",
                        confidence="medium",
                        remediation=(
                            "Avoid unsafe.Pointer unless necessary and document the "
                            "safety invariant."
                        ),
                    )
                )

            if _SQL_CONCAT_RE.search(line) or _SQL_CONCAT_SIMPLE_RE.search(line):
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="sql_injection",
                        summary="SQL query built with string concatenation",
                        severity="critical",
                        confidence="medium",
                        remediation=(
                            "Use parameterized queries with placeholders for "
                            "user-controlled values."
                        ),
                    )
                )

            if _WEAK_CRYPTO_RE.search(line):
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="weak_crypto",
                        summary="Weak hash function used",
                        severity="medium",
                        confidence="high",
                        remediation=(
                            "Replace MD5/SHA1 with SHA-256, SHA-512, or a "
                            "purpose-specific password hashing algorithm."
                        ),
                    )
                )

            if _HTTP_LISTEN_RE.search(line):
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="http_no_tls",
                        summary="HTTP server started without TLS",
                        severity="medium",
                        confidence="medium",
                        remediation=(
                            "Use http.ListenAndServeTLS or run behind a properly "
                            "configured TLS terminator."
                        ),
                    )
                )

            command_uses_var = _EXEC_COMMAND_VAR_RE.search(line)
            command_uses_literal = _EXEC_COMMAND_LITERAL_RE.search(line)
            if command_uses_var and not command_uses_literal:
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="command_injection",
                        summary="exec.Command uses a variable command name",
                        severity="high",
                        confidence="medium",
                        remediation=(
                            "Use an allowlisted command and validate all arguments."
                        ),
                    )
                )

            if _HARDCODED_CRED_RE.search(line):
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="hardcoded_credentials",
                        summary="Hardcoded credential detected",
                        severity="high",
                        confidence="medium",
                        remediation=(
                            "Load credentials from environment variables or a "
                            "secrets manager."
                        ),
                    )
                )

            if _INSECURE_SKIP_VERIFY_RE.search(line):
                entries.append(
                    _entry(
                        filepath,
                        line_num,
                        line,
                        check_id="insecure_tls",
                        summary="TLS certificate verification is disabled",
                        severity="high",
                        confidence="high",
                        remediation=(
                            "Remove InsecureSkipVerify or configure trusted "
                            "certificate authorities."
                        ),
                    )
                )

        if _MATH_RAND_IMPORT_RE.search(code_content) and _SECURITY_CONTEXT_RE.search(
            code_content
        ):
            for line_num, line in code_lines:
                if _MATH_RAND_IMPORT_RE.search(line):
                    entries.append(
                        _entry(
                            filepath,
                            line_num,
                            line,
                            check_id="insecure_random",
                            summary="math/rand used in a security-sensitive context",
                            severity="medium",
                            confidence="medium",
                            remediation=(
                                "Use crypto/rand for security-sensitive random values."
                            ),
                        )
                    )
                    break

    return entries, scanned


__all__ = ["detect_go_security"]
