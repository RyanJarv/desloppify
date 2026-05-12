"""SQL-specific test coverage heuristics and mappings."""

from __future__ import annotations

import os
import re

from desloppify.languages.sql.extractors import strip_sql_comments

ASSERT_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bSELECT\b",
        r"\bASSERT\b",
        r"\bRAISE\s+EXCEPTION\b",
    ]
]
MOCK_PATTERNS: list[re.Pattern[str]] = []
SNAPSHOT_PATTERNS: list[re.Pattern[str]] = []
TEST_FUNCTION_RE = re.compile(
    r"^\s*--\s*name:\s*(?:Test|Assert)[A-Za-z_][A-Za-z0-9_]*",
    re.IGNORECASE | re.MULTILINE,
)
BARREL_BASENAMES: set[str] = set()

SQLC_QUERY_RE = re.compile(
    r"^\s*--\s*name:\s*[A-Za-z_][A-Za-z0-9_]*",
    re.IGNORECASE | re.MULTILINE,
)
SQL_LOGIC_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|ALTER|DROP|TRUNCATE)\b",
    re.IGNORECASE,
)


def has_testable_logic(_filepath: str, content: str) -> bool:
    """Return True when a SQL file contains executable query or DDL content."""
    stripped = strip_comments(content)
    return bool(SQLC_QUERY_RE.search(content) or SQL_LOGIC_RE.search(stripped))


def resolve_import_spec(
    _spec: str, _test_path: str, _production_files: set[str]
) -> str | None:
    """SQL files do not expose import specs for coverage mapping."""
    return None


def resolve_barrel_reexports(_filepath: str, _production_files: set[str]) -> set[str]:
    """SQL has no barrel-file re-export expansion for coverage mapping."""
    return set()


def parse_test_import_specs(_content: str) -> list[str]:
    """SQL tests do not provide import specs."""
    return []


def map_test_to_source(test_path: str, production_set: set[str]) -> str | None:
    """Map SQL test fixtures to source SQL by common test naming markers."""
    basename = os.path.basename(test_path)
    dirname = os.path.dirname(test_path)
    candidates: list[str] = []
    if basename.startswith("test_"):
        candidates.append(os.path.join(dirname, basename[5:]))
    if basename.endswith("_test.sql"):
        candidates.append(os.path.join(dirname, f"{basename[:-9]}.sql"))
    for candidate in candidates:
        if candidate in production_set:
            return candidate
    return None


def strip_test_markers(basename: str) -> str | None:
    """Strip SQL test naming markers to derive a source basename."""
    if basename.startswith("test_"):
        return basename[5:]
    if basename.endswith("_test.sql"):
        return f"{basename[:-9]}.sql"
    return None


def strip_comments(content: str) -> str:
    """Strip SQL comments while preserving quoted strings."""
    return strip_sql_comments(content)
