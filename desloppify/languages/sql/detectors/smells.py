"""Dependency-free SQL smell and safety detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from desloppify.languages.sql.extractors import (
    find_sql_files,
    split_sql_statements,
    strip_sql_comments,
)

SELECT_STAR_RE = re.compile(r"\bSELECT\s+(?:DISTINCT\s+)?\*", re.IGNORECASE)
SELECT_RE = re.compile(r"^\s*(?:WITH\b.*?\b)?SELECT\b", re.IGNORECASE | re.DOTALL)
UPDATE_RE = re.compile(r"^\s*UPDATE\b", re.IGNORECASE)
DELETE_RE = re.compile(r"^\s*DELETE\s+FROM\b", re.IGNORECASE)
DROP_RE = re.compile(r"^\s*DROP\s+(?:TABLE|SCHEMA|DATABASE|VIEW|INDEX)\b", re.IGNORECASE)
TRUNCATE_RE = re.compile(r"^\s*TRUNCATE\b", re.IGNORECASE)
CROSS_JOIN_RE = re.compile(r"\bCROSS\s+JOIN\b", re.IGNORECASE)
BROAD_GRANT_RE = re.compile(
    r"\bGRANT\b.+\bON\b.+\bTO\s+(?:PUBLIC|\"?anon\"?|\"?anonymous\"?)\b",
    re.IGNORECASE | re.DOTALL,
)
DISABLE_RLS_RE = re.compile(
    r"\bALTER\s+TABLE\b.+\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class SqlSmellRule:
    """SQL smell metadata."""

    id: str
    label: str
    severity: str


SMELL_RULES: dict[str, SqlSmellRule] = {
    "large_query": SqlSmellRule("large_query", "Large SQL query", "medium"),
    "many_joins": SqlSmellRule("many_joins", "Many JOINs in one query", "medium"),
    "many_unions": SqlSmellRule("many_unions", "Many UNION ALLs in one query", "medium"),
    "select_star": SqlSmellRule("select_star", "SELECT * projection", "medium"),
    "write_without_where": SqlSmellRule(
        "write_without_where", "UPDATE/DELETE without WHERE", "high"
    ),
    "destructive_ddl": SqlSmellRule(
        "destructive_ddl", "Destructive DROP/TRUNCATE statement", "high"
    ),
    "unbounded_select": SqlSmellRule(
        "unbounded_select", "Unbounded SELECT without LIMIT", "medium"
    ),
    "cross_join": SqlSmellRule("cross_join", "CROSS JOIN", "medium"),
    "broad_grant": SqlSmellRule("broad_grant", "Broad GRANT target", "high"),
    "disabled_rls": SqlSmellRule(
        "disabled_rls", "Disabled row-level security", "high"
    ),
}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _resolve_file(root: Path, file_path: str) -> Path:
    path = Path(file_path)
    if path.is_absolute():
        return path
    candidate = root / path
    if candidate.exists():
        return candidate
    return path


def _first_content_line(statement: str) -> str:
    for line in statement.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return statement.strip()


def _line_for_match(statement: str, start_line: int, pattern: re.Pattern[str]) -> int:
    match = pattern.search(statement)
    if not match:
        return start_line
    return start_line + statement[: match.start()].count("\n")


def _has_keyword(statement: str, keyword: str) -> bool:
    return bool(re.search(rf"\b{re.escape(keyword)}\b", statement, re.IGNORECASE))


def _statement_is_largeish(statement: str) -> bool:
    words = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", statement)
    join_count = len(re.findall(r"\bJOIN\b", statement, re.IGNORECASE))
    return len(statement.splitlines()) >= 4 or len(words) >= 18 or join_count >= 2


def _loc(statement: str) -> int:
    return len([line for line in statement.splitlines() if line.strip()])


def _new_smell(rule_id: str) -> dict[str, Any]:
    rule = SMELL_RULES[rule_id]
    return {
        "id": rule.id,
        "label": rule.label,
        "severity": rule.severity,
        "matches": [],
    }


def detect_sql_smells_from_text(sql: str, file: str = "<memory>") -> list[dict[str, Any]]:
    """Return normalized SQL smell entries for one SQL string."""
    grouped: dict[str, dict[str, Any]] = {}

    def add(rule_id: str, line: int, content: str) -> None:
        entry = grouped.setdefault(rule_id, _new_smell(rule_id))
        entry["matches"].append(
            {
                "file": file,
                "line": line,
                "content": content.strip(),
            }
        )

    for statement_info in split_sql_statements(sql):
        raw_statement = statement_info["body"]
        statement = strip_sql_comments(raw_statement).strip()
        if not statement:
            continue
        line = int(statement_info["line"])
        content = _first_content_line(statement)
        join_count = len(re.findall(r"\bJOIN\b", statement, re.IGNORECASE))
        union_all_count = len(re.findall(r"\bUNION\s+ALL\b", statement, re.IGNORECASE))

        if _loc(statement) > 120:
            add("large_query", line, content)
        if join_count > 8:
            add("many_joins", line, content)
        if union_all_count > 5:
            add("many_unions", line, content)
        if SELECT_STAR_RE.search(statement):
            add("select_star", _line_for_match(statement, line, SELECT_STAR_RE), content)
        if (UPDATE_RE.search(statement) or DELETE_RE.search(statement)) and not _has_keyword(
            statement, "WHERE"
        ):
            add("write_without_where", line, content)
        if DROP_RE.search(statement) or TRUNCATE_RE.search(statement):
            add("destructive_ddl", line, content)
        if (
            SELECT_RE.search(statement)
            and _statement_is_largeish(statement)
            and not _has_keyword(statement, "LIMIT")
            and not _has_keyword(statement, "FETCH")
        ):
            add("unbounded_select", line, content)
        if CROSS_JOIN_RE.search(statement):
            add("cross_join", _line_for_match(statement, line, CROSS_JOIN_RE), content)
        if BROAD_GRANT_RE.search(statement):
            add("broad_grant", line, content)
        if DISABLE_RLS_RE.search(statement):
            add("disabled_rls", line, content)

    smells = list(grouped.values())
    for smell in smells:
        smell["count"] = len(smell["matches"])
        smell["files"] = sorted({match["file"] for match in smell["matches"]})
    return smells


def detect_sql_smells(path: Path) -> list[dict[str, Any]]:
    """Return normalized SQL smell entries for all SQL files under a path."""
    root = Path(path)
    grouped: dict[str, dict[str, Any]] = {}
    for file_path in find_sql_files(root):
        full_path = _resolve_file(root, file_path)
        for smell in detect_sql_smells_from_text(_read_text(full_path), file_path):
            entry = grouped.setdefault(smell["id"], _new_smell(smell["id"]))
            entry["matches"].extend(smell["matches"])

    results = list(grouped.values())
    for smell in results:
        smell["count"] = len(smell["matches"])
        smell["files"] = sorted({match["file"] for match in smell["matches"]})
    return results


def detect_sql_security(path: Path) -> list[dict[str, Any]]:
    """Return security-oriented SQL smells."""
    return [
        smell
        for smell in detect_sql_smells(path)
        if smell["id"] in {"destructive_ddl", "broad_grant", "disabled_rls"}
    ]
