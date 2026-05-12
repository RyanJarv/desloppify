"""Lightweight SQL extraction helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from desloppify.base.discovery.source import SourceDiscoveryOptions, find_source_files
from desloppify.engine.detectors.base import FunctionInfo

SQL_FILE_EXCLUSIONS = [
    "vendor",
    "vendor/**",
    "third_party",
    "third_party/**",
    "node_modules",
    "node_modules/**",
    ".git",
    ".git/**",
    ".worktrees",
    ".worktrees/**",
    ".cache",
    ".cache/**",
    ".sqlc",
    ".sqlc/**",
    "cdk.out",
    "cdk.out/**",
    "generated",
    "generated/**",
    "gen",
    "gen/**",
    "dist",
    "dist/**",
    "build",
    "build/**",
    "*.generated.sql",
]

SQLC_NAME_RE = re.compile(
    r"^\s*--\s*name:\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+(?P<command>:[A-Za-z0-9_]+))?\s*$",
    re.IGNORECASE,
)
TABLE_REF_RE = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INTO|TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM|"
    r"ALTER\s+TABLE|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|"
    r"DROP\s+TABLE(?:\s+IF\s+EXISTS)?)\s+"
    r"(?P<table>(?:\"[^\"]+\"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)(?:\."
    r"(?:\"[^\"]+\"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*))*)",
    re.IGNORECASE,
)
COMMENT_LINE_RE = re.compile(r"^\s*--")
DOLLAR_QUOTE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")


@dataclass(frozen=True)
class SqlcQuery:
    """A sqlc named query block."""

    name: str
    command: str
    file: str
    line: int
    end_line: int
    body: str


@dataclass(frozen=True)
class SqlTableRef:
    """A simple SQL table reference."""

    table: str
    file: str
    line: int
    context: str


def find_sql_files(path: str | Path) -> list[str]:
    """Find raw .sql files, excluding generated/vendor/cache paths."""
    return find_source_files(
        path,
        [".sql"],
        SourceDiscoveryOptions(exclusions=tuple(SQL_FILE_EXCLUSIONS)),
    )


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


def _strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    i = 0
    while i < len(line) - 1:
        char = line[i]
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double and line[i : i + 2] == "--":
            return line[:i]
        i += 1
    return line


def strip_sql_comments(sql: str) -> str:
    """Remove SQL line/block comments while preserving string literals."""
    result: list[str] = []
    i = 0
    in_single = False
    in_double = False
    dollar_quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    while i < len(sql):
        char = sql[i]
        nxt = sql[i : i + 2]
        if dollar_quote is not None:
            if sql.startswith(dollar_quote, i):
                result.append(dollar_quote)
                i += len(dollar_quote)
                dollar_quote = None
                continue
            result.append(char)
            i += 1
            continue
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                result.append(char)
            i += 1
            continue
        if in_block_comment:
            if nxt == "*/":
                in_block_comment = False
                i += 2
                continue
            if char == "\n":
                result.append(char)
            i += 1
            continue
        if in_single and nxt == "''":
            result.append(nxt)
            i += 2
            continue
        if in_double and nxt == '""':
            result.append(nxt)
            i += 2
            continue
        if not in_single and not in_double and nxt == "--":
            in_line_comment = True
            i += 2
            continue
        if not in_single and not in_double and nxt == "/*":
            in_block_comment = True
            i += 2
            continue
        if not in_single and not in_double:
            dollar_match = DOLLAR_QUOTE_RE.match(sql, i)
            if dollar_match:
                dollar_quote = dollar_match.group(0)
                result.append(dollar_quote)
                i += len(dollar_quote)
                continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        result.append(char)
        i += 1
    return "".join(result)


def split_sql_statements(sql: str, *, start_line: int = 1) -> list[dict[str, Any]]:
    """Split SQL into semicolon-terminated statements with line spans."""
    statements: list[dict[str, Any]] = []
    buf: list[str] = []
    line = start_line
    stmt_line = start_line
    in_single = False
    in_double = False
    dollar_quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    i = 0
    while i < len(sql):
        char = sql[i]
        nxt = sql[i : i + 2]
        if not buf and char.isspace():
            if char == "\n":
                line += 1
                stmt_line = line
            i += 1
            continue
        if not buf:
            stmt_line = line
        buf.append(char)
        if dollar_quote is not None:
            if char == "\n":
                line += 1
            if sql.startswith(dollar_quote, i):
                for extra in dollar_quote[1:]:
                    buf.append(extra)
                    if extra == "\n":
                        line += 1
                i += len(dollar_quote)
                dollar_quote = None
                continue
            i += 1
            continue
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                line += 1
            i += 1
            continue
        if in_block_comment:
            if nxt == "*/":
                buf.append(sql[i + 1])
                in_block_comment = False
                i += 2
                continue
            if char == "\n":
                line += 1
            i += 1
            continue
        if in_single and nxt == "''":
            buf.append(sql[i + 1])
            i += 2
            continue
        if in_double and nxt == '""':
            buf.append(sql[i + 1])
            i += 2
            continue
        if not in_single and not in_double and nxt == "--":
            in_line_comment = True
            buf.append(sql[i + 1])
            i += 2
            continue
        if not in_single and not in_double and nxt == "/*":
            in_block_comment = True
            buf.append(sql[i + 1])
            i += 2
            continue
        if not in_single and not in_double:
            dollar_match = DOLLAR_QUOTE_RE.match(sql, i)
            if dollar_match:
                dollar_quote = dollar_match.group(0)
                for extra in dollar_quote[1:]:
                    buf.append(extra)
                i += len(dollar_quote)
                continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double and char == ";":
            text = "".join(buf).strip()
            if text:
                statements.append({"body": text, "line": stmt_line, "end_line": line})
            buf = []
            stmt_line = line
        if char == "\n":
            line += 1
        i += 1
    text = "".join(buf).strip()
    if text:
        statements.append({"body": text, "line": stmt_line, "end_line": line})
    return statements


def extract_sqlc_queries_from_text(sql: str, file: str = "<memory>") -> list[SqlcQuery]:
    """Extract sqlc named query blocks from a SQL string."""
    lines = sql.splitlines()
    markers: list[tuple[int, str, str]] = []
    for idx, line in enumerate(lines, start=1):
        match = SQLC_NAME_RE.match(line)
        if match:
            markers.append((idx, match.group("name"), match.group("command") or ""))

    queries: list[SqlcQuery] = []
    for pos, (line_no, name, command) in enumerate(markers):
        next_line = markers[pos + 1][0] if pos + 1 < len(markers) else len(lines) + 1
        body_lines = lines[line_no: next_line - 1]
        while body_lines and not body_lines[0].strip():
            body_lines.pop(0)
        while body_lines and not body_lines[-1].strip():
            body_lines.pop()
        body = "\n".join(body_lines)
        queries.append(
            SqlcQuery(
                name=name,
                command=command,
                file=file,
                line=line_no,
                end_line=next_line - 1,
                body=body,
            )
        )
    return queries


def extract_sqlc_queries(path: Path) -> list[SqlcQuery]:
    """Extract sqlc named query blocks from all SQL files under a path."""
    root = Path(path)
    queries: list[SqlcQuery] = []
    for file_path in find_sql_files(root):
        full_path = _resolve_file(root, file_path)
        queries.extend(extract_sqlc_queries_from_text(_read_text(full_path), file_path))
    return queries


def normalize_table_name(table: str) -> str:
    """Normalize quote characters around table identifier parts."""
    parts = []
    for part in table.split("."):
        part = part.strip()
        if (
            len(part) >= 2
            and ((part[0], part[-1]) in {('"', '"'), ("`", "`"), ("[", "]")})
        ):
            part = part[1:-1]
        parts.append(part)
    return ".".join(parts)


def extract_table_refs_from_text(sql: str, file: str = "<memory>") -> list[SqlTableRef]:
    """Extract practical table references from SQL text."""
    refs: list[SqlTableRef] = []
    for line_no, line in enumerate(sql.splitlines(), start=1):
        if COMMENT_LINE_RE.match(line):
            continue
        cleaned = _strip_inline_comment(line)
        for match in TABLE_REF_RE.finditer(cleaned):
            table = normalize_table_name(match.group("table"))
            upper = table.upper()
            if upper in {"IF", "ONLY", "SELECT", "SET", "VALUES", "WHERE"}:
                continue
            refs.append(
                SqlTableRef(
                    table=table,
                    file=file,
                    line=line_no,
                    context=cleaned.strip(),
                )
            )
    return refs


def extract_table_refs(path: Path) -> list[SqlTableRef]:
    """Extract table references from all SQL files under a path."""
    root = Path(path)
    refs: list[SqlTableRef] = []
    for file_path in find_sql_files(root):
        full_path = _resolve_file(root, file_path)
        refs.extend(extract_table_refs_from_text(_read_text(full_path), file_path))
    return refs


def extract_functions(path: Path) -> list[FunctionInfo]:
    """Represent sqlc named queries as function-like units for shared tooling."""
    functions: list[FunctionInfo] = []
    for query in extract_sqlc_queries(path):
        functions.append(
            FunctionInfo(
                name=query.name,
                file=query.file,
                line=query.line,
                end_line=query.end_line,
                loc=max(1, query.end_line - query.line + 1),
                body=query.body,
            )
        )
    return functions
