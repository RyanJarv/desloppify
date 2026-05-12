"""SQL detector phases."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from desloppify.engine._state.filtering import make_issue
from desloppify.languages._framework.base.types import LangRuntimeContract
from desloppify.languages.sql.detectors.smells import (
    detect_sql_security,
    detect_sql_smells,
)
from desloppify.languages.sql.extractors import extract_sqlc_queries, extract_table_refs
from desloppify.state_io import Issue

SEVERITY_TIER = {
    "low": 3,
    "medium": 2,
    "high": 1,
}


def _issue_from_match(
    detector: str,
    smell: dict[str, Any],
    match: dict[str, Any],
) -> Issue:
    rule_id = str(smell["id"])
    line = int(match["line"])
    label = str(smell["label"])
    return make_issue(
        detector,
        str(match["file"]),
        f"{rule_id}:L{line}",
        tier=SEVERITY_TIER.get(str(smell.get("severity", "medium")), 2),
        confidence="high",
        summary=f"{label} in SQL statement",
        detail={
            "rule_id": rule_id,
            "label": label,
            "severity": smell.get("severity", "medium"),
            "line": line,
            "content": match.get("content", ""),
        },
    )


def _issues_from_smells(detector: str, smells: list[dict[str, Any]]) -> list[Issue]:
    issues: list[Issue] = []
    for smell in smells:
        for match in smell.get("matches", []):
            issues.append(_issue_from_match(detector, smell, match))
    return issues


def phase_sql_structure(
    path: Path, lang: LangRuntimeContract
) -> tuple[list[Issue], dict[str, int]]:
    """Collect SQL structure metrics for sqlc queries and table references."""
    del lang
    queries = extract_sqlc_queries(path)
    refs = extract_table_refs(path)
    return [], {
        "sqlc_queries": len(queries),
        "table_refs": len(refs),
        "tables": len({ref.table for ref in refs}),
    }


def phase_sql_smells(
    path: Path, lang: LangRuntimeContract
) -> tuple[list[Issue], dict[str, int]]:
    """Detect SQL query-shape smells."""
    del lang
    smells = [
        smell
        for smell in detect_sql_smells(path)
        if smell["id"] not in {"destructive_ddl", "broad_grant", "disabled_rls"}
    ]
    issues = _issues_from_smells("sql_smells", smells)
    return issues, {"sql_smells": len(issues)}


def phase_sql_security(
    path: Path, lang: LangRuntimeContract
) -> tuple[list[Issue], dict[str, int]]:
    """Detect SQL safety and permission risks."""
    del lang
    issues = _issues_from_smells("sql_security", detect_sql_security(path))
    return issues, {"sql_security": len(issues)}
