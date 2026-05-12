"""SQL detect-subcommand wrappers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from desloppify.base.output.terminal import colorize, print_table
from desloppify.languages.sql.detectors.smells import (
    detect_sql_security,
    detect_sql_smells,
)
from desloppify.languages.sql.extractors import extract_sqlc_queries, extract_table_refs

SECURITY_RULE_IDS = {"destructive_ddl", "broad_grant", "disabled_rls"}


def _as_json(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json", False))


def _sql_smells_only(path: Path) -> list[dict]:
    """Return smell findings without SQL security rules."""
    return [
        smell for smell in detect_sql_smells(path) if smell["id"] not in SECURITY_RULE_IDS
    ]


def cmd_queries(args: argparse.Namespace) -> None:
    """List sqlc named queries."""
    queries = extract_sqlc_queries(Path(args.path))
    rows = [
        {
            "name": query.name,
            "command": query.command,
            "file": query.file,
            "line": query.line,
            "end_line": query.end_line,
        }
        for query in queries
    ]
    if _as_json(args):
        print(json.dumps({"count": len(rows), "entries": rows}, indent=2))
        return
    if not rows:
        print(colorize("\nNo sqlc named queries found.", "green"))
        return
    print(colorize(f"\nSQL queries: {len(rows)}\n", "bold"))
    top = getattr(args, "top", 20)
    print_table(
        ["Name", "Command", "File", "Line"],
        [
            [row["name"], row["command"], row["file"], str(row["line"])]
            for row in rows[:top]
        ],
        [32, 10, 64, 6],
    )


def cmd_tables(args: argparse.Namespace) -> None:
    """List SQL table references."""
    refs = extract_table_refs(Path(args.path))
    rows = [
        {
            "table": ref.table,
            "file": ref.file,
            "line": ref.line,
            "context": ref.context,
        }
        for ref in refs
    ]
    if _as_json(args):
        print(json.dumps({"count": len(rows), "entries": rows}, indent=2))
        return
    if not rows:
        print(colorize("\nNo SQL table references found.", "green"))
        return
    print(colorize(f"\nSQL table references: {len(rows)}\n", "bold"))
    top = getattr(args, "top", 20)
    print_table(
        ["Table", "File", "Line", "Context"],
        [
            [row["table"], row["file"], str(row["line"]), row["context"]]
            for row in rows[:top]
        ],
        [32, 54, 6, 52],
    )


def cmd_smells(args: argparse.Namespace) -> None:
    """List SQL smells."""
    smells = _sql_smells_only(Path(args.path))
    if _as_json(args):
        print(json.dumps({"count": sum(s["count"] for s in smells), "entries": smells}, indent=2))
        return
    if not smells:
        print(colorize("\nNo SQL smells found.", "green"))
        return
    print(colorize(f"\nSQL smells: {sum(s['count'] for s in smells)}\n", "bold"))
    top = getattr(args, "top", 20)
    rows = []
    for smell in smells:
        for match in smell["matches"]:
            rows.append(
                [
                    smell["id"],
                    smell["severity"],
                    match["file"],
                    str(match["line"]),
                    match["content"],
                ]
            )
    print_table(["Rule", "Severity", "File", "Line", "Content"], rows[:top], [22, 9, 48, 6, 60])


def cmd_security(args: argparse.Namespace) -> None:
    """List SQL security risks."""
    risks = detect_sql_security(Path(args.path))
    if _as_json(args):
        print(json.dumps({"count": sum(s["count"] for s in risks), "entries": risks}, indent=2))
        return
    if not risks:
        print(colorize("\nNo SQL security risks found.", "green"))
        return
    print(colorize(f"\nSQL security risks: {sum(s['count'] for s in risks)}\n", "bold"))
    top = getattr(args, "top", 20)
    rows = []
    for risk in risks:
        for match in risk["matches"]:
            rows.append(
                [
                    risk["id"],
                    risk["severity"],
                    match["file"],
                    str(match["line"]),
                    match["content"],
                ]
            )
    print_table(["Rule", "Severity", "File", "Line", "Content"], rows[:top], [22, 9, 48, 6, 60])


def get_detect_commands():
    """Return SQL-specific detect commands."""
    return {
        "queries": cmd_queries,
        "tables": cmd_tables,
        "smells": cmd_smells,
        "security": cmd_security,
    }
