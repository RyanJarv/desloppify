from __future__ import annotations

import argparse
import json
from pathlib import Path

from desloppify.languages.sql.commands import cmd_smells
from desloppify.languages.sql.detectors.smells import (
    detect_sql_security,
    detect_sql_smells,
    detect_sql_smells_from_text,
)
from desloppify.languages.sql.phases import phase_sql_security, phase_sql_smells


def test_detect_sql_smells_from_text() -> None:
    sql = """
SELECT * FROM jobs;
UPDATE jobs SET status = 'done';
DELETE FROM audit_events;
SELECT j.id, u.email
FROM jobs j
JOIN users u ON u.id = j.user_id
WHERE j.status = 'queued';
SELECT * FROM a CROSS JOIN b;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO PUBLIC;
ALTER TABLE accounts DISABLE ROW LEVEL SECURITY;
"""

    smells = {entry["id"]: entry for entry in detect_sql_smells_from_text(sql, "q.sql")}

    assert smells["select_star"]["count"] == 2
    assert smells["write_without_where"]["count"] == 2
    assert smells["unbounded_select"]["count"] == 1
    assert smells["cross_join"]["count"] == 1
    assert smells["broad_grant"]["severity"] == "high"
    assert smells["disabled_rls"]["matches"][0]["line"] == 11


def test_detect_sqlc_heavy_query_shape_patterns() -> None:
    joins = "\n".join(
        f"JOIN table_{idx} t{idx} ON t{idx}.id = root.id" for idx in range(9)
    )
    unions = "\nUNION ALL\n".join(f"SELECT {idx} AS n" for idx in range(7))
    large_body = "\n".join(f"SELECT {idx} AS col_{idx}" for idx in range(121))
    sql = f"""-- name: GraphHealth :many
WITH root AS (
  SELECT id FROM graph_nodes
)
SELECT root.id
FROM root
{joins};

-- name: ManyUnionStatuses :many
{unions};

-- name: HugeSchemaBackfill :exec
{large_body};

-- name: Cleanup :exec
TRUNCATE TABLE scratch_graph CASCADE;
"""

    smells = {entry["id"]: entry for entry in detect_sql_smells_from_text(sql, "graphhealth.sql")}

    assert smells["many_joins"]["count"] == 1
    assert smells["many_unions"]["count"] == 1
    assert smells["large_query"]["count"] == 1
    assert smells["destructive_ddl"]["matches"][0]["content"].startswith(
        "TRUNCATE TABLE scratch_graph"
    )


def test_detect_sql_smells_path_and_security_subset(set_project_root: Path) -> None:
    root = set_project_root
    (root / "queries").mkdir()
    (root / "queries/unsafe.sql").write_text(
        """DROP TABLE old_jobs;
TRUNCATE audit_events;
GRANT SELECT ON users TO PUBLIC;
"""
    )

    smells = {entry["id"]: entry for entry in detect_sql_smells(root)}
    risks = {entry["id"]: entry for entry in detect_sql_security(root)}

    assert smells["destructive_ddl"]["count"] == 2
    assert set(risks) == {"destructive_ddl", "broad_grant"}


def test_sql_phases_return_normalized_issues(set_project_root: Path) -> None:
    root = set_project_root
    (root / "queries").mkdir()
    (root / "queries/unsafe.sql").write_text(
        """SELECT * FROM jobs;
DROP TABLE old_jobs;
"""
    )

    smell_issues, smell_counts = phase_sql_smells(root, None)  # type: ignore[arg-type]
    security_issues, security_counts = phase_sql_security(root, None)  # type: ignore[arg-type]

    assert smell_counts == {"sql_smells": 1}
    assert smell_issues[0]["detector"] == "sql_smells"
    assert smell_issues[0]["detail"]["rule_id"] == "select_star"
    assert security_counts == {"sql_security": 1}
    assert security_issues[0]["detector"] == "sql_security"
    assert security_issues[0]["tier"] == 1


def test_direct_smells_command_excludes_security_rules(
    set_project_root: Path, capsys
) -> None:
    root = set_project_root
    (root / "queries").mkdir()
    (root / "queries/mixed.sql").write_text(
        """SELECT * FROM jobs;
DROP TABLE old_jobs;
GRANT SELECT ON users TO PUBLIC;
"""
    )

    cmd_smells(argparse.Namespace(path=str(root), json=True, top=20))
    payload = json.loads(capsys.readouterr().out)

    assert payload["count"] == 1
    assert [entry["id"] for entry in payload["entries"]] == ["select_star"]
