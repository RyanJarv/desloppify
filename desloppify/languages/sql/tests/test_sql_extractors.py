from __future__ import annotations

from pathlib import Path

from desloppify.languages.sql.extractors import (
    extract_functions,
    extract_sqlc_queries,
    extract_sqlc_queries_from_text,
    extract_table_refs,
    extract_table_refs_from_text,
    find_sql_files,
    split_sql_statements,
)


def test_extract_sqlc_named_queries_from_text() -> None:
    sql = """-- name: ListStatusTableCounts :many
SELECT status, count(*)
FROM jobs
GROUP BY status;

-- name: GetJob :one
SELECT id, status
FROM jobs
WHERE id = $1;
"""

    queries = extract_sqlc_queries_from_text(sql, "pkg/dbquery/jobs.sql")

    assert [query.name for query in queries] == ["ListStatusTableCounts", "GetJob"]
    assert queries[0].command == ":many"
    assert queries[0].line == 1
    assert "GROUP BY status" in queries[0].body
    assert queries[1].line == 6


def test_extract_table_refs_from_text() -> None:
    sql = """
SELECT j.id, u.email
FROM jobs j
JOIN public.users u ON u.id = j.user_id;

UPDATE job_status SET stale = true WHERE id = $1;
INSERT INTO audit.events (id) VALUES ($1);
"""

    refs = extract_table_refs_from_text(sql, "queries.sql")

    assert [(ref.table, ref.line) for ref in refs] == [
        ("jobs", 3),
        ("public.users", 4),
        ("job_status", 6),
        ("audit.events", 7),
    ]


def test_extract_table_refs_handles_optional_ddl_clauses() -> None:
    sql = """
CREATE TABLE IF NOT EXISTS public.jobs (id bigint);
DROP TABLE IF EXISTS scratch_jobs;
"""

    refs = extract_table_refs_from_text(sql, "schema.sql")

    assert [(ref.table, ref.line) for ref in refs] == [
        ("public.jobs", 2),
        ("scratch_jobs", 3),
    ]


def test_split_sql_statements_preserves_postgres_dollar_quoted_body() -> None:
    sql = """
CREATE FUNCTION public.touch_job()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

SELECT 1;
"""

    statements = split_sql_statements(sql)

    assert len(statements) == 2
    assert "RETURN NEW;" in statements[0]["body"]
    assert statements[1]["body"] == "SELECT 1;"


def test_find_sql_files_excludes_generated_and_vendor(
    tmp_path: Path, set_project_root: Path
) -> None:
    root = set_project_root
    (root / "pkg/dbquery").mkdir(parents=True)
    (root / "pkg/dbquery/query.sql").write_text("SELECT 1;\n")
    (root / "vendor").mkdir()
    (root / "vendor/ignored.sql").write_text("SELECT 1;\n")
    (root / "generated").mkdir()
    (root / "generated/ignored.sql").write_text("SELECT 1;\n")
    (root / "pkg/dbquery/query.sql.go").write_text("// generated\n")

    assert find_sql_files(tmp_path) == ["pkg/dbquery/query.sql"]


def test_path_extractors_and_function_adapter(set_project_root: Path) -> None:
    root = set_project_root
    (root / "pkg/dbquery").mkdir(parents=True)
    (root / "pkg/dbquery/query.sql").write_text(
        """-- name: ListJobs :many
SELECT *
FROM jobs;
"""
    )

    queries = extract_sqlc_queries(root)
    refs = extract_table_refs(root)
    functions = extract_functions(root)

    assert [query.name for query in queries] == ["ListJobs"]
    assert [ref.table for ref in refs] == ["jobs"]
    assert functions[0].name == "ListJobs"
    assert functions[0].line == 1
