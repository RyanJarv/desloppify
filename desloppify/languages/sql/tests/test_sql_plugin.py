from __future__ import annotations

from desloppify.languages.framework import get_lang
from desloppify.languages.sql import SqlConfig, build_sql_dep_graph, register
from desloppify.languages.sql.commands import get_detect_commands


def test_sql_config_registration_and_shape() -> None:
    register()
    config = get_lang("sql")

    assert isinstance(config, SqlConfig)
    assert config.name == "sql"
    assert config.extensions == [".sql"]
    assert callable(config.file_finder)
    assert callable(config.extract_functions)
    assert callable(config.build_dep_graph)
    assert "sqlc.yaml" in config.detect_markers


def test_sql_detect_commands_include_queries_smells_tables_security() -> None:
    commands = get_detect_commands()

    for name in ("queries", "smells", "tables", "security"):
        assert name in commands
        assert callable(commands[name])


def test_sql_dep_graph_tracks_table_metadata(set_project_root) -> None:
    root = set_project_root
    (root / "queries").mkdir()
    (root / "queries/query.sql").write_text("SELECT * FROM public.jobs;\n")

    graph = build_sql_dep_graph(root)

    assert graph["queries/query.sql"]["tables"] == ["public.jobs"]
    assert graph["queries/query.sql"]["imports"] == set()
