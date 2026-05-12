from __future__ import annotations

from pathlib import Path

from desloppify.languages._framework.treesitter.imports.resolver_cache import (
    reset_import_cache,
)
from desloppify.languages.go.detectors.deps import (
    build_dep_graph,
    build_package_dep_graph,
)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_build_dep_graph_parses_single_and_grouped_imports_with_aliases(
    tmp_path: Path,
) -> None:
    reset_import_cache()
    _write(tmp_path / "go.mod", "module example.com/app\n")
    main_file = _write(
        tmp_path / "cmd" / "app" / "main.go",
        """
package main

import helper "example.com/app/pkg/helper"
import (
    . "example.com/app/pkg/dot"
    _ "example.com/app/pkg/blank"
)
""",
    )
    helper_file = _write(tmp_path / "pkg" / "helper" / "helper.go", "package helper\n")
    dot_file = _write(tmp_path / "pkg" / "dot" / "dot.go", "package dot\n")
    blank_file = _write(tmp_path / "pkg" / "blank" / "blank.go", "package blank\n")

    graph = build_dep_graph(tmp_path)

    assert graph[str(main_file)]["imports"] == {
        str(helper_file),
        str(dot_file),
        str(blank_file),
    }
    assert graph[str(helper_file)]["importers"] == {str(main_file)}
    assert graph[str(dot_file)]["importers"] == {str(main_file)}
    assert graph[str(blank_file)]["importers"] == {str(main_file)}
    reset_import_cache()


def test_build_dep_graph_resolves_local_package_to_scanned_package_files(
    tmp_path: Path,
) -> None:
    reset_import_cache()
    _write(tmp_path / "go.mod", "module example.com/app\n")
    source = _write(
        tmp_path / "main.go",
        'package main\nimport "example.com/app/pkg/service"\n',
    )
    first = _write(tmp_path / "pkg" / "service" / "a.go", "package service\n")
    second = _write(tmp_path / "pkg" / "service" / "b.go", "package service\n")
    test_file = _write(tmp_path / "pkg" / "service" / "a_test.go", "package service\n")

    graph = build_dep_graph(tmp_path)

    assert graph[str(source)]["imports"] == {str(first)}
    assert graph[str(first)]["importers"] == {str(source)}
    assert graph[str(second)]["importers"] == set()
    assert graph[str(test_file)]["importers"] == set()
    reset_import_cache()


def test_build_dep_graph_ignores_external_and_standard_library_imports(
    tmp_path: Path,
) -> None:
    reset_import_cache()
    _write(tmp_path / "go.mod", "module example.com/app\n")
    source = _write(
        tmp_path / "main.go",
        """
package main

import (
    "fmt"
    "github.com/acme/external"
)
""",
    )

    graph = build_dep_graph(tmp_path)

    assert graph[str(source)]["imports"] == set()
    assert graph[str(source)]["import_count"] == 0
    reset_import_cache()


def test_build_dep_graph_does_not_create_same_package_edges_or_cycles(
    tmp_path: Path,
) -> None:
    reset_import_cache()
    _write(tmp_path / "go.mod", "module example.com/app\n")
    first = _write(tmp_path / "pkg" / "thing" / "a.go", "package thing\n")
    second = _write(tmp_path / "pkg" / "thing" / "b.go", "package thing\n")

    graph = build_dep_graph(tmp_path)

    assert graph[str(first)]["imports"] == set()
    assert graph[str(first)]["importers"] == set()
    assert graph[str(second)]["imports"] == set()
    assert graph[str(second)]["importers"] == set()
    reset_import_cache()


def test_build_package_dep_graph_uses_package_directories(tmp_path: Path) -> None:
    reset_import_cache()
    _write(tmp_path / "go.mod", "module example.com/app\n")
    _write(
        tmp_path / "cmd" / "app" / "main.go",
        'package main\nimport "example.com/app/pkg/service"\n',
    )
    _write(tmp_path / "pkg" / "service" / "a.go", "package service\n")
    _write(tmp_path / "pkg" / "service" / "b.go", "package service\n")

    graph = build_package_dep_graph(tmp_path)

    source_pkg = str((tmp_path / "cmd" / "app").resolve())
    target_pkg = str((tmp_path / "pkg" / "service").resolve())
    assert graph[source_pkg]["imports"] == {target_pkg}
    assert graph[target_pkg]["importers"] == {source_pkg}
    reset_import_cache()
