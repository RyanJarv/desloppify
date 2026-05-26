"""Tests for Go dependency graph and package discovery."""

from __future__ import annotations

from pathlib import Path

from desloppify.base.runtime_state import RuntimeContext, runtime_scope
from desloppify.languages.go.detectors.deps import build_dep_graph
from desloppify.languages.go.support import go_package_args


def _write(root: Path, rel_path: str, content: str) -> None:
    target = root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def test_build_dep_graph_resolves_module_imports(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(
        tmp_path,
        "main.go",
        'package main\n\nimport "example.com/app/pkg/service"\n',
    )
    _write(tmp_path, "pkg/service/service.go", "package service\nfunc Run() {}\n")

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        graph = build_dep_graph(tmp_path)

    main = str(tmp_path / "main.go")
    service = str(tmp_path / "pkg/service/service.go")
    assert all(Path(key).is_absolute() for key in graph)
    assert graph[main]["imports"] == {service}
    assert main in graph[service]["importers"]


def test_build_dep_graph_resolves_external_test_package_imports(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(tmp_path, "pkg/service/service.go", "package service\nfunc Run() {}\n")
    _write(
        tmp_path,
        "pkg/service/service_test.go",
        'package service_test\n\nimport "example.com/app/pkg/service"\n',
    )

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        graph = build_dep_graph(tmp_path)

    test_file = str(tmp_path / "pkg/service/service_test.go")
    service = str(tmp_path / "pkg/service/service.go")
    assert graph[test_file]["imports"] == {service}
    assert test_file in graph[service]["importers"]


def test_build_dep_graph_ignores_external_and_stdlib_imports(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(
        tmp_path,
        "main.go",
        """
package main

import (
    "fmt"
    "github.com/acme/external/pkg"
)
""",
    )

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        graph = build_dep_graph(tmp_path)

    assert graph[str(tmp_path / "main.go")]["imports"] == set()


def test_go_package_args_use_exact_discovered_dirs_and_exclusions(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(tmp_path, "main.go", "package main\n")
    _write(tmp_path, "pkg/service/service.go", "package service\n")
    _write(tmp_path, "node_modules/template/bad.go", "package bad\n")

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        args = go_package_args(tmp_path)

    assert args == [".", "./pkg/service"]


def test_go_package_args_exclude_build_tag_only_dirs(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(tmp_path, "main.go", "package main\n")
    _write(
        tmp_path,
        "winonly/win.go",
        "//go:build windows\n\npackage winonly\n",
    )

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        args = go_package_args(tmp_path)

    assert args == ["."]


def test_go_package_args_exclude_nested_modules_outside_workspace(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(tmp_path, "main.go", "package main\n")
    _write(tmp_path, "sub/go.mod", "module example.com/sub\n")
    _write(tmp_path, "sub/pkg/pkg.go", "package pkg\n")

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        args = go_package_args(tmp_path)

    assert args == ["."]


def test_build_dep_graph_reads_module_lines_with_comments(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app // root module\n")
    _write(
        tmp_path,
        "main.go",
        'package main\n\nimport "example.com/app/pkg/service"\n',
    )
    _write(tmp_path, "pkg/service/service.go", "package service\nfunc Run() {}\n")

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        graph = build_dep_graph(tmp_path)

    main = str(tmp_path / "main.go")
    service = str(tmp_path / "pkg/service/service.go")
    assert graph[main]["imports"] == {service}
