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

    assert graph["main.go"]["imports"] == {"pkg/service/service.go"}
    assert "main.go" in graph["pkg/service/service.go"]["importers"]


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

    assert graph["pkg/service/service_test.go"]["imports"] == {"pkg/service/service.go"}
    assert "pkg/service/service_test.go" in graph["pkg/service/service.go"]["importers"]


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

    assert graph["main.go"]["imports"] == set()


def test_go_package_args_use_exact_discovered_dirs_and_exclusions(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n")
    _write(tmp_path, "main.go", "package main\n")
    _write(tmp_path, "pkg/service/service.go", "package service\n")
    _write(tmp_path, "node_modules/template/bad.go", "package bad\n")

    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        args = go_package_args(tmp_path)

    assert args == [".", "./pkg/service"]
