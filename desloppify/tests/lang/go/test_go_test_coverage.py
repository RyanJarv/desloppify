"""Tests for Go-specific coverage import mapping helpers."""

from __future__ import annotations

from desloppify.languages.go import test_coverage as go_cov


def test_resolve_import_spec_matches_relative_package_file():
    production = {"pkg/internal/util.go", "pkg/internal/mapper.go"}
    resolved = go_cov.resolve_import_spec("pkg/internal/util", "pkg/app/app_test.go", production)
    assert resolved == "pkg/internal/util.go"


def test_resolve_import_spec_matches_module_prefixed_path_by_suffix():
    production = {"pkg/service/handler.go"}
    resolved = go_cov.resolve_import_spec(
        "github.com/acme/project/pkg/service/handler",
        "pkg/service/handler_test.go",
        production,
    )
    assert resolved == "pkg/service/handler.go"


def test_resolve_import_spec_skips_special_imports():
    production = {"pkg/service/handler.go"}
    assert go_cov.resolve_import_spec("unsafe", "pkg/service/handler_test.go", production) is None


def test_resolve_import_spec_skips_stdlib_basename_collisions():
    production = {"pkg/foo/testing.go"}
    assert go_cov.resolve_import_spec("testing", "pkg/foo/foo_test.go", production) is None


def test_resolve_import_spec_skips_external_module_collisions(tmp_path):
    (tmp_path / "go.mod").write_text("module github.com/acme/project\n")
    source = tmp_path / "pkg/service/handler.go"
    source.parent.mkdir(parents=True)
    source.write_text("package service\n")
    test_file = tmp_path / "pkg/service/handler_test.go"
    test_file.write_text("package service_test\n")

    resolved = go_cov.resolve_import_spec(
        "github.com/other/project/pkg/service/handler",
        str(test_file),
        {str(source)},
    )

    assert resolved is None


def test_parse_test_import_specs_extracts_single_and_grouped_imports():
    content = """
package service_test

import "testing"

import (
    service "github.com/acme/project/pkg/service"
    _ "github.com/acme/project/pkg/internal/sideeffect"
    // "github.com/acme/project/pkg/commented"
)
"""

    assert go_cov.parse_test_import_specs(content) == [
        "testing",
        "github.com/acme/project/pkg/service",
        "github.com/acme/project/pkg/internal/sideeffect",
    ]
