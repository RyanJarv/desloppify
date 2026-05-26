"""Sanity tests for Go language plugin.

Go plugin originally contributed by tinker495 (PR #128).
"""

from __future__ import annotations

from types import SimpleNamespace

import desloppify.languages.go as go_mod
from desloppify.base.runtime_state import RuntimeContext, runtime_scope
from desloppify.engine.hook_registry import get_lang_hook
from desloppify.engine.policy.zones import FileZoneMap, Zone
from desloppify.languages import get_lang
from desloppify.languages._framework.base.types import DetectorPhase


def test_config_name():
    cfg = get_lang("go")
    assert cfg.name == "go"


def test_config_extensions():
    cfg = get_lang("go")
    assert ".go" in cfg.extensions


def test_detect_markers():
    cfg = get_lang("go")
    assert "go.mod" in cfg.detect_markers


def test_detect_commands_non_empty():
    cfg = get_lang("go")
    assert cfg.detect_commands


def test_has_core_phases():
    cfg = get_lang("go")
    labels = {p.label for p in cfg.phases}
    assert "Structural analysis" in labels
    assert "Security" in labels
    assert "golangci-lint" in labels
    assert "go vet" in labels


def test_config_keeps_tree_sitter_phases_without_unused_imports(monkeypatch):
    def fake_all_treesitter_phases(spec_name: str):
        assert spec_name == "go"
        return [
            DetectorPhase("AST smells", lambda *_args: ([], {})),
            DetectorPhase("Responsibility cohesion", lambda *_args: ([], {})),
            DetectorPhase("Unused imports", lambda *_args: ([], {})),
        ]

    monkeypatch.setattr(go_mod, "all_treesitter_phases", fake_all_treesitter_phases)

    cfg = go_mod.GoConfig()
    labels = {p.label for p in cfg.phases}

    assert "AST smells" in labels
    assert "Responsibility cohesion" in labels
    assert "Unused imports" not in labels


def test_golangci_lint_phase_uses_v2_json_output(monkeypatch, tmp_path):
    cfg = get_lang("go")
    phase = next(p for p in cfg.phases if p.label == "golangci-lint")
    captured = {}

    def fake_run_tool_result(cmd, path, parser):
        captured["cmd"] = cmd
        return SimpleNamespace(status="empty", entries=[], meta={})

    monkeypatch.setattr(
        "desloppify.languages._framework.generic_parts.tool_factories.run_tool_result",
        fake_run_tool_result,
    )
    phase.run(tmp_path, cfg)

    assert "--output.json.path stdout" in captured["cmd"]
    assert "--show-stats=false" in captured["cmd"]
    assert "--out-format" not in captured["cmd"]


def test_golangci_lint_phase_uses_exact_package_dirs(monkeypatch, tmp_path):
    (tmp_path / "pkg" / "service").mkdir(parents=True)
    (tmp_path / "node_modules" / "template").mkdir(parents=True)
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    (tmp_path / "main.go").write_text("package main\n")
    (tmp_path / "pkg" / "service" / "service.go").write_text("package service\n")
    (tmp_path / "node_modules" / "template" / "bad.go").write_text("package bad\n")

    cfg = get_lang("go")
    phase = next(p for p in cfg.phases if p.label == "golangci-lint")
    captured = {}

    def fake_run_tool_result(cmd, path, parser):
        captured["cmd"] = cmd
        return SimpleNamespace(status="empty", entries=[], meta={})

    monkeypatch.setattr(
        "desloppify.languages._framework.generic_parts.tool_factories.run_tool_result",
        fake_run_tool_result,
    )
    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        phase.run(tmp_path, cfg)

    assert captured["cmd"].endswith(" . ./pkg/service")
    assert "./..." not in captured["cmd"]
    assert "node_modules" not in captured["cmd"]


def test_integration_depth_full():
    cfg = get_lang("go")
    assert cfg.integration_depth == "full"


def test_test_coverage_hooks_registered():
    assert get_lang_hook("go", "test_coverage") is not None


def test_go_test_files_classified_as_test_zone():
    cfg = get_lang("go")
    zone_map = FileZoneMap(
        ["pkg/foo.go", "pkg/foo_test.go"],
        cfg.zone_rules,
        rel_fn=lambda path: path,
    )
    assert zone_map.get("pkg/foo.go") == Zone.PRODUCTION
    assert zone_map.get("pkg/foo_test.go") == Zone.TEST


def test_go_vendor_classified_as_vendor():
    cfg = get_lang("go")
    zone_map = FileZoneMap(
        ["pkg/foo.go", "vendor/lib/bar.go"],
        cfg.zone_rules,
        rel_fn=lambda path: path,
    )
    assert zone_map.get("vendor/lib/bar.go") == Zone.VENDOR


def test_strip_test_markers():
    hook = get_lang_hook("go", "test_coverage")
    assert hook.strip_test_markers("utils_test.go") == "utils.go"
    assert hook.strip_test_markers("utils.go") is None


def test_map_test_to_source():
    hook = get_lang_hook("go", "test_coverage")
    prod = {"pkg/foo.go", "pkg/bar.go"}
    assert hook.map_test_to_source("pkg/foo_test.go", prod) == "pkg/foo.go"
    assert hook.map_test_to_source("pkg/baz_test.go", prod) is None
    assert hook.map_test_to_source("pkg/helpers.go", prod) is None
