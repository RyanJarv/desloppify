from __future__ import annotations

import desloppify.languages.cxx as cxx_mod
from desloppify.languages._framework.base.types import DetectorPhase


def test_cxx_uses_full_plugin_config():
    cfg = cxx_mod.CxxConfig()
    assert cfg.name == "cxx"
    assert callable(cfg.build_dep_graph)
    assert callable(cfg.extract_functions)
    assert cfg.review_guidance


def test_cxx_keeps_cppcheck_phase():
    cfg = cxx_mod.CxxConfig()
    labels = {phase.label for phase in cfg.phases}
    assert "cppcheck" in labels


def test_cxx_includes_tree_sitter_phases(monkeypatch):
    captured: dict[str, object] = {}
    sentinel = DetectorPhase("Tree-sitter sentinel", lambda *_args: ([], {}))

    def fake_all_treesitter_phases(
        spec_name: str, *, include_unused_imports: bool = True
    ):
        captured["spec_name"] = spec_name
        captured["include_unused_imports"] = include_unused_imports
        return [sentinel]

    monkeypatch.setattr(
        cxx_mod,
        "all_treesitter_phases",
        fake_all_treesitter_phases,
        raising=False,
    )

    cfg = cxx_mod.CxxConfig()
    labels = {phase.label for phase in cfg.phases}

    assert captured["spec_name"] == "cpp"
    assert captured["include_unused_imports"] is False
    assert "Tree-sitter sentinel" in labels


def test_cxx_excludes_unused_imports_phase():
    cfg = cxx_mod.CxxConfig()
    labels = {phase.label for phase in cfg.phases}
    assert "Unused imports" not in labels
