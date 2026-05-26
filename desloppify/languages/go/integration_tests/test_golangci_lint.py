"""Integration tests for the Go golangci-lint detector phase."""

from __future__ import annotations

from pathlib import Path

from desloppify.base.runtime_state import RuntimeContext, runtime_scope
from desloppify.languages import get_lang


def _write(root: Path, rel_path: str, content: str) -> None:
    target = root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def test_golangci_lint_phase_reports_unused_import(tmp_path, monkeypatch):
    _write(tmp_path, "go.mod", "module example.com/desloppifygolangci\n")
    _write(
        tmp_path,
        "main.go",
        """
package main

import "fmt"

func main() {}
""",
    )

    cfg = get_lang("go")
    phase = next(phase for phase in cfg.phases if phase.label == "golangci-lint")

    monkeypatch.chdir(tmp_path)
    with runtime_scope(RuntimeContext(project_root=tmp_path)):
        issues, potential = phase.run(tmp_path, cfg)

    assert potential["golangci_lint"] >= 1
    assert any(
        issue["file"] == "main.go"
        and "imported and not used" in issue["summary"]
        for issue in issues
    )
