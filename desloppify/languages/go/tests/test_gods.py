"""Tests for Go god struct extraction."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from desloppify.engine.detectors.gods import detect_gods
from desloppify.languages.go.detectors.gods import GO_GOD_RULES, extract_go_structs


def _write(tmp_path: Path, name: str, content: str) -> str:
    file = tmp_path / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(content)
    return str(file)


def _extract(tmp_path: Path) -> list:
    files = [str(file) for file in tmp_path.rglob("*.go")]
    with patch("desloppify.languages.go.detectors.gods.find_go_files", return_value=files):
        return extract_go_structs(tmp_path)


def test_extract_simple_struct(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "model.go",
        "package model\n\ntype User struct {\n    Name string\n    Age  int\n}\n",
    )

    structs = _extract(tmp_path)

    assert len(structs) == 1
    assert structs[0].name == "User"
    assert structs[0].attributes == ["Name", "Age"]


def test_extract_struct_with_methods_across_files(tmp_path: Path) -> None:
    _write(tmp_path, "model.go", "package model\n\ntype User struct {\n    Name string\n}\n")
    _write(
        tmp_path,
        "user_methods.go",
        "package model\n\nfunc (u *User) Validate() error {\n    return nil\n}\n",
    )

    structs = _extract(tmp_path)

    assert len(structs) == 1
    assert [method.name for method in structs[0].methods] == ["Validate"]
    assert structs[0].metrics["method_count"] == 1
    assert structs[0].metrics["field_count"] == 1


def test_extract_multiple_structs(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "model.go",
        "package model\n\n"
        "type User struct {\n    Name string\n}\n\n"
        "type Order struct {\n    ID int\n    Item string\n}\n",
    )

    structs = _extract(tmp_path)

    assert {struct.name for struct in structs} == {"User", "Order"}


def test_methods_do_not_bleed_between_packages(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/a/config.go", "package a\n\ntype Config struct {\n    A int\n}\n")
    _write(tmp_path, "pkg/a/config_methods.go", "package a\n\nfunc (c *Config) AOnly() {}\n")
    _write(tmp_path, "pkg/b/config.go", "package b\n\ntype Config struct {\n    B int\n}\n")
    _write(tmp_path, "pkg/b/config_methods.go", "package b\n\nfunc (c *Config) BOnly() {}\n")

    structs = sorted(_extract(tmp_path), key=lambda struct: struct.file)

    assert len(structs) == 2
    assert [method.name for method in structs[0].methods] == ["AOnly"]
    assert [method.name for method in structs[1].methods] == ["BOnly"]


def test_god_struct_detected_by_shared_detector(tmp_path: Path) -> None:
    methods = "\n".join(f"func (s *Big) Method{i}() {{}}" for i in range(12))
    fields = "\n".join(f"    Field{i} int" for i in range(16))
    _write(
        tmp_path,
        "big.go",
        f"package big\n\ntype Big struct {{\n{fields}\n}}\n\n{methods}\n",
    )

    structs = _extract(tmp_path)
    entries, total = detect_gods(structs, GO_GOD_RULES, min_reasons=2)

    assert total == 1
    assert len(entries) == 1
    assert entries[0]["name"] == "Big"
    assert len(entries[0]["reasons"]) >= 2


def test_god_rules_thresholds() -> None:
    rules_by_name = {rule.name: rule for rule in GO_GOD_RULES}

    assert rules_by_name["method_count"].threshold == 10
    assert rules_by_name["field_count"].threshold == 15
    assert rules_by_name["loc"].threshold == 300
