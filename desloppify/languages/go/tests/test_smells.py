"""Tests for Go smell detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from desloppify.languages._framework.base.smell_contracts import (
    normalize_smell_entries,
)
from desloppify.languages.go.detectors.smells import detect_smells


def _write(tmp_path: Path, name: str, content: str) -> str:
    file = tmp_path / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(content)
    return str(file)


def _detect(tmp_path: Path) -> tuple[list[dict], int]:
    files = [str(file) for file in tmp_path.rglob("*.go")]
    with patch(
        "desloppify.languages.go.detectors.smells.find_go_files",
        return_value=files,
    ):
        return detect_smells(tmp_path)


def test_smell_entries_normalize_for_issue_factory(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "lib.go",
        "package lib\n\n// TODO fix\nfunc f() {\n    _ = doSomething()\n}\n",
    )

    entries, total = _detect(tmp_path)
    normalized = normalize_smell_entries(entries)

    assert total == 1
    assert {entry.smell_id for entry in normalized} == {"ignored_error", "todo_fixme"}
    assert all(entry.matches for entry in normalized)


def test_multiline_smells(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "lib.go",
        "package lib\n\n"
        "func f() {\n"
        "    err := doSomething()\n"
        "    if err != nil {\n"
        "    }\n"
        "    for i := 0; i < 10; i++ {\n"
        "        defer cleanup()\n"
        "    }\n"
        "    return\n"
        "    x := 2\n"
        "}\n",
    )

    entries, _ = _detect(tmp_path)

    assert {"empty_error_branch", "defer_in_loop", "unreachable_code"} <= {
        entry["id"] for entry in entries
    }


def test_naked_return_only_flags_named_results(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "lib.go",
        "package lib\n\n"
        "func voidReturn() {\n"
        "    return\n"
        "}\n\n"
        "func namedReturn() (value int, err error) {\n"
        "    return\n"
        "}\n",
    )

    entries, _ = _detect(tmp_path)
    naked_entries = [entry for entry in entries if entry["id"] == "naked_return"]

    assert len(naked_entries) == 1
    assert naked_entries[0]["count"] == 1


def test_global_var_skip_patterns(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "lib.go",
        "package lib\n\n"
        "var Cmd = &cobra.Command{}\n"
        "var re = regexp.MustCompile(`\\d+`)\n"
        "var (\n    x = 1\n)\n"
        "var GlobalState int\n",
    )

    entries, _ = _detect(tmp_path)
    global_entries = [entry for entry in entries if entry["id"] == "global_var"]

    assert len(global_entries) == 1
    assert global_entries[0]["count"] == 1


def test_panic_in_main_is_not_library_panic(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "main.go",
        "package main\n\nfunc main() {\n    panic(\"expected\")\n}\n",
    )

    entries, _ = _detect(tmp_path)

    assert "panic_in_lib" not in {entry["id"] for entry in entries}


def test_test_files_are_skipped(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "lib_test.go",
        "package lib\n\nfunc f() {\n    panic(\"test panic\")\n}\n",
    )

    entries, total = _detect(tmp_path)

    assert total == 1
    assert entries == []
