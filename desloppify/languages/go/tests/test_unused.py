"""Tests for staticcheck-based Go unused detection."""

from __future__ import annotations

from subprocess import TimeoutExpired
from unittest.mock import Mock, patch

from desloppify.languages.go.detectors.unused import (
    _extract_name,
    _parse_staticcheck_output,
    _try_staticcheck,
    detect_unused,
)


def test_extract_name_variants() -> None:
    assert _extract_name('"MyFunc" is unused') == "MyFunc"
    assert _extract_name("MyFunc is unused") == "MyFunc"
    assert _extract_name('"x" is assigned but never used') == "x"
    assert _extract_name("something else entirely") == "something"


def test_parse_staticcheck_output_filters_and_categories() -> None:
    lines = [
        "pkg/handler.go:10:6: U1000 func handleRequest is unused",
        'pkg/handler.go:15:2: SA4006 "result" is assigned but never used',
        "pkg/handler_test.go:10:6: U1000 func testHelper is unused",
        "pkg/handler.go:20:6: U1000 func _internalHelper is unused",
        "not a valid staticcheck line",
    ]

    entries = _parse_staticcheck_output(lines, "all", "/project")

    assert [entry["name"] for entry in entries] == ["handleRequest", "result"]
    assert [entry["category"] for entry in entries] == ["exports", "vars"]
    assert entries[0]["file"] == "/project/pkg/handler.go"


def test_parse_staticcheck_output_respects_category() -> None:
    lines = [
        "pkg/handler.go:10:6: U1000 func handleRequest is unused",
        'pkg/handler.go:15:2: SA4006 "result" is assigned but never used',
    ]

    exports = _parse_staticcheck_output(lines, "exports", "/project")
    vars_ = _parse_staticcheck_output(lines, "vars", "/project")

    assert [entry["category"] for entry in exports] == ["exports"]
    assert [entry["category"] for entry in vars_] == ["vars"]


def test_try_staticcheck_parses_subprocess_output(tmp_path) -> None:
    proc = Mock(
        stdout="pkg/handler.go:10:6: U1000 func handleRequest is unused\n",
        stderr="",
    )
    with patch(
        "desloppify.languages.go.detectors.unused.subprocess.run",
        return_value=proc,
    ):
        result = _try_staticcheck(tmp_path, "all")

    assert result is not None
    entries, available = result
    assert available is True
    assert entries[0]["name"] == "handleRequest"


def test_try_staticcheck_missing_or_timed_out_degrades(tmp_path) -> None:
    with patch(
        "desloppify.languages.go.detectors.unused.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        assert _try_staticcheck(tmp_path, "all") is None

    with patch(
        "desloppify.languages.go.detectors.unused.subprocess.run",
        side_effect=TimeoutExpired(cmd="staticcheck", timeout=120),
    ):
        assert _try_staticcheck(tmp_path, "all") is None


def test_detect_unused_reports_staticcheck_availability(tmp_path) -> None:
    mock_entries = [
        {"file": "a.go", "line": 5, "col": 1, "name": "unused", "category": "exports"}
    ]
    with patch(
        "desloppify.languages.go.detectors.unused.find_go_files",
        return_value=["a.go", "b.go"],
    ), patch(
        "desloppify.languages.go.detectors.unused._try_staticcheck",
        return_value=(mock_entries, True),
    ):
        entries, total, available = detect_unused(tmp_path)

    assert entries == mock_entries
    assert total == 2
    assert available is True


def test_detect_unused_missing_staticcheck_is_empty(tmp_path) -> None:
    with patch(
        "desloppify.languages.go.detectors.unused.find_go_files",
        return_value=["a.go"],
    ), patch(
        "desloppify.languages.go.detectors.unused._try_staticcheck",
        return_value=None,
    ):
        entries, total, available = detect_unused(tmp_path)

    assert entries == []
    assert total == 1
    assert available is False
