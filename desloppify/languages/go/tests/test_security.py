"""Tests for Go-specific security detection."""

from __future__ import annotations

from pathlib import Path

from desloppify.engine.policy.zones import FileZoneMap, Zone, ZoneRule
from desloppify.languages.go.detectors.security import detect_go_security


def _write(tmp_path: Path, name: str, content: str) -> str:
    source = tmp_path / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content)
    return str(source)


def _detect(tmp_path: Path, filename: str, content: str) -> tuple[list[dict], int]:
    filepath = _write(tmp_path, filename, content)
    return detect_go_security([filepath], zone_map=None)


def _kinds(entries: list[dict]) -> set[str]:
    return {entry["detail"]["kind"] for entry in entries}


def test_detect_go_security_flags_unsafe_pointer(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "hack.go",
        """package hack

import "unsafe"

func f() {
    p := unsafe.Pointer(nil)
    _ = p
}
""",
    )

    assert scanned == 1
    assert "unsafe_pointer" in _kinds(entries)


def test_detect_go_security_flags_sql_concat(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "db.go",
        """package db

func f(db *sql.DB, name string) {
    db.Query("SELECT * FROM users WHERE name = " + name)
}
""",
    )

    assert scanned == 1
    assert "sql_injection" in _kinds(entries)


def test_detect_go_security_flags_weak_crypto(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "hash.go",
        """package hash

func f() {
    h := md5.New()
    _ = h
}
""",
    )

    assert scanned == 1
    assert "weak_crypto" in _kinds(entries)


def test_detect_go_security_suppresses_literal_exec_command(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "exec.go",
        """package exec

func f() {
    exec.Command("ls", "-la")
}
""",
    )

    assert scanned == 1
    assert "command_injection" not in _kinds(entries)


def test_detect_go_security_flags_hardcoded_credentials(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "auth.go",
        """package auth

func f() {
    password := "supersecretpassword123"
    _ = password
}
""",
    )

    assert scanned == 1
    assert "hardcoded_credentials" in _kinds(entries)


def test_detect_go_security_flags_insecure_tls(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "tls.go",
        """package lib

import "crypto/tls"

func f() *tls.Config {
    return &tls.Config{InsecureSkipVerify: true}
}
""",
    )

    assert scanned == 1
    assert "insecure_tls" in _kinds(entries)


def test_detect_go_security_skips_test_zone(tmp_path: Path) -> None:
    filepath = _write(
        tmp_path,
        "auth_test.go",
        """package auth

func f() {
    password := "supersecretpassword123"
    _ = password
}
""",
    )
    zone_map = FileZoneMap(
        [filepath],
        [ZoneRule(Zone.TEST, ["_test.go"])],
        rel_fn=lambda path: Path(path).name,
    )

    entries, scanned = detect_go_security([filepath], zone_map)

    assert scanned == 0
    assert entries == []


def test_detect_go_security_skips_comments(tmp_path: Path) -> None:
    entries, scanned = _detect(
        tmp_path,
        "comments.go",
        """package comments

// p := unsafe.Pointer(nil)
/*
password := "supersecretpassword123"
return &tls.Config{InsecureSkipVerify: true}
*/
func f() {}
""",
    )

    assert scanned == 1
    assert entries == []
