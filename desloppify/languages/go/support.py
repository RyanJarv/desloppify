"""Shared Go source and package helpers."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from desloppify.base.discovery.file_paths import resolve_scan_file
from desloppify.base.discovery.paths import get_project_root
from desloppify.languages.go.extractors import find_go_files

_GO_IMPORT_DECL_RE = re.compile(
    r"""(?ms)^\s*import\s+(?P<body>\((?P<block>.*?)\)|(?:[._A-Za-z]\w*\s+)?["`][^"`]+["`])"""
)
_GO_STRING_RE = re.compile(r"""(?P<quote>["`])(?P<path>[^"`]+)(?P=quote)""")
_GO_MODULE_RE = re.compile(r"""(?m)^\s*module\s+(\S+)\s*$""")


@dataclass(frozen=True)
class GoSourceFile:
    """A discovered Go file with both graph and filesystem paths."""

    ref: str
    path: Path


@dataclass(frozen=True)
class GoModule:
    """A Go module declared by a go.mod file."""

    root: Path
    module_path: str


def scan_root(path: Path | str) -> Path:
    """Resolve the scan root using the active Desloppify project root."""
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.resolve()
    return (get_project_root() / candidate).resolve()


def find_go_source_files(path: Path | str) -> list[GoSourceFile]:
    """Find Go files and retain the reference shape used by source discovery."""
    root = scan_root(path)
    files: list[GoSourceFile] = []
    for ref in find_go_files(path):
        resolved = resolve_scan_file(ref, scan_root=root)
        files.append(GoSourceFile(ref=ref, path=resolved))
    return sorted(files, key=lambda item: item.ref)


def go_package_args(path: Path | str) -> list[str]:
    """Return exact Go package-directory args for the current scan."""
    root = scan_root(path)
    package_dirs = {source.path.parent for source in find_go_source_files(path)}
    args: list[str] = []
    for package_dir in sorted(package_dirs):
        try:
            rel_dir = package_dir.relative_to(root)
        except ValueError:
            args.append(str(package_dir))
            continue
        if str(rel_dir) == ".":
            args.append(".")
        else:
            args.append("./" + rel_dir.as_posix())
    return args or ["."]


def shell_join(parts: list[str]) -> str:
    """Join command parts for the existing generic tool runner interface."""
    return " ".join(shlex.quote(part) for part in parts)


def strip_go_comments(content: str) -> str:
    """Strip Go comments while preserving string literals."""
    out: list[str] = []
    in_block = False
    in_string: str | None = None
    i = 0
    while i < len(content):
        ch = content[i]
        nxt = content[i + 1] if i + 1 < len(content) else ""

        if in_block:
            if ch == "\n":
                out.append("\n")
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue

        if in_string is not None:
            out.append(ch)
            if ch == "\\" and i + 1 < len(content):
                out.append(content[i + 1])
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in ('"', "`"):
            in_string = ch
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch == "/" and nxt == "/":
            while i < len(content) and content[i] != "\n":
                i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def iter_import_specs(content: str) -> list[str]:
    """Extract Go import path strings from single and grouped imports."""
    stripped = strip_go_comments(content)
    specs: list[str] = []
    for match in _GO_IMPORT_DECL_RE.finditer(stripped):
        body = match.group("block") or match.group("body")
        specs.extend(path.group("path") for path in _GO_STRING_RE.finditer(body))
    return specs


def read_text_or_none(path: Path) -> str | None:
    """Read text from a file, returning None when it cannot be read."""
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def read_module_path(go_mod: Path) -> str | None:
    """Read the module path from a go.mod file."""
    content = read_text_or_none(go_mod)
    if content is None:
        return None
    match = _GO_MODULE_RE.search(content)
    if match:
        return match.group(1)
    return None


def nearest_go_module(start: Path, modules: list[GoModule]) -> GoModule | None:
    """Return the nearest known Go module containing a path."""
    matches: list[GoModule] = []
    for module in modules:
        try:
            start.relative_to(module.root)
        except ValueError:
            continue
        matches.append(module)
    if not matches:
        return None
    return max(matches, key=lambda module: len(module.root.parts))


def discover_go_modules(files: list[GoSourceFile]) -> list[GoModule]:
    """Discover modules by walking from source files to nearest go.mod files."""
    go_mods: set[Path] = set()
    for source in files:
        for candidate in (source.path.parent, *source.path.parents):
            go_mod = candidate / "go.mod"
            if go_mod.is_file():
                go_mods.add(go_mod)
                break

    modules: list[GoModule] = []
    for go_mod in sorted(go_mods):
        module_path = read_module_path(go_mod)
        if module_path:
            modules.append(GoModule(root=go_mod.parent.resolve(), module_path=module_path))
    return modules
