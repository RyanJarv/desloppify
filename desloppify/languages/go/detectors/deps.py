"""Go dependency graph builder."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from desloppify.base.discovery.file_paths import resolve_path
from desloppify.engine.detectors.graph import finalize_graph
from desloppify.languages._framework.treesitter.imports.resolver_cache import (
    read_go_module_path,
)
from desloppify.languages._framework.treesitter.imports.resolvers_backend import (
    resolve_go_import,
)
from desloppify.languages.go.extractors import find_go_files

_SINGLE_IMPORT_RE = re.compile(
    r"""(?m)^\s*import\s+(?:[._A-Za-z]\w*\s+|\.\s+)?["`]([^"`\n]+)["`]"""
)
_GROUP_IMPORT_RE = re.compile(r"""(?ms)^\s*import\s*\((.*?)\)""")
_GROUP_IMPORT_SPEC_RE = re.compile(
    r"""(?m)^\s*(?:[._A-Za-z]\w*\s+|\.\s+)?["`]([^"`\n]+)["`]"""
)


def _find_go_module_root(path: Path) -> Path:
    cursor = path if path.is_dir() else path.parent
    for candidate in (cursor, *cursor.parents):
        if (candidate / "go.mod").is_file():
            return candidate
    return cursor


def _strip_go_comments(content: str) -> str:
    """Remove Go comments while preserving string literals for import parsing."""
    result: list[str] = []
    i = 0
    length = len(content)
    while i < length:
        char = content[i]
        next_char = content[i + 1] if i + 1 < length else ""

        if char == "/" and next_char == "/":
            result.extend("  ")
            i += 2
            while i < length and content[i] != "\n":
                result.append(" ")
                i += 1
            continue

        if char == "/" and next_char == "*":
            result.extend("  ")
            i += 2
            while i < length:
                if content[i] == "*" and i + 1 < length and content[i + 1] == "/":
                    result.extend("  ")
                    i += 2
                    break
                result.append("\n" if content[i] == "\n" else " ")
                i += 1
            continue

        if char == '"':
            result.append(char)
            i += 1
            while i < length:
                result.append(content[i])
                if content[i] == "\\":
                    i += 1
                    if i < length:
                        result.append(content[i])
                elif content[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        if char == "`":
            result.append(char)
            i += 1
            while i < length:
                result.append(content[i])
                if content[i] == "`":
                    i += 1
                    break
                i += 1
            continue

        result.append(char)
        i += 1

    return "".join(result)


def _iter_go_imports(content: str) -> list[str]:
    cleaned = _strip_go_comments(content)
    imports: list[str] = []
    grouped_spans: list[tuple[int, int]] = []

    for match in _GROUP_IMPORT_RE.finditer(cleaned):
        grouped_spans.append(match.span())
        imports.extend(_GROUP_IMPORT_SPEC_RE.findall(match.group(1)))

    for match in _SINGLE_IMPORT_RE.finditer(cleaned):
        start = match.start()
        in_group = any(
            span_start <= start < span_end for span_start, span_end in grouped_spans
        )
        if in_group:
            continue
        imports.append(match.group(1))

    return imports


def _target_package_files(
    resolved_package_file: str,
    *,
    source_file: str,
    files_by_dir: dict[Path, list[str]],
) -> list[str]:
    target_dir = Path(resolved_package_file).resolve().parent
    source_dir = Path(source_file).resolve().parent
    if target_dir == source_dir:
        return []
    return files_by_dir.get(target_dir, [])


def build_dep_graph(
    path: Path,
    roslyn_cmd: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build a representative Go dependency graph from local package imports.

    Go imports packages rather than files. For the shared file-oriented deps
    command we represent a package import with one stable non-test file from the
    target package instead of fanning out to every file in that package.
    """
    del roslyn_cmd
    files = find_go_files(path)
    abs_files = [str(Path(resolve_path(filepath)).resolve()) for filepath in files]
    graph = {filepath: {"imports": set(), "importers": set()} for filepath in abs_files}
    if not graph:
        return {}

    module_root = _find_go_module_root(Path(path).resolve())
    production_files = {
        filepath for filepath in abs_files if not filepath.endswith("_test.go")
    }
    files_by_dir: dict[Path, list[str]] = {}
    for filepath in sorted(production_files):
        files_by_dir.setdefault(Path(filepath).parent, []).append(filepath)

    for filepath in abs_files:
        try:
            content = Path(filepath).read_text(errors="replace")
        except OSError as exc:
            _ = (filepath, exc)
            continue

        for import_path in _iter_go_imports(content):
            resolved = resolve_go_import(import_path, filepath, str(module_root))
            if resolved is None:
                continue

            targets = _target_package_files(
                resolved,
                source_file=filepath,
                files_by_dir=files_by_dir,
            )
            if not targets:
                continue
            target = targets[0]
            if target == filepath or target not in graph:
                continue
            graph[filepath]["imports"].add(target)
            graph[target]["importers"].add(filepath)

    return finalize_graph(graph)


def build_package_dep_graph(
    path: Path,
) -> dict[str, dict[str, Any]]:
    """Build a package-directory graph for Go package cycle detection."""
    files = find_go_files(path)
    abs_files = [str(Path(resolve_path(filepath)).resolve()) for filepath in files]
    if not abs_files:
        return {}

    module_root = _find_go_module_root(Path(path).resolve())
    module_path = read_go_module_path(str(module_root / "go.mod"))
    package_dirs = {
        str(Path(filepath).parent)
        for filepath in abs_files
        if not filepath.endswith("_test.go")
    }
    graph: dict[str, dict[str, Any]] = {
        package_dir: {"imports": set(), "importers": set()}
        for package_dir in sorted(package_dirs)
    }

    for filepath in abs_files:
        if filepath.endswith("_test.go"):
            continue
        source_package = str(Path(filepath).parent)
        try:
            content = Path(filepath).read_text(errors="replace")
        except OSError:
            continue

        for import_path in _iter_go_imports(content):
            target_package = _resolve_package_dir(
                import_path,
                module_root=module_root,
                module_path=module_path,
                package_dirs=package_dirs,
            )
            if target_package is None or target_package == source_package:
                continue
            graph[source_package]["imports"].add(target_package)
            graph[target_package]["importers"].add(source_package)

    return finalize_graph(graph)


def _resolve_package_dir(
    import_path: str,
    *,
    module_root: Path,
    module_path: str,
    package_dirs: set[str],
) -> str | None:
    if not module_path or not import_path.startswith(module_path):
        return None
    rel_path = import_path[len(module_path) :].lstrip("/")
    candidate = str((module_root / rel_path).resolve())
    return candidate if candidate in package_dirs else None


__all__ = ["build_dep_graph", "build_package_dep_graph"]
