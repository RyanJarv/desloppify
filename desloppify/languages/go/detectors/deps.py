"""Go dependency graph builder."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from desloppify.engine.detectors.graph import finalize_graph
from desloppify.languages.go.support import (
    GoModule,
    GoSourceFile,
    discover_go_modules,
    find_go_source_files,
    iter_import_specs,
    nearest_go_module,
    read_text_or_none,
    scan_root,
)


def _module_package_path(package_dir: Path, module: GoModule) -> str | None:
    try:
        rel_dir = package_dir.relative_to(module.root)
    except ValueError:
        return None
    if str(rel_dir) == ".":
        return module.module_path
    return f"{module.module_path}/{rel_dir.as_posix()}"


def _build_package_index(
    files: list[GoSourceFile],
    modules: list[GoModule],
    root: Path,
) -> tuple[dict[str, set[str]], dict[Path, set[str]]]:
    package_refs_by_dir: dict[Path, set[str]] = defaultdict(set)
    for source in files:
        if source.path.name.endswith("_test.go"):
            continue
        package_refs_by_dir[source.path.parent].add(source.ref)

    package_index: dict[str, set[str]] = defaultdict(set)
    for package_dir, refs in package_refs_by_dir.items():
        module = nearest_go_module(package_dir, modules)
        if module is not None:
            import_path = _module_package_path(package_dir, module)
            if import_path:
                package_index[import_path].update(refs)

        try:
            rel_dir = package_dir.relative_to(root)
        except ValueError:
            continue
        if str(rel_dir) != ".":
            package_index[rel_dir.as_posix()].update(refs)

    return dict(package_index), dict(package_refs_by_dir)


def _resolve_import(
    spec: str,
    *,
    source_path: Path,
    package_index: dict[str, set[str]],
    package_refs_by_dir: dict[Path, set[str]],
) -> set[str]:
    cleaned = spec.strip().strip("\"'`")
    if not cleaned or cleaned in {"C", "unsafe"}:
        return set()
    if cleaned.startswith("."):
        target_dir = (source_path.parent / cleaned).resolve()
        return set(package_refs_by_dir.get(target_dir, set()))
    return set(package_index.get(cleaned, set()))


def build_dep_graph(
    path: Path,
    roslyn_cmd: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build a Go dependency graph from local import declarations."""
    del roslyn_cmd
    files = find_go_source_files(path)
    graph = {source.ref: {"imports": set(), "importers": set()} for source in files}
    if not graph:
        return {}

    root = scan_root(path)
    modules = discover_go_modules(files)
    package_index, package_refs_by_dir = _build_package_index(files, modules, root)

    for source in files:
        content = read_text_or_none(source.path)
        if content is None:
            continue

        for spec in iter_import_specs(content):
            resolved_refs = _resolve_import(
                spec,
                source_path=source.path,
                package_index=package_index,
                package_refs_by_dir=package_refs_by_dir,
            )
            for resolved in resolved_refs:
                if resolved == source.ref:
                    continue
                graph[source.ref]["imports"].add(resolved)
                graph[resolved]["importers"].add(source.ref)

    return finalize_graph(graph)


__all__ = ["build_dep_graph"]
