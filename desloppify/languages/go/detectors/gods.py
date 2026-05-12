"""Go god struct extraction for the shared god detector."""

from __future__ import annotations

import re
from pathlib import Path

from desloppify.base.discovery.file_paths import resolve_scan_file
from desloppify.engine.detectors.base import ClassInfo, FunctionInfo, GodRule
from desloppify.languages.go.extractors import find_go_files

_RECEIVER_RE = re.compile(
    r"^func\s+\(\s*\w+\s+\*?(\w+)(?:\[[\w,\s]+\])?\s*\)\s+(\w+)"
)
_STRUCT_DECL_RE = re.compile(r"^type\s+(\w+)\s+struct\s*\{")

GO_GOD_RULES: list[GodRule] = [
    GodRule(
        name="method_count",
        description="methods",
        extract=lambda cls: len(cls.methods),
        threshold=10,
    ),
    GodRule(
        name="field_count",
        description="fields",
        extract=lambda cls: len(cls.attributes),
        threshold=15,
    ),
    GodRule(
        name="loc",
        description="LOC",
        extract=lambda cls: cls.loc,
        threshold=300,
    ),
]


def extract_go_structs(path: Path) -> list[ClassInfo]:
    """Extract Go structs as ClassInfo records with fields and receiver methods."""
    files = find_go_files(path)
    methods_by_struct = _collect_receiver_methods(path, files)

    structs: list[ClassInfo] = []
    for filepath in files:
        try:
            content = _read_source(path, filepath)
        except OSError:
            continue
        structs.extend(_extract_structs_from_file(filepath, content, methods_by_struct))
    return structs


def _collect_receiver_methods(
    scan_root: Path,
    files: list[str],
) -> dict[tuple[str, str], list[FunctionInfo]]:
    methods_by_struct: dict[tuple[str, str], list[FunctionInfo]] = {}
    for filepath in files:
        try:
            lines = _read_source(scan_root, filepath).splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, start=1):
            match = _RECEIVER_RE.match(line.strip())
            if not match:
                continue
            struct_name, method_name = match.groups()
            key = (str(resolve_scan_file(filepath, scan_root=scan_root).parent), struct_name)
            methods_by_struct.setdefault(key, []).append(
                FunctionInfo(
                    name=method_name,
                    file=filepath,
                    line=index,
                    end_line=index,
                    loc=1,
                    body=line,
                )
            )
    return methods_by_struct


def _read_source(scan_root: Path, filepath: str) -> str:
    return resolve_scan_file(filepath, scan_root=scan_root).read_text(errors="replace")


def _extract_structs_from_file(
    filepath: str,
    content: str,
    methods_by_struct: dict[tuple[str, str], list[FunctionInfo]],
) -> list[ClassInfo]:
    lines = content.splitlines()
    structs: list[ClassInfo] = []
    index = 0
    while index < len(lines):
        match = _STRUCT_DECL_RE.match(lines[index].strip())
        if not match:
            index += 1
            continue

        struct_name = match.group(1)
        start_line = index + 1
        end_index, fields = _read_struct_body(lines, index + 1)
        end_line = min(len(lines), end_index + 1)
        struct_dir = str(Path(filepath).resolve().parent) if Path(filepath).is_absolute() else ""
        methods = methods_by_struct.get((struct_dir, struct_name), [])
        if not methods and not Path(filepath).is_absolute():
            # Relative paths from tests/scans are keyed by their resolved source
            # path in _collect_receiver_methods. Fall back to basename matching
            # only when there is exactly one matching package key.
            matches = [
                values
                for (package_dir, name), values in methods_by_struct.items()
                if name == struct_name and package_dir.endswith(str(Path(filepath).parent))
            ]
            if len(matches) == 1:
                methods = matches[0]

        structs.append(
            ClassInfo(
                name=struct_name,
                file=filepath,
                line=start_line,
                loc=max(1, end_line - start_line + 1),
                methods=methods,
                attributes=fields,
                metrics={
                    "method_count": len(methods),
                    "field_count": len(fields),
                    "name": struct_name,
                },
            )
        )
        index = end_index + 1
    return structs


def _read_struct_body(lines: list[str], start_index: int) -> tuple[int, list[str]]:
    depth = 1
    fields: list[str] = []
    index = start_index
    while index < len(lines) and depth > 0:
        stripped = lines[index].strip()
        depth += stripped.count("{") - stripped.count("}")
        if depth > 0:
            field_name = _field_name(stripped)
            if field_name:
                fields.append(field_name)
        index += 1
    return index - 1, fields


def _field_name(stripped_line: str) -> str | None:
    if not stripped_line or stripped_line.startswith(("//", "/*", "*", "}")):
        return None
    parts = stripped_line.split()
    if len(parts) < 2:
        return None
    return parts[0].rstrip(",")


__all__ = ["GO_GOD_RULES", "extract_go_structs"]
