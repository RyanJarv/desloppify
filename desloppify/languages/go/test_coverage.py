"""Go-specific test coverage heuristics and mappings.

Originally contributed by tinker495 (KyuSeok Jung) in PR #128.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from desloppify.languages.go.support import (
    iter_import_specs,
    read_module_path,
    strip_go_comments,
)

ASSERT_PATTERNS = [
    re.compile(p)
    for p in [
        r"\bt\.Error",
        r"\bt\.Fatal",
        r"\bt\.Fail",
        r"\bassert\.",
        r"\brequire\.",
        r"\bExpect\(",
    ]
]
MOCK_PATTERNS = [
    re.compile(p)
    for p in [
        r"\bgomock\.NewController",
        r"\bmock\.",
        r"\.EXPECT\(\)",
    ]
]
SNAPSHOT_PATTERNS: list[re.Pattern[str]] = []
TEST_FUNCTION_RE = re.compile(r"(?m)^func\s+Test\w+\(.*?\*testing\.T\)")
BARREL_BASENAMES: set[str] = set()


def has_testable_logic(_filepath: str, content: str) -> bool:
    """Return True when a Go file contains func declarations."""
    return bool(re.search(r"(?m)^func\s+", content))


def resolve_import_spec(
    spec: str, test_path: str, production_files: set[str]
) -> str | None:
    """Best-effort Go import-path to source-file resolution for direct imports."""
    normalized = spec.strip().strip("\"'`").replace("\\", "/").strip("/")
    if not normalized or normalized in {"C", "unsafe"}:
        return None
    if _is_non_local_import(normalized, test_path):
        return None

    segments = [segment for segment in normalized.split("/") if segment]
    if not segments:
        return None

    candidates: list[str] = []
    for idx in range(len(segments)):
        tail = "/".join(segments[idx:])
        if not tail:
            continue
        leaf = tail.split("/")[-1]
        candidates.append(f"{tail}.go")
        candidates.append(f"{tail}/{leaf}.go")

    test_path = test_path.replace("\\", "/").strip()
    if test_path:
        test_dir = os.path.dirname(test_path)
        leaf = segments[-1]
        candidates.append(f"{test_dir}/{leaf}.go")
        parent = os.path.dirname(test_dir)
        if parent:
            candidates.append(f"{parent}/{leaf}.go")

    normalized_production = {
        file_path.replace("\\", "/").strip("/"): file_path for file_path in production_files
    }
    for candidate in candidates:
        normalized_candidate = candidate.replace("\\", "/").strip("/")
        if normalized_candidate in normalized_production:
            return normalized_production[normalized_candidate]
        suffix = f"/{normalized_candidate}"
        for normalized_path, original in normalized_production.items():
            if normalized_path.endswith(suffix):
                return original
    return None


def _is_non_local_import(spec: str, test_path: str) -> bool:
    """Return True for imports that should not resolve to project files."""
    segments = [segment for segment in spec.split("/") if segment]
    if len(segments) <= 1:
        return True

    first = segments[0]
    if "." not in first:
        return False

    module_path = _nearest_module_path(test_path)
    if module_path is None:
        return False
    return spec != module_path and not spec.startswith(f"{module_path}/")


def _nearest_module_path(test_path: str) -> str | None:
    path = Path(test_path)
    if not path.is_absolute():
        return None
    cursor = path.parent if path.suffix else path
    for candidate in (cursor, *cursor.parents):
        go_mod = candidate / "go.mod"
        if go_mod.is_file():
            return read_module_path(go_mod)
    return None


def resolve_barrel_reexports(_filepath: str, _production_files: set[str]) -> set[str]:
    return set()


def parse_test_import_specs(content: str) -> list[str]:
    return iter_import_specs(content)


def map_test_to_source(test_path: str, production_set: set[str]) -> str | None:
    """Map a Go test file to its source counterpart by naming convention."""
    if not test_path.endswith("_test.go"):
        return None
    src = test_path[:-8] + ".go"
    if src in production_set:
        return src
    return None


def strip_test_markers(basename: str) -> str | None:
    """Strip Go test naming marker to derive source basename."""
    if basename.endswith("_test.go"):
        return basename[:-8] + ".go"
    return None


def strip_comments(content: str) -> str:
    """Strip Go comments while preserving string literals."""
    return strip_go_comments(content)
