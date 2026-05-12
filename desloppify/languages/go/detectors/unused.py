"""Go unused symbol detection via staticcheck."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from desloppify.languages.go.extractors import find_go_files

_STATICCHECK_RE = re.compile(r"^(.+?):(\d+):(\d+):\s+(U1000|SA4006)\s+(.+)$")
_NAME_RE = re.compile(r"(?:\"([^\"]+)\"|(\S+))\s+is\s+(?:unused|assigned)")


def detect_unused(path: Path, category: str = "all") -> tuple[list[dict], int, bool]:
    """Detect unused Go symbols with staticcheck when available.

    Returns ``(entries, total_files_checked, staticcheck_available)``. Missing
    or timed-out staticcheck is a graceful no-op so tests and scans do not need
    a local staticcheck install.
    """
    total_files = len(find_go_files(path))
    result = _try_staticcheck(path, category)
    if result is None:
        return [], total_files, False
    entries, available = result
    return entries, total_files, available


def _try_staticcheck(path: Path, category: str) -> tuple[list[dict], bool] | None:
    checks = _checks_for_category(category)
    if not checks:
        return [], True

    try:
        proc = subprocess.run(
            ["staticcheck", "-checks", ",".join(checks), "-f", "text", "./..."],
            capture_output=True,
            text=True,
            cwd=str(path),
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except UnicodeDecodeError:
        return [], True

    lines = (proc.stdout + proc.stderr).splitlines()
    return _parse_staticcheck_output(lines, category, str(path.resolve())), True


def _checks_for_category(category: str) -> list[str]:
    checks = []
    if category in ("all", "exports"):
        checks.append("U1000")
    if category in ("all", "vars"):
        checks.append("SA4006")
    return checks


def _parse_staticcheck_output(
    lines: list[str],
    category: str,
    base_path: str,
) -> list[dict]:
    """Parse staticcheck text output into unused-symbol entries."""
    entries: list[dict] = []
    for line in lines:
        match = _STATICCHECK_RE.match(line)
        if not match:
            continue
        filepath = match.group(1)
        line_num = int(match.group(2))
        col = int(match.group(3))
        code = match.group(4)
        message = match.group(5)

        if not Path(filepath).is_absolute():
            filepath = str(Path(base_path) / filepath)
        if filepath.endswith("_test.go"):
            continue

        symbol_category = "vars" if code == "SA4006" else "exports"
        if category != "all" and symbol_category != category:
            continue

        name = _extract_name(message)
        if name.startswith("_"):
            continue
        entries.append(
            {
                "file": filepath,
                "line": line_num,
                "col": col,
                "name": name,
                "category": symbol_category,
            }
        )
    return entries


def _extract_name(message: str) -> str:
    """Extract a symbol name from a staticcheck unused message."""
    match = _NAME_RE.search(message)
    if match:
        return match.group(1) or match.group(2)
    quoted = re.search(r'"([^"]+)"', message)
    if quoted:
        return quoted.group(1)
    parts = message.split()
    return parts[0] if parts else message


__all__ = [
    "detect_unused",
]
