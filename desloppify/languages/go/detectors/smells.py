"""Go code smell detection."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from desloppify.base.discovery.file_paths import resolve_scan_file
from desloppify.base.output.fallbacks import log_best_effort_failure
from desloppify.languages.go.extractors import (
    _FUNC_DECL_RE,
    _find_body_brace,
    _find_matching_brace,
    find_go_files,
)

logger = logging.getLogger(__name__)

GO_SMELL_CHECKS: list[dict[str, Any]] = [
    {
        "id": "ignored_error",
        "label": "Ignored error value",
        "pattern": r"_\s*(?:,\s*_\s*)?=\s*\w+.*(?:err|Err)",
        "severity": "high",
    },
    {
        "id": "ignored_error",
        "label": "Ignored error value",
        "pattern": r"_\s*=\s*\w+(?:\.\w+)?\(",
        "severity": "high",
    },
    {
        "id": "naked_return",
        "label": "Naked return with named result values",
        "pattern": None,
        "severity": "medium",
    },
    {
        "id": "empty_error_branch",
        "label": "Empty error-handling branch",
        "pattern": None,
        "severity": "high",
    },
    {
        "id": "panic_in_lib",
        "label": "panic() in library package",
        "pattern": None,
        "severity": "high",
    },
    {
        "id": "init_side_effects",
        "label": "func init() with side effects",
        "pattern": None,
        "severity": "medium",
    },
    {
        "id": "global_var",
        "label": "Package-level mutable var declaration",
        "pattern": None,
        "severity": "low",
    },
    {
        "id": "defer_in_loop",
        "label": "defer inside a for loop",
        "pattern": None,
        "severity": "high",
    },
    {
        "id": "goroutine_closure_capture",
        "label": "Goroutine captures loop variable",
        "pattern": None,
        "severity": "high",
    },
    {
        "id": "error_wrap_verb",
        "label": "fmt.Errorf wraps error with %v instead of %w",
        "pattern": r"""fmt\.Errorf\s*\([^)]*%v[^)]*\berr\b""",
        "severity": "medium",
    },
    {
        "id": "json_unmarshal_interface",
        "label": "json.Unmarshal into interface{}/any without struct",
        "pattern": None,
        "severity": "medium",
    },
    {
        "id": "hardcoded_url",
        "label": "Hardcoded URL in source code",
        "pattern": r"""(?:['"]|`)https?://[^\s'"` ]+(?:['"]|`)""",
        "severity": "medium",
    },
    {
        "id": "todo_fixme",
        "label": "TODO/FIXME/HACK comments",
        "pattern": r"//\s*(?:TODO|FIXME|HACK|XXX)",
        "severity": "low",
    },
    {
        "id": "magic_number",
        "label": "Magic number in logic",
        "pattern": r"(?:==|!=|>=?|<=?|[+\-*/])\s*\d{4,}",
        "severity": "low",
    },
    {
        "id": "monster_function",
        "label": "Monster function (>150 LOC)",
        "pattern": None,
        "severity": "high",
    },
    {
        "id": "dead_function",
        "label": "Dead function (empty body)",
        "pattern": None,
        "severity": "medium",
    },
    {
        "id": "unreachable_code",
        "label": "Unreachable code after return/panic/os.Exit",
        "pattern": None,
        "severity": "medium",
    },
]

_UNIQUE_IDS = list(dict.fromkeys(check["id"] for check in GO_SMELL_CHECKS))
_GLOBAL_VAR_RE = re.compile(r"^var\s+\w+")
_GLOBAL_VAR_SKIP_RE = re.compile(
    r"^var\s+\w+\s*=?\s*(?:"
    r"&?cobra\.Command\b"
    r"|regexp\.MustCompile\b"
    r"|sync\.\w+"
    r"|errors\.New\b"
    r"|fmt\.Errorf\b"
    r"|template\.Must\b"
    r")"
)
_JSON_UNMARSHAL_RE = re.compile(r"json\.(?:Unmarshal|NewDecoder)")
_INTERFACE_EMPTY_RE = re.compile(r"\binterface\s*\{\}|\bany\b")


def detect_smells(path: Path) -> tuple[list[dict], int]:
    """Detect Go smell patterns and return normalized smell-entry dictionaries."""
    smell_counts: dict[str, list[dict]] = {smell_id: [] for smell_id in _UNIQUE_IDS}
    files = find_go_files(path)

    for filepath in files:
        if filepath.endswith("_test.go") or "/vendor/" in filepath:
            continue
        try:
            content = resolve_scan_file(filepath, scan_root=path).read_text(
                errors="replace"
            )
        except (OSError, UnicodeDecodeError) as exc:
            log_best_effort_failure(logger, f"read Go smell candidate {filepath}", exc)
            continue

        lines = content.splitlines()
        _run_regex_checks(filepath, lines, smell_counts)
        _detect_empty_error_branch(filepath, lines, smell_counts)
        _detect_naked_returns(filepath, content, smell_counts)
        _detect_panic_in_lib(filepath, content, lines, smell_counts)
        _detect_init_side_effects(filepath, content, smell_counts)
        _detect_defer_in_loop(filepath, lines, smell_counts)
        _detect_goroutine_closure(filepath, lines, smell_counts)
        _detect_global_var(filepath, lines, smell_counts)
        _detect_monster_functions(filepath, content, smell_counts)
        _detect_dead_functions(filepath, content, smell_counts)
        _detect_unreachable_code(filepath, lines, smell_counts)
        _detect_json_unmarshal_interface(filepath, lines, smell_counts)

    return _build_entries(smell_counts), len(files)


def _run_regex_checks(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    for check in GO_SMELL_CHECKS:
        pattern = check["pattern"]
        if pattern is None:
            continue
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") and check["id"] != "todo_fixme":
                continue
            if not re.search(pattern, line):
                continue
            if check["id"] == "hardcoded_url" and re.match(
                r"^(?:var|const)\s+[A-Za-z_]\w*\s*=",
                stripped,
            ):
                continue
            smell_counts[check["id"]].append(_match(filepath, index, stripped))


def _detect_empty_error_branch(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not re.match(r"if\s+err\s*!=\s*nil\s*\{", stripped):
            continue
        for next_line in lines[index + 1 : min(index + 3, len(lines))]:
            next_stripped = next_line.strip()
            if not next_stripped:
                continue
            if next_stripped == "}":
                smell_counts["empty_error_branch"].append(
                    _match(filepath, index + 1, stripped)
                )
            break


def _detect_naked_returns(
    filepath: str,
    content: str,
    smell_counts: dict[str, list[dict]],
) -> None:
    """Flag bare returns only in functions with named result parameters."""
    for match in _FUNC_DECL_RE.finditer(content):
        brace_pos = _find_body_brace(content, match.end())
        if brace_pos is None:
            continue
        if not _has_named_results(content[match.end() - 1 : brace_pos]):
            continue
        end = _find_matching_brace(content, brace_pos)
        if end is None:
            continue
        body = content[brace_pos + 1 : end]
        body_start_line = content.count("\n", 0, brace_pos) + 1
        for offset, line in enumerate(body.splitlines(), start=1):
            stripped = line.strip()
            if stripped == "return":
                smell_counts["naked_return"].append(
                    _match(filepath, body_start_line + offset, stripped)
                )


def _has_named_results(signature_tail: str) -> bool:
    close_params = _find_matching_paren(signature_tail, 0)
    if close_params is None:
        return False
    returns = signature_tail[close_params + 1 :].strip()
    if not returns.startswith("(") or ")" not in returns:
        return False
    result_list = returns[1 : returns.find(")")].strip()
    return bool(re.search(r"\b[A-Za-z_]\w*\s+(?:\*|\[\]|\w)", result_list))


def _find_matching_paren(text: str, open_pos: int) -> int | None:
    depth = 0
    for index, char in enumerate(text[open_pos:], start=open_pos):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _detect_panic_in_lib(
    filepath: str,
    content: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    package_match = re.search(r"^package\s+(\w+)", content, re.MULTILINE)
    if not package_match or package_match.group(1) == "main":
        return
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("//") and re.search(r"\bpanic\s*\(", stripped):
            smell_counts["panic_in_lib"].append(_match(filepath, index, stripped))


def _detect_init_side_effects(
    filepath: str,
    content: str,
    smell_counts: dict[str, list[dict]],
) -> None:
    side_effect_patterns = [
        r"\bhttp\.\w+",
        r"\bos\.(Open|Create|Remove|Mkdir|Stat|ReadFile|WriteFile)",
        r"\bexec\.Command",
        r"\bnet\.Dial",
        r"\bsql\.Open",
        r"\bioutil\.Read",
    ]
    for match in _FUNC_DECL_RE.finditer(content):
        if match.group(1) != "init":
            continue
        brace_pos = _find_body_brace(content, match.end())
        if brace_pos is None:
            continue
        end = _find_matching_brace(content, brace_pos)
        if end is None:
            continue
        body = content[brace_pos + 1 : end]
        if any(re.search(pattern, body) for pattern in side_effect_patterns):
            line = content.count("\n", 0, match.start()) + 1
            smell_counts["init_side_effects"].append(
                _match(filepath, line, "func init() with side effects")
            )


def _detect_defer_in_loop(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    in_for = False
    for_depth = 0
    brace_depth = 0
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if re.match(r"\bfor\b", stripped) and "{" in stripped and not in_for:
            in_for = True
            for_depth = brace_depth
        brace_depth += stripped.count("{") - stripped.count("}")
        if in_for and re.match(r"\s*defer\b", line):
            smell_counts["defer_in_loop"].append(_match(filepath, index, stripped))
        if in_for and brace_depth <= for_depth:
            in_for = False


def _detect_goroutine_closure(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    in_for = False
    for_depth = 0
    brace_depth = 0
    for_vars: list[str] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for_match = re.match(
            r"for\s+(?:(\w+)(?:\s*,\s*(\w+))?\s*:?=|_\s*,\s*(\w+)\s*:?=)",
            stripped,
        )
        if for_match and "{" in stripped and not in_for:
            in_for = True
            for_depth = brace_depth
            for_vars = [group for group in for_match.groups() if group]
        brace_depth += stripped.count("{") - stripped.count("}")
        if in_for and re.match(r"go\s+func\s*\(", stripped):
            if _closure_references_vars(lines[index - 1 : index + 19], for_vars):
                smell_counts["goroutine_closure_capture"].append(
                    _match(filepath, index, stripped)
                )
        if in_for and brace_depth <= for_depth:
            in_for = False
            for_vars = []


def _closure_references_vars(lines: list[str], variables: list[str]) -> bool:
    for body_line in lines[1:]:
        for variable in variables:
            if re.search(rf"\b{re.escape(variable)}\b", body_line):
                return True
    return False


def _detect_global_var(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    in_var_block = False
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or line != line.lstrip():
            continue
        if re.match(r"^var\s*\(", stripped):
            in_var_block = True
            continue
        if in_var_block:
            if stripped == ")":
                in_var_block = False
            continue
        if _GLOBAL_VAR_RE.match(stripped) and not _GLOBAL_VAR_SKIP_RE.match(stripped):
            smell_counts["global_var"].append(_match(filepath, index, stripped))


def _detect_monster_functions(
    filepath: str,
    content: str,
    smell_counts: dict[str, list[dict]],
) -> None:
    for match in _FUNC_DECL_RE.finditer(content):
        brace_pos = _find_body_brace(content, match.end())
        if brace_pos is None:
            continue
        end = _find_matching_brace(content, brace_pos)
        if end is None:
            continue
        start_line = content.count("\n", 0, match.start()) + 1
        end_line = content.count("\n", 0, end) + 1
        loc = end_line - start_line + 1
        if loc > 150:
            smell_counts["monster_function"].append(
                _match(filepath, start_line, f"func {match.group(1)} ({loc} LOC)")
            )


def _detect_dead_functions(
    filepath: str,
    content: str,
    smell_counts: dict[str, list[dict]],
) -> None:
    for match in _FUNC_DECL_RE.finditer(content):
        brace_pos = _find_body_brace(content, match.end())
        if brace_pos is None:
            continue
        end = _find_matching_brace(content, brace_pos)
        if end is None:
            continue
        body = content[brace_pos + 1 : end].strip()
        body_clean = re.sub(r"//.*", "", body)
        body_clean = re.sub(r"/\*.*?\*/", "", body_clean, flags=re.DOTALL)
        if not body_clean.strip():
            line = content.count("\n", 0, match.start()) + 1
            smell_counts["dead_function"].append(
                _match(filepath, line, f"func {match.group(1)} (empty body)")
            )


def _detect_unreachable_code(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//") or not re.match(
            r"(?:return\b|panic\(|os\.Exit\()",
            stripped,
        ):
            continue
        depth = stripped.count("{") - stripped.count("}")
        depth += stripped.count("(") - stripped.count(")")
        if depth > 0:
            continue
        for next_index in range(index + 1, min(index + 5, len(lines))):
            next_stripped = lines[next_index].strip()
            if not next_stripped or next_stripped.startswith("//"):
                continue
            if re.match(r"^[}\)]+[,;\s]*$", next_stripped):
                break
            if next_stripped.startswith(("case ", "default:")):
                break
            smell_counts["unreachable_code"].append(
                _match(filepath, next_index + 1, next_stripped)
            )
            break


def _detect_json_unmarshal_interface(
    filepath: str,
    lines: list[str],
    smell_counts: dict[str, list[dict]],
) -> None:
    iface_vars = set()
    for line in lines:
        match = re.match(
            r"var\s+(\w+)\s+(?:interface\s*\{\}\s*|any\b)",
            line.strip(),
        )
        if match:
            iface_vars.add(match.group(1))

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or not _JSON_UNMARSHAL_RE.search(stripped):
            continue
        if any(re.search(rf"&{re.escape(var)}\b", stripped) for var in iface_vars):
            smell_counts["json_unmarshal_interface"].append(
                _match(filepath, index, stripped)
            )
        elif _INTERFACE_EMPTY_RE.search(stripped):
            smell_counts["json_unmarshal_interface"].append(
                _match(filepath, index, stripped)
            )


def _build_entries(smell_counts: dict[str, list[dict]]) -> list[dict]:
    severity_order = {"high": 0, "medium": 1, "low": 2}
    label_lookup = {}
    severity_lookup = {}
    for check in GO_SMELL_CHECKS:
        label_lookup.setdefault(check["id"], check["label"])
        severity_lookup.setdefault(check["id"], check["severity"])

    entries = []
    for smell_id in _UNIQUE_IDS:
        matches = smell_counts[smell_id]
        if not matches:
            continue
        entries.append(
            {
                "id": smell_id,
                "label": label_lookup[smell_id],
                "severity": severity_lookup[smell_id],
                "count": len(matches),
                "files": len({match["file"] for match in matches}),
                "matches": matches[:50],
            }
        )
    entries.sort(
        key=lambda entry: (severity_order.get(entry["severity"], 9), -entry["count"])
    )
    return entries


def _match(filepath: str, line: int, content: str) -> dict:
    return {"file": filepath, "line": line, "content": content[:100]}


__all__ = ["GO_SMELL_CHECKS", "detect_smells"]
