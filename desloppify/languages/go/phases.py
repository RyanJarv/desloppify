"""Go detector phase runners.

Originally contributed by tinker495 (KyuSeok Jung) in PR #128.
"""

from __future__ import annotations

from pathlib import Path

from desloppify.base.output.terminal import log
from desloppify.engine.detectors.base import ComplexitySignal
from desloppify.engine.detectors.graph import detect_cycles
from desloppify.engine.policy.zones import adjust_potential, filter_entries
from desloppify.languages._framework.base.shared_phases import run_structural_phase
from desloppify.languages._framework.base.smell_contracts import (
    normalize_smell_entries,
)
from desloppify.languages._framework.base.types import LangRuntimeContract
from desloppify.languages._framework.issue_factories import (
    make_cycle_issues,
    make_smell_issues,
    make_unused_issues,
)
from desloppify.languages.go.detectors.deps import build_package_dep_graph
from desloppify.languages.go.detectors.gods import GO_GOD_RULES, extract_go_structs
from desloppify.languages.go.detectors.smells import detect_smells
from desloppify.languages.go.detectors.unused import detect_unused
from desloppify.state_io import Issue

GO_COMPLEXITY_SIGNALS = [
    ComplexitySignal(
        "if/else branches",
        r"\b(?:if|else\s+if|else)\b",
        weight=1,
        threshold=25,
    ),
    ComplexitySignal(
        "switch/case",
        r"\b(?:switch|case)\b",
        weight=1,
        threshold=10,
    ),
    ComplexitySignal(
        "select blocks",
        r"\bselect\b",
        weight=2,
        threshold=5,
    ),
    ComplexitySignal(
        "for loops",
        r"\bfor\b",
        weight=1,
        threshold=15,
    ),
    ComplexitySignal(
        "goroutines",
        r"\bgo\s+\w+",
        weight=2,
        threshold=5,
    ),
    ComplexitySignal(
        "defer",
        r"\bdefer\b",
        weight=1,
        threshold=10,
    ),
    ComplexitySignal(
        "TODOs",
        r"(?m)//\s*(?:TODO|FIXME|HACK|XXX)",
        weight=2,
        threshold=0,
    ),
]


def phase_structural(path: Path, lang: LangRuntimeContract) -> tuple[list[Issue], dict[str, int]]:
    """Run structural detectors (large/complexity/flat directories/god structs)."""
    return run_structural_phase(
        path,
        lang,
        complexity_signals=GO_COMPLEXITY_SIGNALS,
        log_fn=log,
        god_rules=GO_GOD_RULES,
        god_extractor_fn=extract_go_structs,
    )


def phase_coupling(path: Path, lang: LangRuntimeContract) -> tuple[list[Issue], dict[str, int]]:
    """Run package-level Go cycle detection.

    Go imports packages, not individual files, so shared file-level single-use
    and orphaned heuristics are intentionally not run for Go package imports.
    """
    graph = build_package_dep_graph(path)
    lang.dep_graph = graph
    cycle_entries, total_packages = detect_cycles(graph)
    cycle_entries = filter_entries(lang.zone_map, cycle_entries, "cycles", file_key="files")
    results = make_cycle_issues(cycle_entries, log)
    log(f"         -> {len(results)} Go package coupling issues total")
    return results, {
        "cycles": adjust_potential(lang.zone_map, total_packages),
    }


def phase_smells(path: Path, lang: LangRuntimeContract) -> tuple[list[Issue], dict[str, int]]:
    """Run Go-specific smell detectors and normalize them into issues."""
    smell_entries, total_smell_files = detect_smells(path)
    normalized_smells = normalize_smell_entries(smell_entries)
    results = make_smell_issues(
        [entry.to_mapping() for entry in normalized_smells],
        log,
    )
    return results, {
        "smells": adjust_potential(lang.zone_map, total_smell_files),
    }


def phase_unused(path: Path, lang: LangRuntimeContract) -> tuple[list[Issue], dict[str, int]]:
    """Run staticcheck-backed Go unused symbol detection when available."""
    entries, total_files, available = detect_unused(path)
    if not available:
        log("         staticcheck unavailable; skipping Go unused symbol detection")
        return [], {"unused": adjust_potential(lang.zone_map, total_files)}

    entries = filter_entries(lang.zone_map, entries, "unused")
    return make_unused_issues(entries, log), {
        "unused": adjust_potential(lang.zone_map, total_files),
    }
