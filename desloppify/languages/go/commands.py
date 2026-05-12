"""Go detect-subcommand registry using canonical framework composition.

Originally contributed by tinker495 (KyuSeok Jung) in PR #128.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from desloppify.base.discovery.file_paths import rel
from desloppify.base.output.terminal import display_entries
from desloppify.engine.detectors import gods as gods_detector_mod
from desloppify.languages._framework.commands.base import (
    make_cmd_complexity,
    make_cmd_large,
    make_cmd_naming,
    make_cmd_single_use,
    make_cmd_smells,
)
from desloppify.languages._framework.commands.registry import (
    build_standard_detect_registry,
    compose_detect_registry,
    make_cmd_cycles,
    make_cmd_deps,
    make_cmd_dupes,
    make_cmd_orphaned,
)
from desloppify.languages.go.detectors.deps import build_dep_graph
from desloppify.languages.go.detectors.gods import GO_GOD_RULES, extract_go_structs
from desloppify.languages.go.detectors.smells import detect_smells
from desloppify.languages.go.detectors.unused import detect_unused
from desloppify.languages.go.extractors import extract_functions, find_go_files
from desloppify.languages.go.phases import GO_COMPLEXITY_SIGNALS

cmd_large = make_cmd_large(
    find_go_files,
    default_threshold=500,
    module_name=__name__,
)
cmd_complexity = make_cmd_complexity(
    find_go_files,
    GO_COMPLEXITY_SIGNALS,
    default_threshold=15,
    module_name=__name__,
)
cmd_deps = make_cmd_deps(
    build_dep_graph_fn=build_dep_graph,
    empty_message="No Go dependencies detected.",
    import_count_label="Imports",
    top_imports_label="Top imports",
    module_name=__name__,
)
cmd_cycles = make_cmd_cycles(build_dep_graph_fn=build_dep_graph, module_name=__name__)
cmd_orphaned = make_cmd_orphaned(
    build_dep_graph_fn=build_dep_graph,
    extensions=[".go"],
    extra_entry_patterns=["main.go", "cmd/"],
    extra_barrel_names=set(),
    module_name=__name__,
)
cmd_dupes = make_cmd_dupes(extract_functions_fn=extract_functions, module_name=__name__)
cmd_single_use = make_cmd_single_use(
    build_dep_graph=build_dep_graph,
    barrel_names=set(),
    module_name=__name__,
)
cmd_smells = make_cmd_smells(detect_smells, module_name=__name__)
cmd_naming = make_cmd_naming(
    find_go_files,
    skip_names={"main.go", "doc.go"},
    skip_dirs={"vendor", "testdata"},
    module_name=__name__,
)


def cmd_unused(args: argparse.Namespace) -> None:
    entries, total, available = detect_unused(Path(args.path))
    empty = (
        "staticcheck is not installed; install it for Go unused symbol detection."
        if not available
        else "No unused symbols found."
    )
    display_entries(
        args,
        entries,
        label=f"Unused symbols ({total} files checked)",
        empty_msg=empty,
        columns=["File", "Line", "Name", "Category"],
        widths=[55, 6, 30, 10],
        row_fn=lambda entry: [
            rel(entry["file"]),
            str(entry["line"]),
            entry["name"],
            entry["category"],
        ],
    )


def cmd_gods(args: argparse.Namespace) -> None:
    entries, _ = gods_detector_mod.detect_gods(
        extract_go_structs(Path(args.path)),
        GO_GOD_RULES,
        min_reasons=2,
    )
    display_entries(
        args,
        entries,
        label="God structs",
        empty_msg="No god structs found.",
        columns=["File", "Struct", "LOC", "Why"],
        widths=[50, 24, 6, 45],
        row_fn=lambda entry: [
            rel(entry["file"]),
            entry["name"],
            str(entry["loc"]),
            ", ".join(entry["reasons"]),
        ],
    )


def get_detect_commands() -> dict[str, Callable[..., None]]:
    return compose_detect_registry(
        base_registry=build_standard_detect_registry(
            cmd_deps=cmd_deps,
            cmd_cycles=cmd_cycles,
            cmd_orphaned=cmd_orphaned,
            cmd_dupes=cmd_dupes,
            cmd_large=cmd_large,
            cmd_complexity=cmd_complexity,
        ),
        extra_registry={
            "single_use": cmd_single_use,
            "smells": cmd_smells,
            "naming": cmd_naming,
            "unused": cmd_unused,
            "gods": cmd_gods,
        },
    )
