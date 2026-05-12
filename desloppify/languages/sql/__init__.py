"""SQL language configuration for Desloppify."""

from __future__ import annotations

from typing import Any

from desloppify.base.discovery.paths import get_area
from desloppify.engine.policy.zones import COMMON_ZONE_RULES, Zone, ZoneRule
from desloppify.languages._framework.base.phase_builders import (
    detector_phase_security,
    detector_phase_signature,
    detector_phase_test_coverage,
    shared_subjective_duplicates_tail,
)
from desloppify.languages._framework.base.types import (
    DetectorPhase,
    LangConfig,
    LangSecurityResult,
)
from desloppify.languages._framework.registry.registration import register_full_plugin
from desloppify.languages.sql import test_coverage as sql_test_coverage_hooks
from desloppify.languages.sql.commands import get_detect_commands
from desloppify.languages.sql.extractors import (
    SQL_FILE_EXCLUSIONS,
    extract_functions,
    find_sql_files,
)
from desloppify.languages.sql.phases import (
    phase_sql_security,
    phase_sql_smells,
    phase_sql_structure,
)
from desloppify.languages.sql.review import (
    HOLISTIC_REVIEW_DIMENSIONS,
    LOW_VALUE_PATTERN,
    MIGRATION_MIXED_EXTENSIONS,
    MIGRATION_PATTERN_PAIRS,
    REVIEW_GUIDANCE,
    api_surface,
    module_patterns,
)

SQL_ZONE_RULES = [
    ZoneRule(Zone.TEST, ["/tests/", "/test/", "_test.sql", ".test.sql"]),
    ZoneRule(Zone.VENDOR, ["/vendor/", "/third_party/"]),
    ZoneRule(Zone.GENERATED, ["/generated/", "/gen/", ".generated.sql"]),
] + COMMON_ZONE_RULES


def build_sql_dep_graph(path) -> dict[str, dict[str, Any]]:
    """Return a dependency graph shape for SQL files.

    Raw SQL has table references rather than source-file imports. The graph keeps
    files as nodes and stores referenced tables as metadata so shared callers have
    a stable graph-shaped object without inventing table-to-file ownership.
    """
    from pathlib import Path

    from desloppify.languages.sql.extractors import extract_table_refs, find_sql_files

    root = Path(path)
    refs_by_file: dict[str, set[str]] = {}
    for ref in extract_table_refs(root):
        refs_by_file.setdefault(ref.file, set()).add(ref.table)
    return {
        file_path: {
            "imports": set(),
            "importers": set(),
            "import_count": 0,
            "importer_count": 0,
            "tables": sorted(refs_by_file.get(file_path, set())),
        }
        for file_path in find_sql_files(root)
    }


class SqlConfig(LangConfig):
    """SQL language configuration."""

    def __init__(self):
        super().__init__(
            name="sql",
            extensions=[".sql"],
            exclusions=SQL_FILE_EXCLUSIONS,
            default_src=".",
            build_dep_graph=build_sql_dep_graph,
            entry_patterns=[],
            barrel_names=set(),
            phases=[
                DetectorPhase("SQL structure", phase_sql_structure),
                DetectorPhase("SQL smells", phase_sql_smells),
                DetectorPhase("SQL security", phase_sql_security),
                detector_phase_signature(),
                detector_phase_test_coverage(),
                detector_phase_security(),
                *shared_subjective_duplicates_tail(),
            ],
            fixers={},
            get_area=get_area,
            detect_commands=get_detect_commands(),
            boundaries=[],
            typecheck_cmd="",
            file_finder=find_sql_files,
            large_threshold=400,
            complexity_threshold=20,
            default_scan_profile="full",
            detect_markers=["sqlc.yaml", "sqlc.yml"],
            external_test_dirs=["tests", "test"],
            test_file_extensions=[".sql"],
            review_module_patterns_fn=module_patterns,
            review_api_surface_fn=api_surface,
            review_guidance=REVIEW_GUIDANCE,
            review_low_value_pattern=LOW_VALUE_PATTERN,
            holistic_review_dimensions=HOLISTIC_REVIEW_DIMENSIONS,
            migration_pattern_pairs=MIGRATION_PATTERN_PAIRS,
            migration_mixed_extensions=MIGRATION_MIXED_EXTENSIONS,
            extract_functions=extract_functions,
            zone_rules=SQL_ZONE_RULES,
        )

    def detect_lang_security_detailed(self, files, zone_map) -> LangSecurityResult:
        """Security is handled by the SQL security phase."""
        del files, zone_map
        return LangSecurityResult(entries=[], files_scanned=0)


def register() -> None:
    """Register SQL language config."""
    register_full_plugin("sql", SqlConfig, test_coverage=sql_test_coverage_hooks)


Config = SqlConfig


__all__ = [
    "Config",
    "SqlConfig",
    "SQL_FILE_EXCLUSIONS",
    "SQL_ZONE_RULES",
    "build_sql_dep_graph",
    "register",
]
