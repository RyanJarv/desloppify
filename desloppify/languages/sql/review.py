"""SQL review metadata."""

from __future__ import annotations

HOLISTIC_REVIEW_DIMENSIONS = [
    "authorization_consistency",
    "incomplete_migration",
    "logic_clarity",
    "contract_coherence",
]

LOW_VALUE_PATTERN = None
MIGRATION_MIXED_EXTENSIONS: set[str] = set()
MIGRATION_PATTERN_PAIRS: list[tuple[str, object, object]] = []

REVIEW_GUIDANCE = {
    "focus": [
        "Check whether write and destructive statements are scoped.",
        "Prefer explicit projections and bounded read paths for application queries.",
        "Look for broad permissions or disabled row-level security.",
    ],
}


def module_patterns(path: str) -> list[str]:
    """Return review grouping patterns for a SQL file."""
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 2:
        return ["/".join(parts[-2:])]
    return [path]


def api_surface(files: dict[str, str]) -> dict:
    """Return a tiny review surface for SQL files."""
    return {
        "files": sorted(files),
        "query_files": len(files),
    }
