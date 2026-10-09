"""Shared test helpers (plain functions, no pytest fixtures required)."""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Optional

from codemind.analyzer import AnalysisResult, analyze
from codemind.config import Config


def write_project(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")
    return root


def analyze_snippet(root: Path, code: str, name: str = "mod.py", config: Optional[Config] = None) -> AnalysisResult:
    write_project(root, {name: code})
    return analyze(root, config)


def ids(result: AnalysisResult) -> list[str]:
    return [f.rule_id for f in result.findings]


def of(result: AnalysisResult, rule_id: str):
    return [f for f in result.findings if f.rule_id == rule_id]
