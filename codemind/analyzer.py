"""End-to-end analysis pipeline: scan -> graph -> rules -> score."""
from __future__ import annotations

import datetime as _dt
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from codemind.config import Config, ConfigError
from codemind.dependency_graph import DependencyAnalysis, build_dependency_analysis
from codemind.models import Finding, ProjectInfo, Severity
from codemind.rules import RuleContext, all_rules, run_rules
from codemind.scanner import scan_project
from codemind.scoring import FileStat, ScoreResult, compute_score, file_stats


@dataclass
class AnalysisResult:
    root: Path
    project: ProjectInfo
    findings: list[Finding]
    graph: DependencyAnalysis
    score: ScoreResult
    files: list[FileStat]
    config: Config
    rule_errors: list[str] = field(default_factory=list)
    generated_at: str = ""
    scan_id: Optional[int] = None

    @property
    def functions(self) -> list:
        return [(m, f) for m in self.project.modules for f in m.functions]

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(f.severity.value for f in self.findings)
        return {s.value: counts.get(s.value, 0) for s in sorted(Severity, key=lambda s: -s.rank)}

    def summary(self) -> dict[str, Any]:
        funcs = [f for _, f in self.functions]
        mis = [m.maintainability for m in self.project.modules]
        return {
            "files_found": self.project.files_found,
            "files_analyzed": len(self.project.modules),
            "files_skipped": len(self.project.issues),
            "loc": self.project.total_loc,
            "functions": len(funcs),
            "classes": sum(len(m.classes) for m in self.project.modules),
            "findings": len(self.findings),
            "heuristic_findings": sum(1 for f in self.findings if f.is_heuristic),
            "severity_counts": self.severity_counts(),
            "rule_counts": dict(sorted(Counter(f.rule_id for f in self.findings).items())),
            "mean_complexity": round(sum(f.complexity for f in funcs) / len(funcs), 3) if funcs else 0.0,
            "max_complexity": max((f.complexity for f in funcs), default=0),
            "mean_maintainability": round(sum(mis) / len(mis), 2) if mis else 100.0,
            "cycles": len(self.graph.cycles),
            "score": self.score.score,
            "grade": self.score.grade,
        }

    def top_files(self, limit: int = 10) -> list[FileStat]:
        ranked = sorted((s for s in self.files if s.risk > 0), key=lambda s: (-s.risk, s.path))
        return ranked[:limit]

    def top_functions(self, limit: int = 10) -> list[tuple[str, Any]]:
        ranked = sorted(self.functions, key=lambda mf: (-mf[1].complexity, mf[0].path, mf[1].lineno))
        return ranked[:limit]

    def priorities(self, limit: int = 5) -> list[str]:
        """Plain-language recommendations ordered by expected payoff."""
        items: list[str] = []
        t = self.config.thresholds
        for cycle in self.graph.cycles[:3]:
            items.append(f"Break the import cycle {' -> '.join(cycle['path'] + [cycle['path'][0]])}.")
        serious = [f for f in self.findings if f.severity.rank >= Severity.HIGH.rank]
        if serious:
            rules = ", ".join(sorted({f.rule_id for f in serious}))
            items.append(f"Review the {len(serious)} high/critical finding(s) first ({rules}).")
        for mod, fn in self.top_functions(3):
            if fn.complexity > t.max_complexity:
                items.append(f"Refactor {mod.path}:{fn.lineno} '{fn.qualname}' (cyclomatic complexity {fn.complexity}).")
        for stat in self.top_files(3):
            items.append(f"Inspect {stat.path} (risk {stat.risk:.1f}, {stat.findings} finding(s)).")
        if self.project.issues:
            items.append(f"Resolve {len(self.project.issues)} unreadable/unparsable file(s) so they can be analysed.")
        seen, unique = set(), []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique[:limit] or ["No significant issues were detected by the enabled rules."]


def validate_rule_ids(config: Config) -> None:
    known = {r.meta.id for r in all_rules()}
    unknown = (config.disabled_rules | set(config.severity_overrides)) - known
    if unknown:
        raise ConfigError(f"unknown rule id(s) in configuration: {', '.join(sorted(unknown))}")


def analyze(root: Path, config: Optional[Config] = None) -> AnalysisResult:
    """Analyse the Python project in ``root`` without executing any of its code."""
    config = config or Config()
    validate_rule_ids(config)
    project = scan_project(root, config)
    graph = build_dependency_analysis(project)
    findings, errors = run_rules(project, RuleContext(config, graph))
    score = compute_score(project, findings, graph, config)
    return AnalysisResult(
        root=root.resolve(), project=project, findings=findings, graph=graph, score=score,
        files=file_stats(project, findings, config), config=config, rule_errors=errors,
        generated_at=_dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
    )
