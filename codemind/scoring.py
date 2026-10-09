"""Transparent 0-100 heuristic quality score and per-file risk ranking.

Method
------
``score = 100 - sum(penalty_i)`` over four factors. Each factor produces a
*badness* in ``[0, 1]``; its penalty is ``badness * weight_i / sum(weights) * 100``
(weights are configurable and normalised, so the penalties never exceed 100).

1. **findings**   ``1 - exp(-density / density_scale)`` where ``density`` is the
   confidence-weighted severity points per 100 LOC (minimum denominator: 100 LOC).
   Severity points: critical 10, high 5, medium 2, low 0.5, info 0.1; confidence
   multipliers: definite 1.0, high 0.9, medium 0.6, low 0.3.
2. **complexity** half from mean cyclomatic complexity (2 -> 0, 12 -> 1), half from
   the share of functions above ``max_complexity`` (25 % or more -> 1).
3. **maintainability** LOC-weighted mean *function* maintainability index (>=70 -> 0, <=20 -> 1);
   module-level MI is used only when a project has no functions (module size alone is not penalised).
4. **structure** share of functions/classes breaking size, nesting or parameter
   limits (30 % or more -> 1, weight 70 %) plus import cycles (3 or more -> 1, weight 30 %).

The score is a heuristic summary for trend tracking. It is NOT an objective
measure of correctness, security or test coverage.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from codemind.config import Config
from codemind.dependency_graph import DependencyAnalysis
from codemind.models import Confidence, Finding, ProjectInfo, Severity

SEVERITY_POINTS = {Severity.CRITICAL: 10.0, Severity.HIGH: 5.0, Severity.MEDIUM: 2.0, Severity.LOW: 0.5, Severity.INFO: 0.1}
CONFIDENCE_MULTIPLIER = {Confidence.DEFINITE: 1.0, Confidence.HIGH: 0.9, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.3}
CAVEAT = "The score is a heuristic summary of static metrics, not an objective measure of correctness."


def finding_points(finding: Finding) -> float:
    return SEVERITY_POINTS[finding.severity] * CONFIDENCE_MULTIPLIER[finding.confidence]


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass
class ScoreFactor:
    name: str
    weight: float
    badness: float
    penalty: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "weight": round(self.weight, 2), "badness": round(self.badness, 3),
                "penalty": round(self.penalty, 2), "detail": self.detail}


@dataclass
class ScoreResult:
    score: float
    grade: str
    factors: list[ScoreFactor] = field(default_factory=list)
    caveat: str = CAVEAT

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "grade": self.grade, "caveat": self.caveat,
                "factors": [f.to_dict() for f in self.factors]}


def grade_for(score: float) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return grade
    return "F"


def compute_score(project: ProjectInfo, findings: list[Finding], graph: DependencyAnalysis, config: Config) -> ScoreResult:
    """Compute the explainable quality score for an analysed project."""
    w, t = config.weights, config.thresholds
    if not project.modules:
        return ScoreResult(100.0, "A", [], CAVEAT + " No analysable code was found, so the score is vacuous.")
    total_weight = (w.findings + w.complexity + w.maintainability + w.structure) or 1.0
    loc = max(project.total_loc, 1)
    functions = [f for m in project.modules for f in m.functions]
    classes = [c for m in project.modules for c in m.classes]

    points = sum(finding_points(f) for f in findings)
    density = points / max(loc / 100.0, 1.0)
    bad_findings = 1 - math.exp(-density / max(w.density_scale, 1e-9))
    d_findings = f"{len(findings)} findings = {points:.1f} weighted points over {loc} LOC -> {density:.2f} points/100 LOC"

    if functions:
        mean_cc = sum(f.complexity for f in functions) / len(functions)
        over = sum(1 for f in functions if f.complexity > t.max_complexity) / len(functions)
        bad_complexity = 0.5 * _clamp((mean_cc - 2) / 10) + 0.5 * _clamp(over / 0.25)
        d_complexity = f"mean CC {mean_cc:.2f}; {over * 100:.1f}% of {len(functions)} functions exceed CC {t.max_complexity}"
    else:
        bad_complexity, d_complexity = 0.0, "no functions"

    if functions:
        fn_weight = sum(max(f.loc, 1) for f in functions)
        mean_mi = sum(f.maintainability * max(f.loc, 1) for f in functions) / fn_weight
        scope = "function"
    else:
        mean_mi = sum(m.maintainability * m.loc for m in project.modules) / loc
        scope = "module"
    bad_mi = _clamp((70 - mean_mi) / 50)
    d_mi = f"LOC-weighted mean {scope} maintainability index {mean_mi:.1f} (>=70 good, <=20 poor)"

    violating = sum(1 for f in functions if f.loc > t.max_function_lines or f.max_nesting > t.max_nesting or f.param_count > t.max_parameters)
    violating += sum(1 for c in classes if c.loc > t.max_class_lines or len(c.methods) > t.max_class_methods)
    units = len(functions) + len(classes)
    share = violating / units if units else 0.0
    cycles = len(graph.cycles)
    bad_structure = 0.7 * _clamp(share / 0.3) + 0.3 * _clamp(cycles / 3)
    d_structure = f"{violating}/{units} units break size/nesting/parameter limits; {cycles} import cycle(s)"

    raw = [("findings", w.findings, bad_findings, d_findings), ("complexity", w.complexity, bad_complexity, d_complexity),
           ("maintainability", w.maintainability, bad_mi, d_mi), ("structure", w.structure, bad_structure, d_structure)]
    factors = [ScoreFactor(n, wt / total_weight * 100, b, b * wt / total_weight * 100, d) for n, wt, b, d in raw]
    score = round(max(0.0, 100.0 - sum(f.penalty for f in factors)), 1)
    return ScoreResult(score, grade_for(score), factors)


@dataclass
class FileStat:
    path: str
    loc: int
    functions: int
    classes: int
    total_complexity: int
    max_complexity: int
    mean_complexity: float
    maintainability: float
    findings: int
    risk: float
    worst_function: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "mean_complexity": round(self.mean_complexity, 2), "risk": round(self.risk, 2)}


def file_stats(project: ProjectInfo, findings: list[Finding], config: Config) -> list[FileStat]:
    """Per-file metrics and a risk number (higher = review first).

    ``risk = weighted finding points + 0.25 * sum(CC above limit) + 0.1 * max(0, 40 - module MI)``
    """
    by_path: dict[str, list[Finding]] = {}
    for f in findings:
        by_path.setdefault(f.path, []).append(f)
    limit = config.thresholds.max_complexity
    stats = []
    for m in sorted(project.modules, key=lambda m: m.path):
        ccs = [fn.complexity for fn in m.functions]
        worst = max(m.functions, key=lambda fn: (fn.complexity, fn.qualname), default=None)
        risk = (sum(finding_points(f) for f in by_path.get(m.path, []))
                + 0.25 * sum(max(0, c - limit) for c in ccs) + 0.1 * max(0.0, 40 - m.maintainability))
        stats.append(FileStat(m.path, m.loc, len(m.functions), len(m.classes), m.complexity, max(ccs, default=0),
                              sum(ccs) / len(ccs) if ccs else 0.0, m.maintainability, len(by_path.get(m.path, [])),
                              risk, worst.qualname if worst else ""))
    # Files that failed to parse still deserve attention.
    for path in sorted({f.path for f in findings} - {s.path for s in stats}):
        stats.append(FileStat(path, 0, 0, 0, 0, 0, 0.0, 0.0, len(by_path[path]), sum(finding_points(f) for f in by_path[path])))
    return stats
