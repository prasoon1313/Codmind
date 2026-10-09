"""Terminal, JSON and CSV reports plus safe output-file handling."""
from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Any, Optional

from codemind import __version__
from codemind.analyzer import AnalysisResult
from codemind.complexity import maintainability_band
from codemind.models import Severity
from codemind.rules.base import RuleMeta
from codemind.scoring import CAVEAT

DISCLAIMER = (
    "Static analysis only: findings marked heuristic are indicators, not proof of runtime bugs. "
    "The quality score is a heuristic, not an objective measure of correctness."
)
_ALLOWED_SUFFIXES = {".json", ".csv", ".graphml", ".txt", ".md", ".xml"}
_COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


class OutputPathError(ValueError):
    """Raised when a report destination is considered unsafe."""


def safe_output_path(raw: str) -> Path:
    """Validate a report destination.

    Rejects ``..`` components, directories, symlinks, and any suffix outside a
    small allow-list (so a report can never overwrite ``.py`` sources or other
    executable files). Parent directories are created on write.
    """
    path = Path(raw).expanduser()
    if ".." in path.parts:
        raise OutputPathError(f"output path must not contain '..': {raw}")
    if path.suffix.lower() not in _ALLOWED_SUFFIXES:
        raise OutputPathError(f"output file must end with one of {', '.join(sorted(_ALLOWED_SUFFIXES))}: {raw}")
    if path.is_dir():
        raise OutputPathError(f"output path is a directory: {raw}")
    if path.is_symlink():
        raise OutputPathError(f"refusing to write through a symbolic link: {raw}")
    return path


def write_output(raw: str, text: str) -> Path:
    path = safe_output_path(raw)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise OutputPathError(f"cannot write {raw}: {exc.strerror or exc}") from None
    return path


def _paint(text: str, kind: str, color: bool) -> str:
    return f"\033[{_COLORS[kind]}m{text}\033[0m" if color and kind in _COLORS else text


def use_color(stream: Any) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def result_to_dict(result: AnalysisResult, top: int = 10) -> dict[str, Any]:
    return {
        "tool": {"name": "codemind", "version": __version__},
        "disclaimer": DISCLAIMER,
        "root": result.root.as_posix(),
        "generated_at": result.generated_at,
        "scan_id": result.scan_id,
        "summary": result.summary(),
        "score": result.score.to_dict(),
        "issues": [i.__dict__ for i in result.project.issues],
        "findings": [f.to_dict() for f in result.findings],
        "files": [s.to_dict() for s in sorted(result.files, key=lambda s: s.path)],
        "complexity": {
            "top_functions": [
                {"path": m.path, "function": f.qualname, "line": f.lineno, "complexity": f.complexity, "loc": f.loc,
                 "nesting": f.max_nesting, "maintainability": f.maintainability}
                for m, f in result.top_functions(top)
            ],
            "top_modules": [
                {"path": m.path, "complexity": m.complexity, "maintainability": m.maintainability, "loc": m.loc}
                for m in sorted(result.project.modules, key=lambda m: (-m.complexity, m.path))[:top]
            ],
        },
        "dependencies": {**result.graph.summary(), "cycles_detail": result.graph.cycles,
                         "top_coupled_modules": [{"module": n, **m} for n, m in result.graph.top_modules("coupling", top)],
                         "isolated_functions": result.graph.isolated_functions},
        "highest_risk_files": [s.to_dict() for s in result.top_files(top)],
        "priorities": result.priorities(),
        "rule_errors": result.rule_errors,
        "config": result.config.to_dict(),
    }


def render_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def render_csv(result: AnalysisResult, kind: str = "files") -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    if kind == "files":
        writer.writerow(["path", "loc", "functions", "classes", "total_complexity", "max_complexity", "mean_complexity",
                         "maintainability", "findings", "risk", "worst_function"])
        for s in sorted(result.files, key=lambda s: (-s.risk, s.path)):
            writer.writerow([s.path, s.loc, s.functions, s.classes, s.total_complexity, s.max_complexity,
                             f"{s.mean_complexity:.2f}", f"{s.maintainability:.2f}", s.findings, f"{s.risk:.2f}", s.worst_function])
    elif kind == "findings":
        writer.writerow(["rule_id", "severity", "confidence", "heuristic", "path", "line", "symbol", "message", "suggestion"])
        for f in result.findings:
            writer.writerow([f.rule_id, f.severity.value, f.confidence.value, f.is_heuristic, f.path, f.line, f.symbol, f.message, f.suggestion])
    elif kind == "functions":
        writer.writerow(["path", "function", "line", "loc", "complexity", "nesting", "parameters", "maintainability"])
        for m, f in sorted(result.functions, key=lambda mf: (-mf[1].complexity, mf[0].path, mf[1].lineno)):
            writer.writerow([m.path, f.qualname, f.lineno, f.loc, f.complexity, f.max_nesting, f.param_count, f.maintainability])
    else:
        raise ValueError(f"unknown CSV kind {kind!r}")
    return buffer.getvalue()


def trend_csv(trend: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    cols = ["scan_id", "created_at", "score", "grade", "findings", "loc", "mean_complexity", "max_complexity", "score_delta", "findings_delta"]
    writer.writerow(cols)
    for row in trend:
        writer.writerow(["" if row[c] is None else row[c] for c in cols])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Terminal text
# ---------------------------------------------------------------------------
def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    cells = [[str(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return ["  " + fmt.format(*headers).rstrip(), "  " + "  ".join("-" * w for w in widths)] + [
        "  " + fmt.format(*r).rstrip() for r in cells
    ]


def render_text(result: AnalysisResult, top: int = 10, max_findings: int = 50, color: bool = False,
                min_severity: Severity = Severity.INFO) -> str:
    s = result.summary()
    out: list[str] = [f"CodeMind analysis of {result.root}", "=" * 60]
    out.append(f"Score: {s['score']}/100 (grade {s['grade']})  [heuristic]")
    out.append(f"Files: {s['files_analyzed']} analysed / {s['files_found']} found, {s['files_skipped']} skipped | "
               f"LOC: {s['loc']} | Functions: {s['functions']} | Classes: {s['classes']}")
    counts = ", ".join(f"{k} {v}" for k, v in s["severity_counts"].items())
    out.append(f"Findings: {s['findings']} ({counts}); {s['heuristic_findings']} heuristic")
    out.append(f"Complexity: mean {s['mean_complexity']}, max {s['max_complexity']} | "
               f"Maintainability (mean): {s['mean_maintainability']} ({maintainability_band(s['mean_maintainability'])}) | "
               f"Import cycles: {s['cycles']}")
    if result.scan_id is not None:
        out.append(f"Saved as scan #{result.scan_id}")

    out += ["", "Score breakdown", "-" * 15]
    out += _table(["factor", "weight", "badness", "penalty", "detail"],
                  [[f.name, f"{f.weight:.1f}", f"{f.badness:.2f}", f"-{f.penalty:.1f}", f.detail] for f in result.score.factors])
    out.append(f"  Note: {CAVEAT}")

    if result.project.issues:
        out += ["", "Skipped files", "-" * 13]
        out += [f"  {i.path}: [{i.kind}] {i.message}" for i in result.project.issues]

    shown = [f for f in result.findings if f.severity.rank >= min_severity.rank]
    out += ["", f"Findings ({len(shown)} shown of {len(result.findings)})", "-" * 12]
    for f in shown[:max_findings]:
        tag = _paint(f"[{f.severity.value.upper()}]", f.severity.value, color)
        kind = f"{f.confidence.value}, heuristic" if f.is_heuristic else "definite"
        out.append(f"  {tag} {f.rule_id} {f.path}:{f.line}  {f.message}")
        out.append(f"        confidence: {kind} | fix: {f.suggestion}")
    if len(shown) > max_findings:
        out.append(f"  ... {len(shown) - max_findings} more (use --max-findings or --format json)")
    if not shown:
        out.append("  none")

    out += ["", f"Most complex functions (top {top})", "-" * 30]
    out += _table(["function", "location", "CC", "LOC", "nest", "MI"],
                  [[f.qualname, f"{m.path}:{f.lineno}", f.complexity, f.loc, f.max_nesting, f"{f.maintainability:.0f}"]
                   for m, f in result.top_functions(top)]) if result.functions else ["  no functions"]
    out += ["", f"Most complex modules (top {top})", "-" * 29]
    ranked = sorted(result.project.modules, key=lambda m: (-m.complexity, m.path))[:top]
    out += _table(["module", "total CC", "LOC", "MI"], [[m.path, m.complexity, m.loc, f"{m.maintainability:.0f}"] for m in ranked]) if ranked else ["  no modules"]

    out += ["", "Dependencies", "-" * 12]
    d = result.graph.summary()
    out.append(f"  {d['modules']} modules, {d['import_edges']} import edges, {d['functions']} functions, "
               f"{d['call_edges']} resolved call edges ({d['resolved_calls']}/{d['total_calls']} calls resolved)")
    if d["third_party_packages"]:
        out.append("  third-party imports: " + ", ".join(d["third_party_packages"]))
    for cycle in result.graph.cycles:
        out.append("  cycle: " + " -> ".join(cycle["path"] + [cycle["path"][0]]))
    coupled = [(n, m) for n, m in result.graph.top_modules("coupling", 5) if m["coupling"] > 0]
    if coupled:
        out.append("  most connected modules:")
        out += _table(["module", "in", "out", "betweenness"], [[n, m["in_degree"], m["out_degree"], m["betweenness"]] for n, m in coupled])
    if result.graph.isolated_functions:
        sample = ", ".join(result.graph.isolated_functions[:5])
        more = len(result.graph.isolated_functions) - 5
        out.append(f"  isolated functions (no resolved callers/callees): {sample}" + (f" (+{more} more)" if more > 0 else ""))

    out += ["", "Highest-risk files", "-" * 18]
    risky = result.top_files(top)
    out += _table(["file", "risk", "findings", "max CC", "MI"], [[x.path, f"{x.risk:.1f}", x.findings, x.max_complexity, f"{x.maintainability:.0f}"] for x in risky]) if risky else ["  none"]
    out += ["", "Recommended priorities", "-" * 22] + [f"  {i}. {p}" for i, p in enumerate(result.priorities(), 1)]
    if result.rule_errors:
        out += ["", "Internal rule errors"] + [f"  {e}" for e in result.rule_errors]
    out += ["", DISCLAIMER]
    return "\n".join(out) + "\n"


def render_compare_text(cmp: dict[str, Any], limit: int = 15) -> str:
    b, a, d = cmp["before"], cmp["after"], cmp["delta"]
    sign = lambda v: f"{v:+g}"  # noqa: E731
    out = [f"Comparison of scan #{b['id']} -> #{a['id']}  ({cmp['root']})", "=" * 60,
           f"Score:        {b['score']} -> {a['score']} ({sign(d['score'])})   grade {b['grade']} -> {a['grade']}",
           f"Findings:     {b['finding_count']} -> {a['finding_count']} ({sign(d['findings'])})",
           f"LOC:          {b['loc']} -> {a['loc']} ({sign(d['loc'])})",
           f"Complexity:   mean {b['mean_complexity']} -> {a['mean_complexity']} ({sign(d['mean_complexity'])}), "
           f"max {b['max_complexity']} -> {a['max_complexity']} ({sign(d['max_complexity'])})",
           f"Maintainab.:  mean {b['mean_maintainability']} -> {a['mean_maintainability']} ({sign(d['mean_maintainability'])})", ""]
    for title, key in (("New findings", "new_findings"), ("Resolved findings", "resolved_findings")):
        items = cmp[key]
        out.append(f"{title}: {len(items)}")
        out += [f"  {f['rule_id']} [{f['severity']}] {f['path']}:{f['line']}  {f['message']}" for f in items[:limit]]
        if len(items) > limit:
            out.append(f"  ... {len(items) - limit} more")
    out.append(f"Persistent findings: {len(cmp['persistent_findings'])}")
    out += ["", f"Complexity regressions: {len(cmp['complexity_regressions'])}"]
    out += [f"  {c['path']} {c['function']}: {c['before']} -> {c['after']} ({c['delta']:+d})" for c in cmp["complexity_regressions"][:limit]]
    out.append(f"Complexity improvements: {len(cmp['complexity_improvements'])}")
    out += [f"  {c['path']} {c['function']}: {c['before']} -> {c['after']} ({c['delta']:+d})" for c in cmp["complexity_improvements"][:limit]]
    out.append(f"Functions added: {len(cmp['added_functions'])}, removed: {len(cmp['removed_functions'])}")
    return "\n".join(out) + "\n"


def render_trend_text(trend: list[dict[str, Any]]) -> list[str]:
    rows = []
    for t in trend:
        bar = "#" * int(round(t["score"] / 5))
        delta = "" if t["score_delta"] is None else f"{t['score_delta']:+.1f}"
        rows.append([f"#{t['scan_id']}", t["created_at"], f"{t['score']:.1f}", t["grade"], delta, t["findings"], t["mean_complexity"], bar])
    return _table(["scan", "when (UTC)", "score", "grade", "delta", "findings", "mean CC", "score bar (5 pts = #)"], rows)


def render_stored_report(report: dict[str, Any], trend: list[dict[str, Any]], top: int = 10) -> str:
    s = report["summary"]
    out = [f"CodeMind history report for {report['root']}", "=" * 60,
           f"Latest scan #{report['scan_id']} at {report['created_at']}",
           f"Score: {s['score']}/100 (grade {s['grade']})  [heuristic] | LOC {s['loc']} | functions {s['functions']} | files {s['files_analyzed']}",
           "Findings: " + ", ".join(f"{k} {s['severity_counts'].get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")) + f" (total {s['findings']})",
           "", "Score breakdown", "-" * 15]
    out += _table(["factor", "weight", "badness", "penalty", "detail"],
                  [[f["name"], f["weight"], f["badness"], f"-{f['penalty']}", f["detail"]] for f in report["score"]["factors"]])
    out += ["", "Trend", "-" * 5] + render_trend_text(trend)
    out += ["", "Highest-risk files", "-" * 18]
    out += _table(["file", "risk", "findings", "max CC"], [[x["path"], x["risk"], x["findings"], x["max_complexity"]] for x in report["top_files"][:top]]) if report["top_files"] else ["  none"]
    out += ["", "Recommended priorities", "-" * 22] + [f"  {i}. {p}" for i, p in enumerate(report["priorities"], 1)]
    out += ["", DISCLAIMER]
    return "\n".join(out) + "\n"


def render_rules_text(metas: list[RuleMeta]) -> str:
    rows = [[m.id, m.name, m.category, m.severity.value, m.confidence.value] for m in metas]
    return "\n".join(["Available rules (use 'codemind explain RULE_ID' for details)", ""] + _table(["id", "name", "category", "severity", "confidence"], rows)) + "\n"


def render_rule_explanation(meta: RuleMeta) -> str:
    out = [f"{meta.id}: {meta.name}", "=" * 60, f"Category:   {meta.category}", f"Severity:   {meta.severity.value} (default; configurable)",
           f"Confidence: {meta.confidence.value}" + (" (heuristic)" if meta.confidence.value != "definite" else " (syntactic/measured fact)"),
           "", "What it detects", f"  {meta.summary}", "", "Why it matters", f"  {meta.rationale}", "", "Suggested fix", f"  {meta.suggestion}"]
    if meta.bad:
        out += ["", "Problematic example"] + [f"    {line}" for line in meta.bad.splitlines()]
    if meta.good:
        out += ["", "Better"] + [f"    {line}" for line in meta.good.splitlines()]
    if meta.limitations:
        out += ["", "Limitations", f"  {meta.limitations}"]
    out += ["", "Suppress on one line with:  # codemind: ignore[" + meta.id + "]"]
    return "\n".join(out) + "\n"
