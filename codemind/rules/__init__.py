"""Rule engine: registry plus execution with severity overrides and suppressions."""
from __future__ import annotations

import re
from dataclasses import replace

from codemind.models import Finding, ProjectInfo
from codemind.rules import bugs, duplicates, project as project_rules, structural  # noqa: F401  (register rules)
from codemind.rules.base import Rule, RuleContext, RuleMeta, all_rules, get_rule, register

__all__ = ["Rule", "RuleContext", "RuleMeta", "all_rules", "get_rule", "register", "run_rules"]

_SUPPRESS = re.compile(r"#\s*codemind:\s*ignore(?:\[([A-Za-z0-9_,\s]+)\])?")


def _suppressed(finding: Finding, lines_by_path: dict[str, list[str]]) -> bool:
    lines = lines_by_path.get(finding.path)
    if not lines or not 1 <= finding.line <= len(lines):
        return False
    match = _SUPPRESS.search(lines[finding.line - 1])
    if not match:
        return False
    if match.group(1) is None:
        return True
    return finding.rule_id in {r.strip().upper() for r in match.group(1).split(",")}


def run_rules(project: ProjectInfo, ctx: RuleContext) -> tuple[list[Finding], list[str]]:
    """Run all enabled rules; returns ``(findings, internal_errors)``.

    A crashing rule never aborts the analysis: it is reported in the error list.
    Inline ``# codemind: ignore[RULE]`` comments suppress findings on that line.
    """
    config = ctx.config
    findings: list[Finding] = []
    errors: list[str] = []
    for rule in all_rules():
        rule_id = rule.meta.id
        if rule_id in config.disabled_rules:
            continue
        try:
            for module in project.modules:
                try:
                    findings.extend(rule.check_module(module, ctx))
                except Exception as exc:  # noqa: BLE001 - isolate rule failures
                    errors.append(f"{rule_id} failed on {module.path}: {type(exc).__name__}: {exc}")
            findings.extend(rule.check_project(project, ctx))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rule_id} failed: {type(exc).__name__}: {exc}")

    lines_by_path = {m.path: m.lines for m in project.modules}
    result: dict[tuple, Finding] = {}
    for finding in findings:
        override = config.severity_overrides.get(finding.rule_id)
        if override is not None:
            finding = replace(finding, severity=override)
        if _suppressed(finding, lines_by_path):
            continue
        result.setdefault((finding.rule_id, finding.path, finding.line, finding.message), finding)
    return sorted(result.values(), key=lambda f: f.sort_key()), errors
