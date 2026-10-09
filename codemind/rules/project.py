"""Project-level rules: scan problems, architecture and dead-code hints."""
from __future__ import annotations

from typing import Iterable

from codemind.models import Confidence, Finding, ProjectInfo, Severity
from codemind.rules.base import Rule, RuleContext, RuleMeta, register


@register
class SyntaxErrorRule(Rule):
    meta = RuleMeta(
        "CM001", "file-syntax-error", "scan", Severity.HIGH, Confidence.DEFINITE,
        "A Python file could not be parsed.",
        "The file cannot be imported or analysed; every other check is skipped for it.",
        "Fix the syntax error (note: the analysed project is never executed).",
        limitations="Parsing uses the interpreter running CodeMind, so syntax newer than that version is reported as an error.",
    )

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        for issue in project.issues:
            if issue.kind == "syntax_error":
                yield self.make(issue.path, issue.line, f"Syntax error: {issue.message}", detail=issue.message)


@register
class UnreadableFileRule(Rule):
    meta = RuleMeta(
        "CM002", "unreadable-file", "scan", Severity.LOW, Confidence.DEFINITE,
        "A Python file was skipped because it could not be read, decoded or exceeds the size limit.",
        "Skipped files are not analysed, so results may under-report problems.",
        "Check permissions/encoding, or raise 'max_file_size_kb' in the configuration.",
    )

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        for issue in project.issues:
            if issue.kind in ("unreadable", "too_large"):
                yield self.make(issue.path, 1, f"File skipped: {issue.message}", detail=issue.kind)


@register
class CircularImport(Rule):
    meta = RuleMeta(
        "CM301", "circular-import", "architecture", Severity.HIGH, Confidence.DEFINITE,
        "Modules import each other in a cycle through module-level imports.",
        "Import cycles cause partially initialised modules, ImportError at start-up and tight coupling.",
        "Move shared code to a third module, invert the dependency, or import lazily inside a function as a last resort.",
        limitations="Only module-level imports form cycles; imports inside functions and under TYPE_CHECKING are excluded. "
        "Whether a cycle fails at runtime depends on import order.",
    )

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        if ctx.graph is None:
            return
        for cycle in ctx.graph.cycles:
            chain = " -> ".join([*cycle["path"], cycle["path"][0]])
            yield self.make(cycle["file"], cycle["line"], f"Circular import: {chain}.",
                            detail=",".join(cycle["modules"]))


@register
class HighCoupling(Rule):
    meta = RuleMeta(
        "CM302", "high-module-coupling", "architecture", Severity.MEDIUM, Confidence.MEDIUM,
        "A module has many internal import relationships (in + out).",
        "Highly connected modules are architectural bottlenecks: changes ripple widely and they are hard to test in isolation.",
        "Split the module by responsibility and narrow its public surface.",
        limitations="Heuristic based on the static import graph; legitimate facade modules may be flagged.",
    )

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        if ctx.graph is None:
            return
        limit = ctx.config.thresholds.max_module_coupling
        by_name = {m.name: m for m in project.modules}
        for name, metrics in sorted(ctx.graph.module_metrics.items()):
            if metrics["coupling"] > limit and name in by_name:
                yield self.make(
                    by_name[name].path, 1,
                    f"Module '{name}' is connected to {metrics['coupling']} modules "
                    f"(fan-in {metrics['in_degree']}, fan-out {metrics['out_degree']}, limit {limit}).",
                    symbol=name,
                )


@register
class UnusedPrivateFunction(Rule):
    meta = RuleMeta(
        "CM303", "possibly-unused-private-function", "hygiene", Severity.LOW, Confidence.LOW,
        "A private (_name) function or method is never referenced anywhere in the project.",
        "Unreferenced private helpers are often leftovers and add maintenance cost.",
        "Delete the function after confirming it is not used dynamically.",
        limitations="Dynamic access (getattr with computed names, plugins, serialisation hooks) is invisible to static analysis. "
        "Decorated functions and dunder methods are skipped.",
    )

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        referenced: set[str] = set()
        for module in project.modules:
            referenced |= module.referenced_names
        for module in project.modules:
            for fn in module.functions:
                name = fn.name
                if not name.startswith("_") or name.startswith("__") or fn.decorators:
                    continue
                own_refs = sum(1 for other in module.functions for c in other.calls if c.split(".")[-1] == name)
                if name not in referenced and own_refs == 0:
                    yield self.make(module.path, fn.lineno, f"Private function '{fn.qualname}' is never referenced.",
                                    symbol=fn.qualname)
