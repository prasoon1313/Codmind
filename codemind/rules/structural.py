"""Size, complexity and hygiene rules (CM1xx imports, CM2xx structure)."""
from __future__ import annotations

from typing import Iterable

from codemind.models import Confidence, Finding, ModuleInfo, Severity
from codemind.rules.base import Rule, RuleContext, RuleMeta, register


@register
class UnusedImport(Rule):
    meta = RuleMeta(
        "CM114", "unused-import", "hygiene", Severity.LOW, Confidence.HIGH,
        "An imported name is never used in the module.",
        "Unused imports add noise, slow start-up and can hide circular-import problems.",
        "Remove the import, or re-export it explicitly through __all__.",
        "import os\n\nprint('hi')", "print('hi')",
        "Names used only via getattr/strings, side-effect imports and __init__.py re-exports are not detected; "
        "__init__.py files are skipped. Names in string annotations and __all__ count as used.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        if module.is_package:
            return
        for imp in module.imports:
            if imp.module == "__future__":
                continue
            for binding in imp.bindings:
                if binding.local not in module.used_names:
                    yield self.make(module.path, imp.lineno, f"'{binding.local}' is imported but never used.",
                                    detail=binding.local)


@register
class WildcardImport(Rule):
    meta = RuleMeta(
        "CM115", "wildcard-import", "hygiene", Severity.LOW, Confidence.DEFINITE,
        "A 'from module import *' statement.",
        "Wildcard imports pollute the namespace, hide where names come from and defeat static analysis.",
        "Import the specific names you need.",
        "from os.path import *", "from os.path import join, exists",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for imp in module.imports:
            if imp.wildcard:
                yield self.make(module.path, imp.lineno, f"Wildcard import from '{imp.module or '.' * imp.level}'.",
                                detail=imp.module)


@register
class LongFunction(Rule):
    meta = RuleMeta(
        "CM201", "long-function", "complexity", Severity.MEDIUM, Confidence.DEFINITE,
        "A function has more code lines than the configured limit.",
        "Long functions mix responsibilities, are hard to test and review, and tend to accumulate bugs.",
        "Extract cohesive blocks into well-named helper functions.",
        limitations="Counts non-blank, non-comment lines between 'def' and the end of the body.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        limit = ctx.config.thresholds.max_function_lines
        for fn in module.functions:
            if fn.loc > limit:
                yield self.make(module.path, fn.lineno, f"'{fn.qualname}' has {fn.loc} lines (limit {limit}).",
                                symbol=fn.qualname,
                                severity=Severity.HIGH if fn.loc > 2 * limit else Severity.MEDIUM)


@register
class HighComplexity(Rule):
    meta = RuleMeta(
        "CM202", "high-cyclomatic-complexity", "complexity", Severity.MEDIUM, Confidence.DEFINITE,
        "A function's cyclomatic complexity exceeds the configured limit.",
        "Each decision point adds an execution path that needs a test. High complexity correlates with defects.",
        "Split the function, replace conditionals with data tables or polymorphism, use early returns.",
        limitations="Method is documented in codemind.complexity. Severity becomes HIGH above 'high_complexity'.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        t = ctx.config.thresholds
        for fn in module.functions:
            if fn.complexity > t.max_complexity:
                yield self.make(module.path, fn.lineno,
                                f"'{fn.qualname}' has cyclomatic complexity {fn.complexity} (limit {t.max_complexity}).",
                                symbol=fn.qualname,
                                severity=Severity.HIGH if fn.complexity > t.high_complexity else Severity.MEDIUM)


@register
class DeepNesting(Rule):
    meta = RuleMeta(
        "CM203", "deep-nesting", "complexity", Severity.MEDIUM, Confidence.DEFINITE,
        "Control structures are nested deeper than the configured limit.",
        "Deep nesting makes the flow hard to follow and usually signals missing guard clauses or helpers.",
        "Use early returns/continues, extract inner blocks, or flatten conditions.",
        limitations="'elif' chains do not count as extra nesting.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        limit = ctx.config.thresholds.max_nesting
        for fn in module.functions:
            if fn.max_nesting > limit:
                yield self.make(module.path, fn.lineno, f"'{fn.qualname}' nests control flow {fn.max_nesting} levels deep (limit {limit}).",
                                symbol=fn.qualname)


@register
class TooManyParameters(Rule):
    meta = RuleMeta(
        "CM204", "too-many-parameters", "complexity", Severity.LOW, Confidence.DEFINITE,
        "A function takes more parameters than the configured limit.",
        "Long parameter lists are hard to call correctly and often hide a missing abstraction.",
        "Group related parameters in a dataclass or pass a configuration object.",
        limitations="'self'/'cls' are not counted; *args and **kwargs count as one each.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        limit = ctx.config.thresholds.max_parameters
        for fn in module.functions:
            if fn.param_count > limit:
                yield self.make(module.path, fn.lineno, f"'{fn.qualname}' takes {fn.param_count} parameters (limit {limit}).",
                                symbol=fn.qualname)


@register
class LargeClass(Rule):
    meta = RuleMeta(
        "CM205", "large-class", "complexity", Severity.MEDIUM, Confidence.DEFINITE,
        "A class is longer, or has more methods, than the configured limits.",
        "Very large classes usually violate the single-responsibility principle.",
        "Split the class by responsibility; extract collaborators or mixins.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        t = ctx.config.thresholds
        for cls in module.classes:
            reasons = []
            if cls.loc > t.max_class_lines:
                reasons.append(f"{cls.loc} lines (limit {t.max_class_lines})")
            if len(cls.methods) > t.max_class_methods:
                reasons.append(f"{len(cls.methods)} methods (limit {t.max_class_methods})")
            if reasons:
                yield self.make(module.path, cls.lineno, f"Class '{cls.qualname}' is large: {', '.join(reasons)}.",
                                symbol=cls.qualname)
