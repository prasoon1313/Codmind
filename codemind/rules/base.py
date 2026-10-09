"""Rule framework: metadata, base class, registry and execution context."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Optional

from codemind.config import Config
from codemind.models import Confidence, Finding, ModuleInfo, ProjectInfo, Severity

if TYPE_CHECKING:  # pragma: no cover
    from codemind.dependency_graph import DependencyAnalysis


@dataclass(frozen=True)
class RuleMeta:
    """Static documentation for a rule (used by ``codemind rules/explain``)."""

    id: str
    name: str
    category: str
    severity: Severity
    confidence: Confidence
    summary: str
    rationale: str
    suggestion: str
    bad: str = ""
    good: str = ""
    limitations: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "default_severity": self.severity.value,
            "default_confidence": self.confidence.value,
            "summary": self.summary,
            "rationale": self.rationale,
            "suggestion": self.suggestion,
            "bad_example": self.bad,
            "good_example": self.good,
            "limitations": self.limitations,
        }


@dataclass
class RuleContext:
    config: Config
    graph: Optional["DependencyAnalysis"] = None


class Rule:
    """Base class. Override :meth:`check_module` and/or :meth:`check_project`."""

    meta: RuleMeta

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        return ()

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        return ()

    def make(
        self,
        path: str,
        line: int,
        message: str,
        *,
        symbol: str = "",
        detail: str = "",
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        suggestion: Optional[str] = None,
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity or self.meta.severity,
            path=path,
            line=max(int(line), 1),
            message=message,
            confidence=confidence or self.meta.confidence,
            suggestion=suggestion or self.meta.suggestion,
            symbol=symbol,
            detail=detail,
            category=self.meta.category,
        )


_REGISTRY: dict[str, Rule] = {}


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator adding a rule instance to the global registry."""
    instance = cls()
    rule_id = instance.meta.id
    if rule_id in _REGISTRY:
        raise ValueError(f"duplicate rule id {rule_id}")
    _REGISTRY[rule_id] = instance
    return cls


def all_rules() -> list[Rule]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def get_rule(rule_id: str) -> Rule:
    try:
        return _REGISTRY[rule_id.upper()]
    except KeyError:
        raise KeyError(f"unknown rule {rule_id!r}") from None
