"""Core data models shared by every CodeMind component.

AST nodes and raw sources are attached to models with ``serialize=False``
metadata so :func:`to_plain` can emit JSON-safe dictionaries.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(str, Enum):
    """Finding severity, ordered from least to most serious."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return value if isinstance(value, cls) else cls(str(value).strip().lower())
        except ValueError:
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {allowed}") from None


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """How strongly a finding is supported by static evidence.

    ``DEFINITE`` means the finding is a syntactic/measured fact (it does not
    claim anything about runtime behaviour). Everything else is a heuristic.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DEFINITE = "definite"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2, Confidence.DEFINITE: 3}


@dataclass(frozen=True)
class Finding:
    """A single analysis result. Heuristic findings never prove a runtime bug."""

    rule_id: str
    severity: Severity
    path: str
    line: int
    message: str
    confidence: Confidence
    suggestion: str
    symbol: str = ""
    detail: str = ""
    category: str = ""

    @property
    def fingerprint(self) -> str:
        """Line-independent identity so moved code is not reported as new."""
        raw = "\x1f".join((self.rule_id, self.path, self.symbol, self.detail))
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def is_heuristic(self) -> bool:
        return self.confidence is not Confidence.DEFINITE

    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.path, self.line, self.rule_id, self.message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "heuristic": self.is_heuristic,
            "path": self.path,
            "line": self.line,
            "symbol": self.symbol,
            "message": self.message,
            "suggestion": self.suggestion,
            "category": self.category,
            "fingerprint": self.fingerprint,
        }


_NO_SERIALIZE = {"serialize": False}


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    lineno: int
    end_lineno: int
    signature: str
    params: list[str]
    param_count: int
    decorators: list[str]
    has_docstring: bool
    is_method: bool
    is_async: bool
    class_qualname: Optional[str]
    loc: int
    complexity: int
    max_nesting: int
    maintainability: float
    calls: list[str]
    node: Any = field(default=None, repr=False, compare=False, metadata=_NO_SERIALIZE)


@dataclass
class ClassInfo:
    name: str
    qualname: str
    lineno: int
    end_lineno: int
    bases: list[str]
    decorators: list[str]
    has_docstring: bool
    methods: list[str]
    loc: int
    complexity: int
    node: Any = field(default=None, repr=False, compare=False, metadata=_NO_SERIALIZE)


@dataclass
class ImportBinding:
    """A local name introduced by an import and the dotted object it refers to."""

    local: str
    target: str


@dataclass
class ImportInfo:
    module: str  # absolute dotted module being imported ("" if unresolvable)
    lineno: int
    level: int
    is_from: bool
    names: list[str]  # names imported by ``from module import ...``
    bindings: list[ImportBinding]
    scope: str  # "top" | "lazy" (inside a function) | "type_checking"
    wildcard: bool = False


@dataclass
class GlobalVar:
    name: str
    lineno: int
    is_constant: bool


@dataclass
class ModuleInfo:
    path: str  # POSIX path relative to the scan root
    name: str  # dotted module name
    is_package: bool
    loc: int
    has_docstring: bool
    complexity: int = 1
    maintainability: float = 100.0
    imports: list[ImportInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    globals: list[GlobalVar] = field(default_factory=list)
    used_names: set[str] = field(default_factory=set, metadata=_NO_SERIALIZE)
    referenced_names: set[str] = field(default_factory=set, metadata=_NO_SERIALIZE)
    tree: Any = field(default=None, repr=False, compare=False, metadata=_NO_SERIALIZE)
    source: str = field(default="", repr=False, compare=False, metadata=_NO_SERIALIZE)

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()


@dataclass
class ScanIssue:
    """A file that could not be analysed (syntax error, unreadable, too large)."""

    path: str
    kind: str  # syntax_error | unreadable | too_large | skipped
    message: str
    line: int = 1


@dataclass
class ProjectInfo:
    root: Path
    modules: list[ModuleInfo] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    files_found: int = 0
    package_prefix: str = ""

    def module_by_path(self) -> dict[str, ModuleInfo]:
        return {m.path: m for m in self.modules}

    @property
    def total_loc(self) -> int:
        return sum(m.loc for m in self.modules)


def to_plain(obj: Any) -> Any:
    """Convert models (and containers of models) to JSON-serialisable data."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_plain(getattr(obj, f.name)) for f in fields(obj) if f.metadata.get("serialize", True)}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_plain(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_plain(v) for v in obj)
    if isinstance(obj, Path):
        return obj.as_posix()
    if isinstance(obj, ast.AST):
        return None
    return obj
