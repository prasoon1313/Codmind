"""Configuration loading and validation (``codemind.toml`` / ``[tool.codemind]``)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

from codemind.models import Severity

DEFAULT_IGNORED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".env", "virtualenv", ".tox", ".nox",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".eggs", "node_modules", "site-packages",
        "build", "dist", ".idea", ".vscode", ".codemind",
    }
)


class ConfigError(ValueError):
    """Raised for invalid configuration values."""


@dataclass
class Thresholds:
    max_function_lines: int = 50
    max_complexity: int = 10
    high_complexity: int = 20
    max_nesting: int = 4
    max_parameters: int = 6
    max_class_lines: int = 300
    max_class_methods: int = 20
    max_module_coupling: int = 15
    duplicate_min_statements: int = 4
    duplicate_min_nodes: int = 30


@dataclass
class ScoreWeights:
    """Relative weights (normalised to 100) of the score factors."""

    findings: float = 35.0
    complexity: float = 25.0
    maintainability: float = 20.0
    structure: float = 20.0
    density_scale: float = 5.0  # weighted finding points / 100 LOC giving ~63% findings badness


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    max_file_size_kb: int = 2048
    thresholds: Thresholds = field(default_factory=Thresholds)
    weights: ScoreWeights = field(default_factory=ScoreWeights)
    disabled_rules: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    db_path: Optional[Path] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "exclude": list(self.exclude),
            "max_file_size_kb": self.max_file_size_kb,
            "thresholds": {f.name: getattr(self.thresholds, f.name) for f in fields(self.thresholds)},
            "weights": {f.name: getattr(self.weights, f.name) for f in fields(self.weights)},
            "disabled_rules": sorted(self.disabled_rules),
            "severity_overrides": {k: v.value for k, v in sorted(self.severity_overrides.items())},
        }


def _number(section: str, key: str, value: Any, kind: type) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"[{section}] {key} must be a number, got {value!r}")
    if kind is int:
        if value != int(value):
            raise ConfigError(f"[{section}] {key} must be an integer, got {value!r}")
        value = int(value)
    else:
        value = float(value)
    if value < 0 or (key.startswith(("max_", "duplicate_")) and value == 0):
        raise ConfigError(f"[{section}] {key} must be positive, got {value!r}")
    return value


def _fill(section: str, target: Any, data: Any) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"[{section}] must be a table")
    known = {f.name: f for f in fields(target)}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"[{section}] unknown key {key!r}; allowed: {', '.join(sorted(known))}")
        kind = type(getattr(target, key))
        setattr(target, key, _number(section, key, value, kind))


def config_from_mapping(data: dict[str, Any], base_dir: Optional[Path] = None) -> Config:
    """Build a validated :class:`Config` from a parsed TOML mapping."""
    allowed = {"exclude", "max_file_size_kb", "thresholds", "weights", "rules", "db_path"}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    config = Config()
    exclude = data.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(e, str) for e in exclude):
        raise ConfigError("exclude must be a list of glob strings")
    config.exclude = list(exclude)
    if "max_file_size_kb" in data:
        config.max_file_size_kb = _number("config", "max_file_size_kb", data["max_file_size_kb"], int)
    _fill("thresholds", config.thresholds, data.get("thresholds", {}))
    _fill("weights", config.weights, data.get("weights", {}))
    rules = data.get("rules", {})
    if not isinstance(rules, dict) or set(rules) - {"disable", "severity"}:
        raise ConfigError("[rules] may only contain 'disable' (list) and 'severity' (table)")
    disable = rules.get("disable", [])
    if not isinstance(disable, list) or not all(isinstance(r, str) for r in disable):
        raise ConfigError("[rules] disable must be a list of rule IDs")
    config.disabled_rules = {r.upper() for r in disable}
    severity = rules.get("severity", {})
    if not isinstance(severity, dict):
        raise ConfigError("[rules.severity] must be a table of RULE_ID = \"level\"")
    for rule_id, level in severity.items():
        try:
            config.severity_overrides[str(rule_id).upper()] = Severity.parse(level)
        except ValueError as exc:
            raise ConfigError(f"[rules.severity] {rule_id}: {exc}") from None
    if "db_path" in data:
        if not isinstance(data["db_path"], str) or not data["db_path"]:
            raise ConfigError("db_path must be a non-empty string")
        path = Path(data["db_path"]).expanduser()
        config.db_path = path if path.is_absolute() or base_dir is None else (base_dir / path)
    return config


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration {path}: {exc}") from None


def load_config(explicit: Optional[Path], root: Path) -> Config:
    """Load config from ``explicit``, ``root/codemind.toml`` or pyproject ``[tool.codemind]``."""
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"configuration file not found: {explicit}")
        data = _read_toml(explicit)
        if explicit.name == "pyproject.toml":
            data = data.get("tool", {}).get("codemind", {})
        return config_from_mapping(data, explicit.parent)
    candidate = root / "codemind.toml"
    if candidate.is_file():
        return config_from_mapping(_read_toml(candidate), root)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        section = _read_toml(pyproject).get("tool", {}).get("codemind")
        if section is not None:
            return config_from_mapping(section, root)
    return Config()


def apply_threshold_overrides(config: Config, pairs: list[str]) -> None:
    """Apply ``NAME=VALUE`` CLI overrides to the thresholds table."""
    updates: dict[str, Any] = {}
    for pair in pairs:
        name, sep, raw = pair.partition("=")
        if not sep:
            raise ConfigError(f"invalid --threshold {pair!r}; expected NAME=VALUE")
        try:
            updates[name.strip()] = int(raw)
        except ValueError:
            raise ConfigError(f"--threshold {name}: value must be an integer, got {raw!r}") from None
    _fill("thresholds", config.thresholds, updates)
