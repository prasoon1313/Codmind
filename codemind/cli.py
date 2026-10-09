"""Command-line interface (argparse)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from codemind import __version__
from codemind.analyzer import analyze
from codemind.config import Config, ConfigError, apply_threshold_overrides, load_config
from codemind.history import HistoryError, HistoryStore, default_db_path
from codemind.models import Severity
from codemind.reporting import (
    OutputPathError,
    render_compare_text,
    render_csv,
    render_json,
    render_rule_explanation,
    render_rules_text,
    render_stored_report,
    render_text,
    result_to_dict,
    trend_csv,
    use_color,
    write_output,
)
from codemind.rules import all_rules, get_rule

EXIT_OK, EXIT_ERROR, EXIT_THRESHOLD = 0, 1, 3


class CliError(Exception):
    """User-facing error; printed without a traceback."""


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _add_analysis_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", type=Path, help="path to codemind.toml / pyproject.toml (default: auto-detect in the project)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="additional ignored path glob (repeatable)")
    p.add_argument("--disable", action="append", default=[], metavar="RULE_ID", help="disable a rule (repeatable)")
    p.add_argument("--threshold", action="append", default=[], metavar="NAME=VALUE", help="override a threshold, e.g. max_complexity=15")


def _add_output_options(p: argparse.ArgumentParser, formats: Sequence[str]) -> None:
    p.add_argument("--format", choices=formats, default=formats[0], help=f"output format (default: {formats[0]})")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codemind", description="CodeMind: offline static analysis for Python codebases.",
                                     epilog="Static analysis only: results are heuristics and never prove runtime bugs.")
    parser.add_argument("--version", action="version", version=f"codemind {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = sub.add_parser("scan", help="analyse a project and store the result in the history database")
    scan.add_argument("path", type=Path)
    _add_analysis_options(scan)
    _add_output_options(scan, ("text", "json", "csv"))
    scan.add_argument("--csv-kind", choices=("files", "findings", "functions"), default="files", help="CSV table to export (default: files)")
    scan.add_argument("--db", type=Path, help="history database (default: $CODEMIND_DB or ~/.codemind/history.db)")
    scan.add_argument("--no-save", action="store_true", help="do not store this scan in the history database")
    scan.add_argument("--top", type=_positive, default=10, help="rows in ranking tables (default: 10)")
    scan.add_argument("--max-findings", type=_positive, default=50, help="findings listed in the text report (default: 50)")
    scan.add_argument("--min-severity", type=_severity, default="info", help="hide findings below this severity in text output")
    scan.add_argument("--fail-on", type=_severity, metavar="SEVERITY", help="exit with status 3 if any finding is at least this severe")
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="show the latest stored scan and the historical trend for a project")
    report.add_argument("path", type=Path)
    report.add_argument("--config", type=Path)
    _add_output_options(report, ("text", "json", "csv"))
    report.add_argument("--db", type=Path)
    report.add_argument("--top", type=_positive, default=10)
    report.set_defaults(func=cmd_report)

    compare = sub.add_parser("compare", help="compare two stored scans (new / resolved / persistent findings)")
    compare.add_argument("--before", type=int, required=True, metavar="SCAN_ID")
    compare.add_argument("--after", type=int, required=True, metavar="SCAN_ID")
    _add_output_options(compare, ("text", "json"))
    compare.add_argument("--db", type=Path)
    compare.set_defaults(func=cmd_compare)

    graph = sub.add_parser("graph", help="export the dependency graph")
    graph.add_argument("path", type=Path)
    _add_analysis_options(graph)
    _add_output_options(graph, ("json", "graphml"))
    graph.add_argument("--kind", choices=("imports", "calls", "both"), help="graph to export (default: both for json, imports for graphml)")
    graph.set_defaults(func=cmd_graph)

    rules = sub.add_parser("rules", help="list all rules")
    _add_output_options(rules, ("text", "json"))
    rules.set_defaults(func=cmd_rules)

    explain = sub.add_parser("explain", help="explain one rule")
    explain.add_argument("rule_id", metavar="RULE_ID")
    explain.set_defaults(func=cmd_explain)
    return parser


# ---------------------------------------------------------------------------
def _project_dir(path: Path) -> Path:
    if not path.exists():
        raise CliError(f"path does not exist: {path}")
    if not path.is_dir():
        raise CliError(f"not a directory: {path}")
    return path


def _config_for(args: argparse.Namespace, root: Path) -> Config:
    config = load_config(args.config, root)
    config.exclude.extend(getattr(args, "exclude", []))
    config.disabled_rules.update(r.upper() for r in getattr(args, "disable", []))
    apply_threshold_overrides(config, getattr(args, "threshold", []))
    return config


def _db_path(args: argparse.Namespace, config: Optional[Config] = None) -> Path:
    if getattr(args, "db", None):
        return args.db
    if config is not None and config.db_path is not None:
        return config.db_path
    return default_db_path()


def _emit(text: str, args: argparse.Namespace) -> None:
    if getattr(args, "output", None):
        path = write_output(args.output, text)
        print(f"Wrote {path}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_scan(args: argparse.Namespace) -> int:
    root = _project_dir(args.path)
    config = _config_for(args, root)
    result = analyze(root, config)
    if not args.no_save:
        with HistoryStore(_db_path(args, config)) as store:
            store.save(result)
    if args.format == "json":
        text = render_json(result_to_dict(result, args.top))
    elif args.format == "csv":
        text = render_csv(result, args.csv_kind)
    else:
        text = render_text(result, args.top, args.max_findings, color=use_color(sys.stdout) and not args.output,
                           min_severity=args.min_severity)
    _emit(text, args)
    if args.fail_on is not None and any(f.severity.rank >= args.fail_on.rank for f in result.findings):
        print(f"codemind: findings at or above '{args.fail_on.value}' were found", file=sys.stderr)
        return EXIT_THRESHOLD
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    root = _project_dir(args.path)
    config = load_config(args.config, root)
    with HistoryStore(_db_path(args, config)) as store:
        scan_id = store.latest_scan_id(root)
        if scan_id is None:
            raise CliError(f"no stored scans for {root.resolve()}; run 'codemind scan {args.path}' first")
        report, trend = store.stored_report(scan_id), store.trend(root)
    if args.format == "json":
        text = render_json({**report, "trend": trend})
    elif args.format == "csv":
        text = trend_csv(trend)
    else:
        text = render_stored_report(report, trend, args.top)
    _emit(text, args)
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    with HistoryStore(_db_path(args)) as store:
        comparison = store.compare(args.before, args.after)
    _emit(render_json(comparison) if args.format == "json" else render_compare_text(comparison), args)
    return EXIT_OK


def cmd_graph(args: argparse.Namespace) -> int:
    root = _project_dir(args.path)
    result = analyze(root, _config_for(args, root))
    if args.format == "graphml":
        kind = args.kind or "imports"
        if kind == "both":
            raise CliError("GraphML holds a single graph; choose --kind imports or --kind calls")
        text = result.graph.to_graphml(kind)
    else:
        text = render_json(result.graph.to_dict(args.kind or "both"))
    _emit(text, args)
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    metas = [r.meta for r in all_rules()]
    _emit(render_json([m.to_dict() for m in metas]) if args.format == "json" else render_rules_text(metas), args)
    return EXIT_OK


def cmd_explain(args: argparse.Namespace) -> int:
    try:
        rule = get_rule(args.rule_id)
    except KeyError:
        known = ", ".join(r.meta.id for r in all_rules())
        raise CliError(f"unknown rule {args.rule_id!r}; known rules: {known}") from None
    sys.stdout.write(render_rule_explanation(rule.meta))
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CliError, ConfigError, HistoryError, OutputPathError) as exc:
        print(f"codemind: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # e.g. piping into `head`
        return EXIT_OK
    except KeyboardInterrupt:
        print("codemind: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
