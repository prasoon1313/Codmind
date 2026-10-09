Hello I'm Prasoon! This is my python project!!
# CodeMind: Codebase Intelligence Engine

Offline, Python-only static analysis for Python projects. CodeMind parses source with the built-in
`ast` / `tokenize` modules, builds import and call graphs with NetworkX, runs a modular rule engine,
scores quality transparently, stores every scan in SQLite and compares scans over time.
It never executes the analysed code, needs no network, and uses no AI services.

## Install 

```bash
python -m venv .venv && source .venv/bin/activate     # Python 3.11+
pip install .            # installs the `codemind` command (dependency: networkx)
pip install -e ".[dev]"  # for development + pytest
```

## Commands

```bash
codemind scan ./my_project                       # text report (also saved to history)
codemind scan ./my_project --format json -o report.json
codemind scan ./my_project --format csv --csv-kind findings -o findings.csv   # files | findings | functions
codemind scan ./my_project --fail-on high        # exit status 3 for CI gating
codemind scan ./my_project --threshold max_complexity=15 --disable CM303 --exclude "migrations/"
codemind report ./my_project                     # latest stored scan + historical trend (text|json|csv)
codemind compare --before 1 --after 2            # new / resolved / persistent findings, complexity diffs
codemind graph ./my_project --format graphml -o deps.graphml        # --kind imports|calls
codemind graph ./my_project --format json --kind both
codemind rules                                   # list all rules (--format json)
codemind explain CM101
```

History lives in `$CODEMIND_DB` or `~/.codemind/history.db` (override with `--db` / `db_path`).
Exit codes: `0` ok, `1` error, `2` usage error, `3` `--fail-on` threshold reached.
Suppress one finding with `# codemind: ignore[CM102]` (or `# codemind: ignore`) on its line.
Configuration: `codemind.toml` or `[tool.codemind]` in `pyproject.toml` (see `codemind.example.toml`).

## Architecture

```
codemind/
  models.py            dataclasses: Finding, FunctionInfo, ModuleInfo, ProjectInfo ...
  config.py            validated TOML config, thresholds, score weights
  scanner.py           deterministic discovery; ignored dirs, venv detection, symlink safety, size limit
  parser.py            ast -> modules, classes, functions, imports (top/lazy/TYPE_CHECKING), globals
  astutils.py          scope-aware walkers, structural normalisation for clone detection
  complexity.py        cyclomatic complexity, nesting, Halstead volume, maintainability index
  dependency_graph.py  NetworkX import graph + call graph, cycles (SCC), centrality, JSON/GraphML export
  rules/               registry + engine; bugs.py, structural.py, project.py, duplicates.py
  scoring.py           explainable 0-100 score and per-file risk
  history.py           SQLite store, scan comparison, trends
  reporting.py         text / JSON / CSV reports, safe output paths
  cli.py               argparse CLI
tests/                 87 tests (scanner, parser, rules, graph, scoring, history, CLI)
```

Pipeline: `scan_project -> build_dependency_analysis -> run_rules -> compute_score -> report/save`.
A crashing rule is isolated and reported, never fatal. Output is deterministic (sorted everywhere);
only `generated_at` varies.

## Rules

| ID | Name | Default severity / confidence |
|----|------|-------------------------------|
| CM001/002 | file-syntax-error, unreadable-file | high / low, definite |
| CM101 | mutable-default-argument | high, definite |
| CM102/103 | none-equality-comparison, boolean-literal-equality | low, definite |
| CM104/105 | bare-except, empty-exception-handler | medium, definite |
| CM106 | broad-exception-swallowed | low, medium (heuristic) |
| CM107 | potentially-unreachable-code | medium, high / medium |
| CM108 | unused-local-variable | low, high |
| CM109 | duplicate-definition | medium, high |
| CM110/111/113 | eval-exec, unsafe-subprocess, unsafe-deserialization | high/high/medium, heuristic |
| CM112 | missing-resource-cleanup | medium, medium |
| CM114/115 | unused-import, wildcard-import | low |
| CM201-205 | long-function, complexity, nesting, parameters, large-class | measured facts (definite) |
| CM301/302 | circular-import, high-module-coupling | high definite / medium heuristic |
| CM303 | possibly-unused-private-function | low, low |
| CM304 | duplicate-code-block (normalised AST clones) | low-medium, medium |

*Definite* = syntactic or measured fact. Everything else is a heuristic indicator and is labelled as such;
no finding claims to prove a runtime bug. `codemind explain RULE` documents rationale, examples and limits.

## Methods

* **Cyclomatic complexity**: `1 +` `if/elif`, `for`, `while`, `except`, ternaries, extra `and/or` operands,
  comprehension clauses and filters, `match` cases (not `case _`); nested functions counted separately.
* **Maintainability index**: `max(0, (171 - 5.2 ln V - 0.23 CC - 16.2 ln LOC) * 100/171)`, Halstead volume from tokens.
* **Score** = `100 - sum(penalties)` over four weighted factors (findings density, complexity, maintainability,
  structure); every factor, weight and number is printed with the report. See `codemind/scoring.py`.
  The score is a heuristic for tracking trends, not a measure of correctness.
* **History**: findings are matched by a line-independent fingerprint (rule, file, symbol, detail) as a multiset,
  so moving code is "persistent" and fixing one of two identical findings resolves exactly one.

## Limitations of static analysis

No code is executed: dynamic features (`getattr`, monkey-patching, plugins, `exec`) are invisible; call
resolution ignores inheritance and unknown receivers; unused-code and duplicate-code results are indicators;
shell/deserialisation rules cannot know whether data is trusted; syntax newer than the running Python is reported
as a syntax error; clone detection abstracts identifiers/literals so similar-shaped but unrelated code can match.

## Tests

```bash
pip install -e ".[dev]" && pytest -q
```

## Sample analysis (real output of `examples/sample_project`)

```
Score: 60.9/100 (grade D)  [heuristic]
Findings: 12 (critical 0, high 4, medium 4, low 4, info 0); 7 heuristic
  [HIGH] CM301 shop/billing.py:2  Circular import: shop.billing -> shop.orders -> shop.billing.
  [HIGH] CM110 shop/billing.py:18  Call to eval() with a dynamic argument; verify the input is trusted.
  [HIGH] CM101 shop/orders.py:9  Parameter 'cache' of 'process_orders' has a mutable default ({}).
  [HIGH] CM111 shop/orders.py:28  subprocess.run() runs through a shell; the command is built dynamically.
  [MEDIUM] CM112 shop/orders.py:21  File opened into 'f' without a 'with' block ...
  [MEDIUM] CM104 / CM105 shop/orders.py:29  bare except that silently ignores the error
  [MEDIUM] CM107 shop/orders.py:34  Statement appears unreachable (line 33 always leaves the block).
  [LOW] CM304 shop/billing.py:6 <-> shop/orders.py:10  Duplicate block of 4 statements
  [LOW] CM114 'os' unused;  CM102 comparison to None with '=='

After fixing four issues, `codemind compare --before 1 --after 2`:
  Score 60.9 -> 61.3 (+0.4) | Findings 12 -> 8 (-4) | New: 0 | Resolved: 4 | Persistent: 8
```

## Resume description

**CodeMind: Codebase Intelligence Engine (Python).** Built an offline static-analysis toolkit that parses Python
projects with `ast`/`tokenize`, constructs NetworkX import and call graphs, detects import cycles via strongly
connected components, and runs a 26-rule engine (bug patterns, security smells, normalised-AST clone detection).
Designed an explainable 0-100 quality score, SQLite scan history with fingerprint-based regression tracking, and a
CI-friendly CLI with JSON/CSV/GraphML export. Hardened against path traversal and malformed input; validated on the
CPython standard library (570+ files, 226k LOC in ~30 s) with 87 automated tests.

## Interview questions

1. Why does the cyclomatic-complexity walker not descend into nested functions, and how does that affect class and module totals?
2. Explain how history comparison matches findings across scans. Why fingerprint without line numbers, and why a multiset?
3. How are circular imports found, and why are function-level and `TYPE_CHECKING` imports excluded from cycles?
4. How does the clone detector find maximal duplicate runs from fixed-size statement windows, and how are overlapping/nested reports suppressed?
5. Which design choices keep the analyser safe on untrusted repositories (no execution, symlinks, output paths, rule crashes, huge files)?

## Future enhancements

Inheritance-aware call graph, data-flow based unused/uninitialised variable checks, incremental scans keyed by file hash,
SARIF export, plugin entry points for third-party rules, baseline files for gradual adoption.
