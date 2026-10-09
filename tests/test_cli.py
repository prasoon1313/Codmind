import contextlib
import csv
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import networkx as nx

from codemind.cli import main
from helpers import write_project

BAD = "import os\n\ndef f(x=[]):\n    if x == None:\n        return 1\n"
ROOT = Path(__file__).resolve().parents[1]


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main([str(a) for a in argv])
        except SystemExit as exc:  # argparse errors
            code = int(exc.code)
    return code, out.getvalue(), err.getvalue()


def project(tmp_path, code=BAD):
    proj = tmp_path / "proj"
    write_project(proj, {"pkg/__init__.py": "", "pkg/m.py": code})
    return proj, tmp_path / "h.db"


def test_scan_text_report(tmp_path):
    proj, db = project(tmp_path)
    code, out, _ = run("scan", proj, "--db", db)
    assert code == 0
    for needle in ("Score:", "Score breakdown", "CM101", "CM114", "Most complex functions", "Highest-risk files",
                   "Recommended priorities", "heuristic", "Saved as scan #1"):
        assert needle in out


def test_scan_json_is_valid_and_complete(tmp_path):
    proj, db = project(tmp_path)
    code, out, _ = run("scan", proj, "--format", "json", "--db", db)
    data = json.loads(out)
    assert code == 0 and data["scan_id"] == 1
    assert {"summary", "score", "findings", "files", "complexity", "dependencies", "priorities", "disclaimer"} <= set(data)
    f = data["findings"][0]
    assert {"rule_id", "severity", "path", "line", "message", "confidence", "suggestion", "heuristic"} <= set(f)
    assert data["score"]["factors"] and data["highest_risk_files"][0]["path"] == "pkg/m.py"


def test_scan_csv_kinds(tmp_path):
    proj, db = project(tmp_path)
    for kind, header in (("files", "path"), ("findings", "rule_id"), ("functions", "path")):
        code, out, _ = run("scan", proj, "--format", "csv", "--csv-kind", kind, "--no-save")
        rows = list(csv.reader(io.StringIO(out)))
        assert code == 0 and rows[0][0] == header and len(rows) > 1


def test_no_save_does_not_create_database(tmp_path):
    proj, db = project(tmp_path)
    assert run("scan", proj, "--no-save", "--db", db)[0] == 0
    assert not db.exists()


def test_fail_on_threshold_exit_codes(tmp_path):
    proj, db = project(tmp_path)
    assert run("scan", proj, "--no-save", "--fail-on", "high")[0] == 3
    assert run("scan", proj, "--no-save", "--fail-on", "critical")[0] == 0
    clean, _ = project(tmp_path / "c", "def f():\n    return 1\n")
    assert run("scan", clean, "--no-save", "--fail-on", "info")[0] == 0


def test_output_file_and_unsafe_paths(tmp_path):
    proj, db = project(tmp_path)
    target = tmp_path / "reports" / "out.json"
    code, out, err = run("scan", proj, "--format", "json", "--no-save", "-o", target)
    assert code == 0 and out == "" and json.loads(target.read_text())["summary"]
    for bad in (tmp_path / "x" / ".." / "evil.json", tmp_path / "evil.py", tmp_path / "noext", proj):
        code, _, err = run("scan", proj, "--no-save", "-o", bad)
        assert code == 1 and "error" in err
    assert not (tmp_path / "evil.py").exists()
    link = tmp_path / "link.json"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return
    assert run("scan", proj, "--no-save", "-o", link)[0] == 1


def test_report_requires_a_prior_scan_then_shows_trend(tmp_path):
    proj, db = project(tmp_path)
    code, _, err = run("report", proj, "--db", db)
    assert code == 1 and "codemind scan" in err
    run("scan", proj, "--db", db)
    write_project(proj, {"pkg/m.py": "def f():\n    return 1\n"})
    run("scan", proj, "--db", db)
    code, out, _ = run("report", proj, "--db", db)
    assert code == 0 and "Latest scan #2" in out and "Trend" in out and "#1" in out and "#2" in out
    data = json.loads(run("report", proj, "--db", db, "--format", "json")[1])
    assert [t["scan_id"] for t in data["trend"]] == [1, 2] and data["scan_id"] == 2
    rows = list(csv.reader(io.StringIO(run("report", proj, "--db", db, "--format", "csv")[1])))
    assert rows[0][0] == "scan_id" and len(rows) == 3


def test_compare_command(tmp_path):
    proj, db = project(tmp_path)
    run("scan", proj, "--db", db)
    write_project(proj, {"pkg/m.py": "def f(x=[]):\n    if x == None:\n        return 1\n    return 2\n\ndef g(y={}):\n    return y\n"})
    run("scan", proj, "--db", db)
    code, out, _ = run("compare", "--before", 1, "--after", 2, "--db", db)
    assert code == 0 and "New findings" in out and "Resolved findings" in out and "scan #1 -> #2" in out
    data = json.loads(run("compare", "--before", 1, "--after", 2, "--db", db, "--format", "json")[1])
    assert any(f["rule_id"] == "CM114" for f in data["resolved_findings"])
    assert any(f["symbol"] == "g" for f in data["new_findings"])
    code, _, err = run("compare", "--before", 1, "--after", 42, "--db", db)
    assert code == 1 and "42" in err


def test_graph_command(tmp_path):
    proj = tmp_path / "proj"
    write_project(proj, {"a.py": "import b\n", "b.py": "import a\ndef f(): pass\n"})
    data = json.loads(run("graph", proj)[1])
    assert len(data["cycles"]) == 1 and {"import_graph", "call_graph"} <= set(data)
    assert set(json.loads(run("graph", proj, "--kind", "imports")[1])) >= {"import_graph"}
    code, out, _ = run("graph", proj, "--format", "graphml")
    assert code == 0 and set(nx.parse_graphml(out).nodes) == {"a", "b"}
    target = tmp_path / "g.graphml"
    assert run("graph", proj, "--format", "graphml", "-o", target)[0] == 0 and target.exists()
    code, _, err = run("graph", proj, "--format", "graphml", "--kind", "both")
    assert code == 1 and "single graph" in err


def test_rules_and_explain(tmp_path):
    code, out, _ = run("rules")
    assert code == 0 and "CM101" in out and "CM304" in out
    listing = json.loads(run("rules", "--format", "json")[1])
    assert len(listing) >= 20 and listing[0]["id"] == "CM001"
    code, out, _ = run("explain", "cm101")
    assert code == 0 and "mutable" in out.lower() and "codemind: ignore[CM101]" in out
    code, _, err = run("explain", "NOPE1")
    assert code == 1 and "unknown rule" in err


def test_error_handling(tmp_path):
    assert run("scan", tmp_path / "missing")[0] == 1
    f = tmp_path / "file.py"
    f.write_text("x = 1\n")
    code, _, err = run("scan", f)
    assert code == 1 and "not a directory" in err
    proj, db = project(tmp_path)
    assert run("scan", proj, "--threshold", "max_complexity=abc")[0] == 1
    assert run("scan", proj, "--threshold", "bogus=1")[0] == 1
    assert run("scan", proj, "--disable", "CM777", "--no-save")[0] == 1
    assert run("scan", proj, "--min-severity", "bogus")[0] == 2
    assert run()[0] == 2


def test_threshold_exclude_disable_flags(tmp_path):
    proj, db = project(tmp_path, "def f(a):\n    if a:\n        return 1\n    return 2\n")
    out = run("scan", proj, "--no-save", "--format", "json", "--threshold", "max_complexity=1")[1]
    assert "CM202" in {f["rule_id"] for f in json.loads(out)["findings"]}
    out = run("scan", proj, "--no-save", "--format", "json", "--threshold", "max_complexity=1", "--disable", "cm202")[1]
    assert "CM202" not in {f["rule_id"] for f in json.loads(out)["findings"]}
    out = run("scan", proj, "--no-save", "--format", "json", "--exclude", "pkg")[1]
    assert json.loads(out)["summary"]["files_analyzed"] == 0


def test_config_file_is_loaded_and_validated(tmp_path):
    proj, db = project(tmp_path)
    (proj / "codemind.toml").write_text('exclude = ["pkg/m.py"]\n[rules]\ndisable = ["CM114"]\n[rules.severity]\nCM102 = "critical"\n')
    data = json.loads(run("scan", proj, "--no-save", "--format", "json")[1])
    assert data["summary"]["files_analyzed"] == 1  # only pkg/__init__.py
    (proj / "codemind.toml").write_text('[rules.severity]\nCM102 = "critical"\n[thresholds]\nmax_complexity = 10\n')
    data = json.loads(run("scan", proj, "--no-save", "--format", "json")[1])
    assert next(f for f in data["findings"] if f["rule_id"] == "CM102")["severity"] == "critical"
    (proj / "codemind.toml").write_text("[thresholds]\nmax_complexity = -3\n")
    code, _, err = run("scan", proj, "--no-save")
    assert code == 1 and "max_complexity" in err
    (proj / "codemind.toml").write_text("not = valid = toml")
    assert run("scan", proj, "--no-save")[0] == 1
    (proj / "codemind.toml").unlink()
    (proj / "pyproject.toml").write_text('[tool.codemind.thresholds]\nmax_parameters = 1\n')
    write_project(proj, {"pkg/m.py": "def f(a, b):\n    return a\n"})
    out = json.loads(run("scan", proj, "--no-save", "--format", "json")[1])
    assert "CM204" in {f["rule_id"] for f in out["findings"]}


def test_real_process_invocation_and_determinism(tmp_path):
    proj, db = project(tmp_path)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "CODEMIND_DB": str(db)}
    first = subprocess.run([sys.executable, "-m", "codemind", "scan", str(proj), "--format", "json", "--no-save"],
                           capture_output=True, text=True, env=env, cwd=tmp_path)
    second = subprocess.run([sys.executable, "-m", "codemind", "scan", str(proj), "--format", "json", "--no-save"],
                            capture_output=True, text=True, env=env, cwd=tmp_path)
    assert first.returncode == 0 and first.stderr == ""
    a, b = json.loads(first.stdout), json.loads(second.stdout)
    a.pop("generated_at"), b.pop("generated_at")
    assert a == b
    saved = subprocess.run([sys.executable, "-m", "codemind", "scan", str(proj)], capture_output=True, text=True, env=env, cwd=tmp_path)
    assert saved.returncode == 0 and db.exists()
    version = subprocess.run([sys.executable, "-m", "codemind", "--version"], capture_output=True, text=True, env=env)
    assert version.stdout.startswith("codemind ")
