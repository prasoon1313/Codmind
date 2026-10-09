import math

from codemind.analyzer import analyze
from codemind.config import Config, config_from_mapping
from codemind.scoring import grade_for
from helpers import analyze_snippet, write_project
from test_rules import CLEAN

BAD = '''
import os, subprocess
def f(a, b, c, d, e, f2, g, bucket=[]):
    if a == None:
        try:
            eval(b)
        except:
            pass
    return subprocess.run(f"ls {c}", shell=True)
''' + "\n".join(f"def g{i}(x):\n    " + "\n    ".join(f"if x == {k}:\n        x += {k}" for k in range(14)) + "\n    return x" for i in range(3))


def test_clean_code_outscores_bad_code(tmp_path):
    clean = analyze_snippet(tmp_path / "c", CLEAN)
    bad = analyze_snippet(tmp_path / "b", BAD)
    assert clean.score.score > 95 > bad.score.score
    assert bad.score.score < 70


def test_penalties_explain_the_score_exactly(tmp_path):
    result = analyze_snippet(tmp_path, BAD)
    s = result.score
    assert math.isclose(100 - sum(f.penalty for f in s.factors), s.score, abs_tol=0.06)
    assert [f.name for f in s.factors] == ["findings", "complexity", "maintainability", "structure"]
    assert math.isclose(sum(f.weight for f in s.factors), 100.0)
    assert all(0 <= f.badness <= 1 and f.detail for f in s.factors)
    assert "heuristic" in s.caveat


def test_weights_are_configurable(tmp_path):
    write_project(tmp_path, {"m.py": BAD})
    default = analyze(tmp_path).score
    config = config_from_mapping({"weights": {"findings": 100, "complexity": 0, "maintainability": 0, "structure": 0}})
    custom = analyze(tmp_path, config).score
    assert [f.weight for f in custom.factors] == [100.0, 0.0, 0.0, 0.0]
    assert custom.score != default.score


def test_more_findings_never_improve_the_score(tmp_path):
    base = "def f(x):\n    return x\n"
    worse = base + "def g(y=[]):\n    if y == None:\n        pass\n"
    assert analyze_snippet(tmp_path / "a", worse).score.score < analyze_snippet(tmp_path / "b", base).score.score


def test_cycles_penalise_structure(tmp_path):
    write_project(tmp_path, {"a.py": "import b\n", "b.py": "import a\n"})
    factor = {f.name: f for f in analyze(tmp_path).score.factors}["structure"]
    assert factor.badness > 0 and "1 import cycle" in factor.detail


def test_grades_and_bounds():
    assert [grade_for(x) for x in (100, 90, 89.9, 80, 70, 60, 59.9, 0)] == ["A", "A", "B", "B", "C", "D", "F", "F"]


def test_empty_project_is_vacuous(tmp_path):
    s = analyze(tmp_path).score
    assert s.score == 100.0 and "vacuous" in s.caveat


def test_score_is_deterministic(tmp_path):
    write_project(tmp_path, {"m.py": BAD})
    assert analyze(tmp_path).score.to_dict() == analyze(tmp_path).score.to_dict()


def test_file_risk_ranking(tmp_path):
    write_project(tmp_path, {"clean.py": CLEAN, "risky.py": BAD, "broken.py": "def (:\n"})
    result = analyze(tmp_path)
    ranked = [s.path for s in result.top_files(5)]
    assert ranked[0] == "risky.py" and "clean.py" not in ranked and "broken.py" in ranked
    assert any("risky.py" in p for p in result.priorities())
