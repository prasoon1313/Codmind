from codemind.analyzer import analyze
from codemind.config import Config
from codemind.models import Confidence, Severity
from codemind.rules import all_rules, get_rule
from helpers import analyze_snippet, ids, of, write_project

CLEAN = '''
    """Clean module."""
    import json
    from pathlib import Path


    def load(path: Path) -> dict:
        """Load JSON."""
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)


    def total(values, start=None):
        start = 0 if start is None else start
        for value in values:
            start += value
        return start


    class Box:
        def __init__(self, items=None):
            self.items = list(items or [])

        @property
        def size(self):
            return len(self.items)

        @size.setter
        def size(self, value):
            del self.items[value:]
'''


def test_clean_code_has_no_findings(tmp_path):
    result = analyze_snippet(tmp_path, CLEAN)
    assert result.findings == [], [f.message for f in result.findings]
    assert result.score.score >= 95


def test_every_finding_has_required_fields(tmp_path):
    result = analyze_snippet(tmp_path, "def f(x=[]):\n    if x == None:\n        pass\n")
    assert result.findings
    for f in result.findings:
        assert f.rule_id and f.path == "mod.py" and f.line >= 1 and f.message and f.suggestion
        assert isinstance(f.severity, Severity) and isinstance(f.confidence, Confidence)


def test_rules_are_documented_and_unique():
    rules = all_rules()
    assert len({r.meta.id for r in rules}) == len(rules) >= 20
    for r in rules:
        assert r.meta.summary and r.meta.rationale and r.meta.suggestion
    assert get_rule("cm101").meta.id == "CM101"


def test_mutable_defaults(tmp_path):
    code = "def a(x=[]): pass\ndef b(*, y={}): pass\ndef c(z=dict()): pass\ndef ok(n=None, t=(), s='x'): pass\n"
    found = of(analyze_snippet(tmp_path, code), "CM101")
    assert [f.line for f in found] == [1, 2, 3]
    assert all(f.confidence is Confidence.DEFINITE for f in found)


def test_none_and_bool_comparisons(tmp_path):
    code = "def f(x):\n    a = x == None\n    b = x != None\n    c = x == True\n    d = x is None\n    e = x == 0\n    return a, b, c, d, e\n"
    r = analyze_snippet(tmp_path, code)
    assert [f.line for f in of(r, "CM102")] == [2, 3]
    assert [f.line for f in of(r, "CM103")] == [4]


def test_exception_handling_rules(tmp_path):
    code = '''
        import logging
        def f():
            try: pass
            except: pass
            try: pass
            except Exception: pass
            try: pass
            except ImportError: pass
            try: pass
            except Exception:
                return None
            try: pass
            except Exception as exc:
                logging.error("x %s", exc)
            try: pass
            except ValueError:
                raise
    '''
    r = analyze_snippet(tmp_path, code)
    assert len(of(r, "CM104")) == 1
    empties = of(r, "CM105")
    assert len(empties) == 3
    assert sorted(f.severity.value for f in empties) == ["low", "medium", "medium"]
    swallowed = of(r, "CM106")
    assert len(swallowed) == 1 and swallowed[0].confidence is Confidence.MEDIUM


def test_unreachable_code(tmp_path):
    code = '''
        import sys
        def a():
            return 1
            print("dead")
        def b(x):
            for i in x:
                continue
                print("dead")
        def c(x):
            if x:
                return 1
            else:
                raise ValueError
            print("dead")
        def d():
            sys.exit(1)
            print("dead")
        def ok(x):
            if x:
                return 1
            print("alive")
    '''
    found = of(analyze_snippet(tmp_path, code), "CM107")
    assert [f.line for f in found] == [5, 9, 15, 18]
    assert found[3].confidence is Confidence.MEDIUM and found[0].confidence is Confidence.HIGH


def test_unused_locals(tmp_path):
    code = '''
        def f():
            unused = 1
            _ignored = 2
            used = 3
            a, b = 1, 2
            for i in range(3):
                pass
            def inner():
                return used
            captured = 5
            return lambda: captured
        def g():
            tmp = 1
            return locals()
    '''
    found = of(analyze_snippet(tmp_path, code), "CM108")
    assert [f.detail for f in found] == ["unused"]


def test_duplicate_definitions(tmp_path):
    code = '''
        def run(): pass
        def run(): pass
        class K:
            @property
            def v(self): return 1
            @v.setter
            def v(self, x): pass
            def m(self): pass
            def m(self): pass
        if True:
            def cond(): pass
        else:
            def cond(): pass
    '''
    found = of(analyze_snippet(tmp_path, code), "CM109")
    assert sorted(f.detail for f in found) == ["m", "run"]


def test_eval_exec_and_shadowing(tmp_path):
    code = "def f(s):\n    eval(s)\n    exec('x = 1')\n    eval('1+1')\n"
    found = of(analyze_snippet(tmp_path, code), "CM110")
    assert [(f.line, f.severity.value) for f in found] == [(2, "high"), (3, "medium"), (4, "medium")]
    shadow = analyze_snippet(tmp_path / "s", "def eval(x): return x\ndef g(s): return eval(s)\n")
    assert of(shadow, "CM110") == []
    literal = analyze_snippet(tmp_path / "l", "import ast\nx = ast.literal_eval('1')\n")
    assert of(literal, "CM110") == []


def test_subprocess_rules(tmp_path):
    code = '''
        import os, subprocess
        import subprocess as sp
        from subprocess import run as r
        def f(name):
            subprocess.run(["ls", name])
            subprocess.run("ls " + name, shell=True)
            sp.call("ls", shell=True)
            r(f"echo {name}", shell=True)
            os.system("rm " + name)
            subprocess.run(["ls"], shell=False)
    '''
    found = of(analyze_snippet(tmp_path, code), "CM111")
    assert sorted((f.line, f.severity.value) for f in found) == [(7, "high"), (8, "medium"), (9, "high"), (10, "high")]


def test_deserialization(tmp_path):
    code = "import pickle, yaml\ndef f(b, s):\n    pickle.loads(b)\n    yaml.load(s)\n    yaml.safe_load(s)\n    yaml.load(s, Loader=yaml.SafeLoader)\n"
    assert [f.line for f in of(analyze_snippet(tmp_path, code), "CM113")] == [3, 4]


def test_resource_cleanup(tmp_path):
    code = '''
        import json
        from contextlib import closing
        def leak(p):
            f = open(p)
            return f.read()
        def inline(p):
            return open(p).read()
        def arg(p):
            return json.load(open(p))
        def good_with(p):
            with open(p) as f:
                return f.read()
        def good_close(p):
            f = open(p)
            try:
                return f.read()
            finally:
                f.close()
        def good_return(p):
            f = open(p)
            return f
        def good_closing(p):
            with closing(open(p)) as f:
                return f.read()
    '''
    found = of(analyze_snippet(tmp_path, code), "CM112")
    assert [(f.line, f.severity.value) for f in found] == [(5, "medium"), (8, "low"), (10, "low")]


def test_unused_imports(tmp_path):
    code = '''
        from __future__ import annotations
        import os
        import sys
        import typing as t
        from collections import OrderedDict, deque
        import re
        import json
        __all__ = ["json"]
        def f(x: "OrderedDict") -> t.Any:
            return sys.argv
    '''
    found = of(analyze_snippet(tmp_path, code), "CM114")
    assert sorted(f.detail for f in found) == ["deque", "os", "re"]
    pkg = analyze_snippet(tmp_path / "p", "import os\n", name="pkg/__init__.py")
    assert of(pkg, "CM114") == []


def test_wildcard_import(tmp_path):
    assert [f.line for f in of(analyze_snippet(tmp_path, "from os.path import *\nx = join\n"), "CM115")] == [1]


def test_structural_thresholds_and_severity_scaling(tmp_path):
    body = "\n".join(f"    x{i} = {i}" for i in range(60))
    branches = "\n".join(f"    if a == {i}:\n        return {i}" for i in range(12))
    code = f"def long(a):\n{body}\n    return 1\ndef cx(a):\n{branches}\n    return 0\n"
    code += "def deep(a):\n    if a:\n        for i in a:\n            while i:\n                if i:\n                    with a:\n                        pass\n"
    code += "def many(a, b, c, d, e, f, g): pass\n"
    code += "class Big:\n" + "\n".join(f"    def m{i}(self): pass" for i in range(21)) + "\n"
    r = analyze_snippet(tmp_path, code)
    assert [f.symbol for f in of(r, "CM201")] == ["long"]
    assert [f.symbol for f in of(r, "CM202")] == ["cx"]
    assert [f.symbol for f in of(r, "CM203")] == ["deep"]
    assert [f.symbol for f in of(r, "CM204")] == ["many"]
    assert [f.symbol for f in of(r, "CM205")] == ["Big"]


def test_custom_thresholds_and_disabled_rules(tmp_path):
    code = "def f(a, b):\n    if a:\n        return 1\n    return 2\n"
    assert of(analyze_snippet(tmp_path / "a", code), "CM202") == []
    config = Config()
    config.thresholds.max_complexity = 1
    config.thresholds.max_parameters = 1
    r = analyze_snippet(tmp_path / "b", code, config=config)
    assert {"CM202", "CM204"} <= set(ids(r))
    config.disabled_rules = {"CM202"}
    assert "CM202" not in ids(analyze(tmp_path / "b", config))


def test_severity_override(tmp_path):
    config = Config(severity_overrides={"CM102": Severity.CRITICAL})
    r = analyze_snippet(tmp_path, "def f(x):\n    return x == None\n", config=config)
    assert of(r, "CM102")[0].severity is Severity.CRITICAL


def test_inline_suppression(tmp_path):
    code = "def f(x):\n    a = x == None  # codemind: ignore[CM102]\n    b = x == None  # codemind: ignore\n    c = x == None  # codemind: ignore[CM999]\n    return a, b, c\n"
    assert [f.line for f in of(analyze_snippet(tmp_path, code), "CM102")] == [4]


DUP_A = '''
    def process_orders(orders, tax):
        total = 0
        for order in orders:
            price = order["price"] * order["qty"]
            if order.get("discount"):
                price = price - order["discount"]
            total = total + price * (1 + tax)
        report = {"total": total, "count": len(orders)}
        return report
'''
DUP_B = '''
    def handle_invoices(invoices, vat):
        amount = 0
        for invoice in invoices:
            cost = invoice["cost"] * invoice["units"]
            if invoice.get("rebate"):
                cost = cost - invoice["rebate"]
            amount = amount + cost * (1 + vat)
        summary = {"total": amount, "count": len(invoices)}
        return summary
'''


def test_duplicate_code_across_files_with_renamed_identifiers(tmp_path):
    write_project(tmp_path, {"a.py": DUP_A, "b.py": DUP_B})
    found = of(analyze(tmp_path), "CM304")
    assert sorted(f.path for f in found) == ["a.py", "b.py"]
    assert all(f.confidence is Confidence.MEDIUM for f in found)
    assert "b.py" in next(f for f in found if f.path == "a.py").message


def test_duplicate_blocks_inside_one_file(tmp_path):
    body = '''
        def one(data):
            out = []
            for row in data:
                if row.get("ok"):
                    out.append(row["value"] * 2)
                else:
                    out.append(0)
            return out
        def two(items):
            res = []
            for it in items:
                if it.get("ok"):
                    res.append(it["value"] * 2)
                else:
                    res.append(0)
            return res
    '''
    assert len(of(analyze_snippet(tmp_path, body), "CM304")) == 2


def test_different_code_is_not_flagged_as_duplicate(tmp_path):
    write_project(tmp_path, {"a.py": DUP_A, "c.py": '''
        def different(path):
            import os
            names = sorted(os.listdir(path))
            while names and names[-1].startswith("."):
                names.pop()
            first = names[0] if names else None
            return {"first": first, "all": names}
    '''})
    assert of(analyze(tmp_path), "CM304") == []


def test_trivial_repetition_is_ignored(tmp_path):
    code = "def f(a):\n    a.x = 1\n    a.y = 2\n    a.z = 3\n    a.w = 4\ndef g(b):\n    b.x = 1\n    b.y = 2\n    b.z = 3\n    b.w = 4\n"
    assert of(analyze_snippet(tmp_path, code), "CM304") == []


def test_possibly_unused_private_function(tmp_path):
    code = "def _dead(): pass\ndef _used(): pass\ndef _viaattr(): pass\ndef public(): _used()\nobj = type('o', (), {})\nobj.x = _viaattr\n"
    assert [f.symbol for f in of(analyze_snippet(tmp_path, code), "CM303")] == ["_dead"]


def test_rule_crash_is_isolated(tmp_path):
    from codemind.rules.base import Rule, RuleMeta, _REGISTRY, register

    class Boom(Rule):
        meta = RuleMeta("CM999", "boom", "test", Severity.LOW, Confidence.LOW, "s", "r", "x")

        def check_module(self, module, ctx):
            raise RuntimeError("kaput")

    register(Boom)
    try:
        r = analyze_snippet(tmp_path, "x = 1\n")
        assert any("CM999" in e and "kaput" in e for e in r.rule_errors)
    finally:
        _REGISTRY.pop("CM999", None)
