import sqlite3

from codemind.analyzer import analyze
from codemind.history import HistoryError, HistoryStore
from helpers import write_project

V1 = '''
def stable(a):
    return a

def grows(x):
    if x:
        return 1
    return 0

def risky(v=[]):
    return v == None
'''
V2 = '''
def stable(a):
    return a

def grows(x):
    if x and x > 1:
        for i in range(x):
            if i % 2:
                return i
    return 0

def risky(v=None):
    return v == None

def fresh(q=[]):
    return q
'''


def _store(tmp_path):
    return HistoryStore(tmp_path / "db" / "history.db")  # parent dir does not exist yet


def _scan(store, root, code):
    write_project(root, {"m.py": code})
    result = analyze(root)
    return store.save(result), result


def test_save_creates_database_and_persists_scan(tmp_path):
    proj = tmp_path / "proj"
    with _store(tmp_path) as store:
        scan_id, result = _scan(store, proj, V1)
        assert scan_id == 1 and result.scan_id == 1
        row = store.scan_row(1)
        assert row["finding_count"] == len(result.findings) and row["score"] == result.score.score
        assert sorted(f.fingerprint for f in store.findings_for(1)) == sorted(f.fingerprint for f in result.findings)
    con = sqlite3.connect(tmp_path / "db" / "history.db")
    assert {r[0] for r in con.execute("select name from sqlite_master where type='table'")} >= {"projects", "scans", "findings", "function_metrics"}


def test_compare_new_resolved_and_persistent(tmp_path):
    proj = tmp_path / "proj"
    with _store(tmp_path) as store:
        a, _ = _scan(store, proj, V1)
        b, _ = _scan(store, proj, V2)
        cmp = store.compare(a, b)
    new = {(f["rule_id"], f["symbol"]) for f in cmp["new_findings"]}
    resolved = {(f["rule_id"], f["symbol"]) for f in cmp["resolved_findings"]}
    persistent = {(f["rule_id"], f["symbol"]) for f in cmp["persistent_findings"]}
    assert ("CM101", "fresh") in new and ("CM101", "risky") in resolved
    assert ("CM102", "risky") in persistent
    assert not new & persistent and not resolved & persistent


def test_compare_tracks_complexity_and_score_changes(tmp_path):
    proj = tmp_path / "proj"
    with _store(tmp_path) as store:
        a, _ = _scan(store, proj, V1)
        b, _ = _scan(store, proj, V2)
        cmp = store.compare(a, b)
    reg = cmp["complexity_regressions"]
    assert reg[0]["function"] == "grows" and (reg[0]["before"], reg[0]["after"]) == (2, 5) and reg[0]["delta"] == 3
    assert [f["function"] for f in cmp["added_functions"]] == ["fresh"]
    assert cmp["delta"]["max_complexity"] == 3 and cmp["delta"]["loc"] > 0
    assert cmp["after"]["id"] == b and cmp["before"]["id"] == a


def test_same_scan_has_only_persistent_findings(tmp_path):
    with _store(tmp_path) as store:
        a, _ = _scan(store, tmp_path / "p", V1)
        cmp = store.compare(a, a)
    assert cmp["new_findings"] == [] and cmp["resolved_findings"] == [] and cmp["persistent_findings"]
    assert cmp["delta"]["score"] == 0


def test_duplicate_fingerprints_are_counted_as_multiset(tmp_path):
    two = "def f(a, b):\n    x = a == None\n    y = b == None\n    return x, y\n"
    one = "def f(a, b):\n    x = a == None\n    return x\n"
    with _store(tmp_path) as store:
        a, _ = _scan(store, tmp_path / "p", two)
        b, _ = _scan(store, tmp_path / "p", one)
        cmp = store.compare(a, b)
    assert len(cmp["resolved_findings"]) == 1 and len(cmp["persistent_findings"]) == 1 and cmp["new_findings"] == []


def test_trend_reports_deltas(tmp_path):
    proj = tmp_path / "proj"
    with _store(tmp_path) as store:
        _scan(store, proj, V1)
        _scan(store, proj, V2)
        _scan(store, proj, "def f():\n    return 1\n")
        trend = store.trend(proj)
        assert store.latest_scan_id(proj) == 3
    assert [t["scan_id"] for t in trend] == [1, 2, 3]
    assert trend[0]["score_delta"] is None
    assert trend[2]["score_delta"] == round(trend[2]["score"] - trend[1]["score"], 2) and trend[2]["score_delta"] > 0


def test_errors_for_missing_scans_and_cross_project_compare(tmp_path):
    with _store(tmp_path) as store:
        a, _ = _scan(store, tmp_path / "p1", V1)
        b, _ = _scan(store, tmp_path / "p2", V1)
        for call in (lambda: store.compare(a, 99), lambda: store.compare(a, b)):
            try:
                call()
            except HistoryError as exc:
                assert "99" in str(exc) or "different projects" in str(exc)
            else:
                raise AssertionError("expected HistoryError")
        assert store.latest_scan_id(tmp_path / "never_scanned") is None


def test_stored_report_roundtrip_and_parameterised_paths(tmp_path):
    nasty = tmp_path / "it's \"quoted\"; DROP TABLE scans;--"
    with _store(tmp_path) as store:
        sid, result = _scan(store, nasty, V1)
        report = store.stored_report(sid)
        assert report["root"] == str(result.root) and len(report["findings"]) == len(result.findings)
        assert report["summary"]["score"] == result.score.score
        assert store.scan_row(sid)["id"] == sid  # table survived


def test_unusable_database_path_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    try:
        HistoryStore(blocker / "sub" / "h.db")
    except HistoryError:
        return
    raise AssertionError("expected HistoryError")
