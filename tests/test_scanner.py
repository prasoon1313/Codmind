import os

from codemind.analyzer import analyze
from codemind.config import Config
from codemind.scanner import scan_project
from helpers import ids, write_project


def test_empty_directory_does_not_crash(tmp_path):
    result = analyze(tmp_path)
    assert result.project.modules == []
    assert result.findings == []
    assert result.score.score == 100.0
    assert result.summary()["files_found"] == 0


def test_default_ignored_folders_are_skipped(tmp_path):
    write_project(tmp_path, {
        "app/main.py": "x = 1\n",
        ".git/hooks/pre.py": "x = 1\n",
        "venv/lib/site.py": "x = 1\n",
        ".venv/lib/site.py": "x = 1\n",
        "__pycache__/c.py": "x = 1\n",
        "node_modules/pkg/t.py": "x = 1\n",
        "proj.egg-info/m.py": "x = 1\n",
        "customenv/pyvenv.cfg": "home = /usr\n",
        "customenv/lib/m.py": "x = 1\n",
    })
    project = scan_project(tmp_path, Config())
    assert [m.path for m in project.modules] == ["app/main.py"]


def test_configurable_exclusions(tmp_path):
    write_project(tmp_path, {"keep.py": "x = 1\n", "gen/auto.py": "x = 1\n", "skip_me.py": "x = 1\n", "docs/conf.py": "x = 1\n"})
    config = Config(exclude=["gen/", "skip_*.py", "docs"])
    assert [m.path for m in scan_project(tmp_path, config).modules] == ["keep.py"]


def test_syntax_errors_are_reported_without_crashing(tmp_path):
    write_project(tmp_path, {"good.py": "def f():\n    return 1\n", "bad.py": "def broken(:\n    pass\n"})
    result = analyze(tmp_path)
    assert [m.path for m in result.project.modules] == ["good.py"]
    issue = result.project.issues[0]
    assert (issue.path, issue.kind, issue.line) == ("bad.py", "syntax_error", 1)
    assert "CM001" in ids(result)


def test_null_bytes_and_bad_encoding_are_reported(tmp_path):
    (tmp_path / "nul.py").write_bytes(b"x = 1\x00\n")
    (tmp_path / "latin.py").write_bytes(b"# -*- coding: utf-8 -*-\nx = '\xff\xfe'\n")
    (tmp_path / "ok.py").write_text("y = 2\n")
    result = analyze(tmp_path)
    kinds = {i.path: i.kind for i in result.project.issues}
    assert kinds["nul.py"] == "syntax_error"
    assert kinds["latin.py"] == "unreadable"
    assert [m.path for m in result.project.modules] == ["ok.py"]
    assert "CM002" in ids(result)


def test_declared_legacy_encoding_is_decoded(tmp_path):
    (tmp_path / "l1.py").write_bytes("# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n".encode("latin-1"))
    assert [m.path for m in scan_project(tmp_path, Config()).modules] == ["l1.py"]


def test_oversized_files_are_skipped(tmp_path):
    (tmp_path / "big.py").write_text("x = 1\n" * 1000)
    project = scan_project(tmp_path, Config(max_file_size_kb=1))
    assert project.modules == [] and project.issues[0].kind == "too_large"


def test_symlink_escaping_root_is_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("x = 1\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("y = 1\n")
    try:
        os.symlink(outside / "secret.py", root / "link.py")
        os.symlink(outside, root / "linkdir")
    except (OSError, NotImplementedError):
        return  # symlinks unavailable on this platform
    project = scan_project(root, Config())
    assert [m.path for m in project.modules] == ["ok.py"]
    assert any(i.kind == "skipped" for i in project.issues)


def test_nested_packages_and_deterministic_order(tmp_path):
    write_project(tmp_path, {"a/b/c/mod.py": "x = 1\n", "a/__init__.py": "", "a/b/__init__.py": "", "z.py": "", "a/b/c/__init__.py": ""})
    first = scan_project(tmp_path, Config())
    second = scan_project(tmp_path, Config())
    assert [m.path for m in first.modules] == [m.path for m in second.modules] == sorted(m.path for m in first.modules)
    names = {m.path: m.name for m in first.modules}
    assert names["a/b/c/mod.py"] == "a.b.c.mod" and names["a/b/__init__.py"] == "a.b"


def test_scanner_never_executes_project_code(tmp_path):
    marker = tmp_path / "executed.txt"
    write_project(tmp_path, {"boom.py": f"open({str(marker)!r}, 'w').write('x')\nraise SystemExit(5)\n"})
    analyze(tmp_path)
    assert not marker.exists()
