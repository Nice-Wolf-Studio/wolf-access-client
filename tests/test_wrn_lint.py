"""The WRN literal check (INT-B3: "A linter rule refuses building WRN strings
outside that library"): `wrn_lint.find_wrn_literals` and the
`wolf-access-wrn-lint` console script."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from wolf_access_client.wrn_lint import ALLOW_COMMENT, WrnLiteral, find_wrn_literals, main

ROOT = Path(__file__).resolve().parent.parent
W = "wr" + "n:"   # this file builds its fixtures without a literal of its own


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("source", [
    f'X = "{W}tasks:task/t1"\n',
    f"X = '{W}tasks:task/' + task_id\n",
    f'X = f"{W}{{service}}:{{kind}}/{{ident}}"\n',
    f'X = "{W}%s:%s/%s" % (a, b, c)\n',
    f'X = "{W}{{}}:{{}}/{{}}".format(a, b, c)\n',
    f'X = b"{W}tasks:task/t1"\n',
    f'X = """{W}tasks:task/t1"""\n',
    f'X = rf"{W}{{s}}:t/{{i}}"\n',
    f'def f():\n    return {{"id": "{W}tasks:task/" + i}}\n',
])
def test_a_wrn_literal_is_found(tmp_path, source):
    path = write(tmp_path, "svc/mod.py", source)
    found = find_wrn_literals([tmp_path])
    assert [(f.path, f.line) for f in found] == [(path, source.count("\n", 0, source.index(W)) + 1)]
    assert isinstance(found[0], WrnLiteral)


@pytest.mark.parametrize("source", [
    'X = "no wrn here"\n',
    'X = "see the wrn standard: wrn is a format"\n',
    f'X = "a {W}tasks:task/t1 in the middle of prose"\n',
    f'# a comment about "{W}tasks:task/t1"\n',
    'X = "WRN:tasks:task/t1"\n',
    'X = "urn:tasks:task/t1"\n',
])
def test_text_that_builds_no_wrn_is_not_flagged(tmp_path, source):
    write(tmp_path, "mod.py", source)
    assert find_wrn_literals([tmp_path]) == []


def test_the_allow_comment_on_the_line_lets_one_literal_through(tmp_path):
    write(tmp_path, "mod.py",
          f'A = "{W}tasks:task/t1"  {ALLOW_COMMENT}: a fixture\n'
          f'B = "{W}tasks:task/t2"\n')
    found = find_wrn_literals([tmp_path])
    assert [f.line for f in found] == [2]


def test_the_allow_comment_covers_a_multi_line_literal(tmp_path):
    write(tmp_path, "mod.py", f'A = (\n    "{W}tasks:task/t1"\n)  {ALLOW_COMMENT}\n'
                              f'B = """\n{W}x:y/z\n"""  {ALLOW_COMMENT}\n')
    assert find_wrn_literals([tmp_path]) == []


def test_exclude_skips_matching_paths(tmp_path):
    write(tmp_path, "tests/test_x.py", f'A = "{W}tasks:task/t1"\n')
    kept = write(tmp_path, "svc/mod.py", f'A = "{W}tasks:task/t1"\n')
    found = find_wrn_literals([tmp_path], exclude=["tests/*"])
    assert [f.path for f in found] == [kept]


def test_only_python_files_are_read_and_caches_are_skipped(tmp_path):
    write(tmp_path, "notes.md", f'"{W}tasks:task/t1"\n')
    write(tmp_path, ".venv/lib/x.py", f'A = "{W}tasks:task/t1"\n')
    write(tmp_path, "__pycache__/x.py", f'A = "{W}tasks:task/t1"\n')
    assert find_wrn_literals([tmp_path]) == []


def test_a_single_file_can_be_checked(tmp_path):
    path = write(tmp_path, "one.py", f'A = "{W}tasks:task/t1"\n')
    assert [f.path for f in find_wrn_literals([path])] == [path]


def test_a_file_that_does_not_parse_is_reported(tmp_path):
    path = write(tmp_path, "broken.py", "def (:\n")
    found = find_wrn_literals([tmp_path])
    assert [(f.path, f.problem) for f in found] == [(path, "not valid Python")]


def test_main_exit_codes_and_output(tmp_path, capsys):
    clean = tmp_path / "clean"
    write(clean, "mod.py", "X = 1\n")
    assert main([str(clean)]) == 0
    dirty = tmp_path / "dirty"
    write(dirty, "mod.py", f'X = "{W}tasks:task/t1"\n')
    assert main([str(dirty)]) == 1
    out = capsys.readouterr().out
    assert "mod.py:1:" in out and "parse_wrn" in out
    assert main([str(dirty), "--exclude", "mod.py"]) == 0
    assert main([str(tmp_path / "missing")]) == 2


def test_the_console_script_runs(tmp_path):
    write(tmp_path, "mod.py", f'X = "{W}tasks:task/t1"\n')
    run = subprocess.run([sys.executable, "-m", "wolf_access_client.wrn_lint", str(tmp_path)],
                         capture_output=True, text=True)
    assert run.returncode == 1 and "mod.py:1:" in run.stdout


def test_this_library_builds_wrns_only_in_its_wrn_module():
    """Dogfood: outside `wrn.py` (whose two formatters carry the allow
    comment) and the conformance table, the package has no WRN literal."""
    found = find_wrn_literals([ROOT / "wolf_access_client"],
                              exclude=["*/wrn_conformance.py"])
    assert found == []
