"""Packaging (CLI-D1, criterion 129) and the public-repo rules (BND-12,
criterion 216): PEP 621 metadata, the version equals the release tag, and the
repository holds code only (no secrets, no data)."""
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import pytest

import wolf_access_client

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(tomllib is None, reason="tomllib needs Python 3.11+")
def test_a129_pyproject_has_pep621_metadata():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = pyproject["project"]
    assert project["name"] == "wolf-access-client"
    assert project["requires-python"] == ">=3.10"
    assert project.get("dependencies", []) == []
    assert project["readme"] == "README.md"
    assert "version" not in project
    assert "version" in project.get("dynamic", [])
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "wolf_access_client.__version__"}


def test_a129_installed_version_is_the_package_version():
    from importlib.metadata import version
    assert version("wolf-access-client") == wolf_access_client.__version__


def test_a129_pyproject_version_is_the_package_version():
    """Single source of truth (#16): pyproject.toml reads __version__ dynamically."""
    text = (ROOT / "pyproject.toml").read_text()
    assert not any(line.strip().startswith("version = ") and "attr" not in line
                   for line in text.splitlines())
    assert 'dynamic = ["version"]' in text
    assert 'version = {attr = "wolf_access_client.__version__"}' in text


def test_a129_release_tag_matches_version():
    """On a tag build (GitHub sets GITHUB_REF_TYPE=tag), the tag is vX.Y.Z."""
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        pytest.skip("not a tag build")
    assert os.environ["GITHUB_REF_NAME"] == "v" + wolf_access_client.__version__


ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".yml"}
ALLOWED_NAMES = {".gitignore", "LICENSE", "py.typed"}
ALLOWED_PREFIXES = ("wolf_access_client/", "tests/", "scripts/", "docs/", ".github/workflows/")
ALLOWED_ROOT_FILES = {"pyproject.toml", "README.md", "LICENSE", ".gitignore"}
_SHA_REF = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, check=True, capture_output=True,
                         text=True).stdout
    return [line for line in out.splitlines() if line]


def disallowed_files(paths: Iterable[str]) -> list[str]:
    offenders: list[str] = []
    for f in paths:
        in_allowed_dir = f in ALLOWED_ROOT_FILES or any(f.startswith(p) for p in ALLOWED_PREFIXES)
        allowed_ext = Path(f).suffix in ALLOWED_SUFFIXES or Path(f).name in ALLOWED_NAMES
        if not in_allowed_dir or not allowed_ext:
            offenders.append(f)
    return offenders


def test_a216_repository_holds_code_only_no_data():
    """No database file, dump, export or seed: only code and its docs in allow-listed paths."""
    assert disallowed_files(tracked_files()) == []


def test_a216_disallowed_files_rejects_unlisted_paths_and_data_extensions():
    assert disallowed_files(["fixtures/accounts.yml", "data.py", "tests/seed.json",
                             "README.md", "docs/notes.md", "LICENSE"]) == [
        "fixtures/accounts.yml", "data.py", "tests/seed.json"]


def unpinned_uses_refs(workflow_text: str) -> list[str]:
    bad: list[str] = []
    for line in workflow_text.splitlines():
        m = re.match(r"^\s*-?\s*uses:\s*([^\s#]+)", line)
        if m and not _SHA_REF.fullmatch(m.group(1)):
            bad.append(m.group(1))
    return bad


def test_ci_actions_are_pinned_to_40_hex_commit_shas():
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        assert unpinned_uses_refs(path.read_text()) == [], path.name
    assert unpinned_uses_refs("- uses: actions/checkout@v4\n- uses: actions/setup-python@v5\n") == [
        "actions/checkout@v4", "actions/setup-python@v5"]


def test_ci_secret_scan_includes_unverified_findings():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "trufflehog" in ci and "--fail" in ci
    assert "--results=verified,unknown" not in ci
    assert "--results=verified,unverified,unknown" in ci or "--results" not in ci


def test_package_ships_a_py_typed_marker():
    assert (ROOT / "wolf_access_client" / "py.typed").exists()
    assert 'package-data = {wolf_access_client = ["py.typed"]}' in (
        ROOT / "pyproject.toml").read_text()


PUBLIC_API = {
    # WRNs (INT-B3)
    "Wrn", "WrnError", "parse_wrn", "is_canonical_wrn", "CANONICAL_WRN_SQL",
    "ACCESS_KINDS", "PRINCIPAL_KINDS",
    # client
    "WolfAccessClient", "ACCESS_AUDIENCE", "SEMANTICS", "MAX_EVALUATIONS",
    # values
    "Decision", "EvaluationItem", "SchemaType", "SchemaPermission", "SchemaRole",
    "Written", "Versioned", "Resource", "ReconcileChange", "Reconciled", "ExchangedToken",
    # canonical JSON
    "canonical_json", "diff_hash",
    # errors
    "WolfAccessError", "AccessUnavailable", "WolfAccessUnavailable",
    "WolfAccessResponseError", "WolfAccessHTTPError", "DecisionRefused",
    "TokenExchangeError", "ProblemError", "PROBLEM_TYPES", "BadRequestError",
    "UnauthorizedError", "ForbiddenError", "NotFoundError", "ConflictError",
    "UnavailableError",
    "__version__",
}


def test_public_api_is_exported():
    assert set(wolf_access_client.__all__) == PUBLIC_API
    for name in PUBLIC_API:
        assert hasattr(wolf_access_client, name), name


def test_the_wrn_lint_console_script_is_registered():
    """INT-B3: consumers run `wolf-access-wrn-lint` in CI."""
    from importlib.metadata import entry_points
    (script,) = [e for e in entry_points(group="console_scripts")
                 if e.name == "wolf-access-wrn-lint"]
    assert script.value == "wolf_access_client.wrn_lint:main"


def test_the_old_api_modules_are_gone():
    """0.7.0 removes the calls to routes wolf-access PR #329 removed, and the
    cut-over outbox, relay and gate built on them (README, Changes from 0.6.0)."""
    import importlib
    for name in ("outbox", "relay", "mode"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(f"wolf_access_client.{name}")
