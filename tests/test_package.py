"""Packaging (CLI-D1, criterion 129) and the public-repo rules (BND-12,
criterion 216): PEP 621 metadata, the version equals the release tag, and the
repository holds code only (no secrets, no data)."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

import wolf_access_client

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(tomllib is None, reason="tomllib needs Python 3.11+")
def test_a129_pyproject_has_pep621_metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["name"] == "wolf-access-client"
    assert project["requires-python"] == ">=3.10"
    assert project.get("dependencies", []) == []
    assert project["readme"] == "README.md"


def test_a129_installed_version_is_the_package_version():
    from importlib.metadata import version
    assert version("wolf-access-client") == wolf_access_client.__version__


def test_a129_pyproject_version_is_the_package_version():
    """Criterion 129 reads the release version from pyproject.toml."""
    text = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{wolf_access_client.__version__}"' in text.splitlines()


def test_a129_release_tag_matches_version():
    """On a tag build (GitHub sets GITHUB_REF_TYPE=tag), the tag is vX.Y.Z."""
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        pytest.skip("not a tag build")
    assert os.environ["GITHUB_REF_NAME"] == "v" + wolf_access_client.__version__


ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".yml"}
ALLOWED_NAMES = {".gitignore", "LICENSE", "py.typed"}


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, check=True, capture_output=True,
                         text=True).stdout
    return [line for line in out.splitlines() if line]


def test_a216_repository_holds_code_only_no_data():
    """No database file, dump, export or seed: only code and its docs."""
    offenders = [f for f in tracked_files()
                 if Path(f).suffix not in ALLOWED_SUFFIXES
                 and Path(f).name not in ALLOWED_NAMES]
    assert offenders == []


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
