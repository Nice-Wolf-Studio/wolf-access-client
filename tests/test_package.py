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


def pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    if tomllib is not None:
        return tomllib.loads(text)["project"]["version"]
    for line in text.splitlines():
        if line.startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError("no version in pyproject.toml")


@pytest.mark.skipif(tomllib is None, reason="tomllib needs Python 3.11+")
def test_a129_pyproject_has_pep621_metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["name"] == "wolf-access-client"
    assert project["requires-python"] == ">=3.10"
    assert project.get("dependencies", []) == []
    assert project["readme"] == "README.md"


def test_a129_package_version_matches_pyproject():
    assert wolf_access_client.__version__ == pyproject_version()


def test_a129_release_tag_matches_version():
    """On a tag build (GitHub sets GITHUB_REF_TYPE=tag), the tag is vX.Y.Z."""
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        pytest.skip("not a tag build")
    assert os.environ["GITHUB_REF_NAME"] == "v" + pyproject_version()


ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".yml"}
ALLOWED_NAMES = {".gitignore"}


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
