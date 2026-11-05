"""Packaging metadata must agree with itself."""

import re
import tomllib
from pathlib import Path

import tracewatch

ROOT = Path(__file__).parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def test_the_version_is_the_same_everywhere():
    assert PROJECT["version"] == tracewatch.__version__


def test_the_readme_and_license_files_named_in_the_metadata_exist():
    assert (ROOT / PROJECT["readme"]).exists()
    assert all((ROOT / f).exists() for f in PROJECT["license-files"])
    assert PROJECT["license"] == "Apache-2.0" and "Apache License" in (ROOT / "LICENSE").read_text()[:200]


def test_the_console_script_points_at_a_real_function():
    module, func = PROJECT["scripts"]["tracewatch"].split(":")
    assert callable(getattr(__import__(module, fromlist=[func]), func))


def test_the_pinned_tracee_image_is_a_version_tag_not_latest():
    from tracewatch import tracee

    assert not tracee.IMAGE.endswith(":latest") and re.search(r":\d+\.\d+\.\d+$", tracee.IMAGE)
