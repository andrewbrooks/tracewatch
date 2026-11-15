"""The commit-msg hook: the summary-line convention and the no-attribution rule."""

import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).parents[1] / ".githooks" / "commit-msg"
GOOD_BODY = "Add a thing\n\nIt was missing, and callers worked around it.\n"


def check(tmp_path, message):
    f = tmp_path / "MSG"
    f.write_text(message)
    r = subprocess.run(["bash", str(HOOK), str(f)], capture_output=True, text=True)
    return r.returncode, r.stderr


@pytest.mark.parametrize(
    "message",
    [
        "Add a thing\n",
        GOOD_BODY,
        "x" * 72 + "\n",  # exactly at the limit
        "Merge pull request #9 from someone/a-very-long-branch-name-that-goes-well-past-the-limit-of-seventy-two\n",
        'Revert "A subject that git generated and that is far longer than seventy-two characters in total"\n',
        "fixup! a commit that is going to be folded away before it ever matters to anyone reading history\n",
        "Add a thing\n\n# Please enter the commit message\n# Lines starting with '#' are ignored\n",
        "Add a thing\n\nCo-authored-by: A Person <person@example.com>\n",  # a human co-author is fine
    ],
)
def test_acceptable_messages_pass(tmp_path, message):
    code, err = check(tmp_path, message)
    assert code == 0, err


def test_a_summary_over_72_characters_is_refused_with_its_length(tmp_path):
    code, err = check(tmp_path, "x" * 73 + "\n")
    assert code == 1 and "73 characters" in err and "72 or fewer" in err


def test_an_empty_message_is_refused(tmp_path):
    code, err = check(tmp_path, "\n\n# only comments\n")
    assert code == 1 and "empty" in err


def test_a_body_must_be_separated_from_the_summary_by_a_blank_line(tmp_path):
    code, err = check(tmp_path, "Add a thing\nbecause it was missing\n")
    assert code == 1 and "blank line" in err


@pytest.mark.parametrize(
    "trailer",
    [
        "Co-Authored-By: Claude <noreply@anthropic.com>",
        "co-authored-by: Claude Opus <x@y.z>",
        "Generated with Claude Code",
        "Generated with [Claude Code](https://claude.com/claude-code)",
    ],
)
def test_tool_attribution_is_refused(tmp_path, trailer):
    code, err = check(tmp_path, f"Add a thing\n\nWhy.\n\n{trailer}\n")
    assert code == 1 and "credits a tool" in err


def test_git_itself_runs_the_hook_and_blocks_a_long_summary(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    shutil.copy(HOOK, hooks / "commit-msg")
    repo = tmp_path / "repo"
    repo.mkdir()
    git = [
        "git",
        "-C",
        str(repo),
        "-c",
        f"core.hooksPath={hooks}",
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
    ]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "f").write_text("x")
    subprocess.run([*git, "add", "f"], check=True)
    refused = subprocess.run([*git, "commit", "-q", "-m", "x" * 80], capture_output=True, text=True)
    assert refused.returncode != 0 and "80 characters" in refused.stderr
    accepted = subprocess.run(
        [*git, "commit", "-q", "-m", "Add f", "-m", "It is needed."], capture_output=True, text=True
    )
    assert accepted.returncode == 0, accepted.stderr
