"""The pre-publication audit, exercised on throw-away git repositories."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
import audit

IDENT = {"repo": "/work/secretproj", "home": "/home/zed", "user": "zed", "host": "zedbox", "ips": ["10.20.30.40"]}


def git(repo, *args, env=None):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.name", "T")
    git(tmp_path, "config", "user.email", "1+t@users.noreply.github.com")
    return tmp_path


def commit(repo, files: dict, msg="c"):
    for name, text in files.items():
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


def test_a_clean_repository_passes(repo):
    commit(repo, {"README.md": "hello from /home/dev/project and 192.0.2.10 and user@example.com\n"})
    assert audit.run(repo, IDENT) == []


@pytest.mark.parametrize(
    "files,needle",
    [
        ({"a.txt": "see /home/zed/code"}, "home directory"),
        ({"a.txt": "ssh zedbox"}, "host name"),
        ({"a.txt": "ssh 10.20.30.40"}, "local address"),
        ({"a.txt": "ping 192.168.1.5"}, "private or link-local"),
        ({"a.txt": "cd /home/someoneelse/x"}, "absolute home path"),
        ({"a.txt": "mail me: person@gmail.com"}, "email address"),
        ({"a.txt": "token ghp_" + "A1b2C3d4E5" * 4}, "secret-shaped"),
        ({"NOTES.md": "private log"}, "forbidden file"),
        ({"out/runs/x.json": "{}"}, "forbidden file"),
    ],
)
def test_each_kind_of_leak_is_caught(repo, files, needle):
    commit(repo, files)
    assert any(needle in p for p in audit.run(repo, IDENT)), audit.run(repo, IDENT)


def test_a_leak_that_was_later_deleted_is_still_found_in_history(repo):
    commit(repo, {"a.txt": "path /home/zed/x"})
    commit(repo, {"a.txt": "clean now"})
    assert any("home directory" in p for p in audit.run(repo, IDENT))


def test_commit_messages_are_checked(repo):
    commit(repo, {"a.txt": "x"}, msg="work\n\nCo-Authored-By: Claude Sonnet <noreply@anthropic.com>")
    commit(repo, {"b.txt": "x"}, msg="see NOTES.md for details")
    problems = audit.run(repo, IDENT)
    assert any("attribution trailer" in p for p in problems) and any("private file" in p for p in problems)


def test_a_personal_email_identity_is_flagged(repo):
    git(repo, "config", "user.email", "me@private-domain.org")
    commit(repo, {"a.txt": "x"})
    assert any("non-noreply email" in p for p in audit.run(repo, IDENT))


def test_png_metadata_is_flagged(repo):
    import struct
    import zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"tEXt", b"Author\x00zed")
        + chunk(b"IEND", b"")
    )
    (repo / "i.png").write_bytes(png)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "img")
    assert any("PNG tEXt" in p for p in audit.run(repo, IDENT))


def test_fake_secrets_in_allowlisted_test_files_are_not_flagged(repo):
    commit(repo, {"tests/test_redact.py": 'KEY = "ghp_' + "A1b2C3d4E5" * 4 + '"'})
    assert audit.run(repo, IDENT) == []
