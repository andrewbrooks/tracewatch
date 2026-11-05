"""Pre-publication audit: look for things that should not be in a public repository, in the working tree AND in every
commit. Read-only. Exit status 0 = nothing found, 1 = findings.

usage: python tools/audit.py [--rev REV ...]       (default: every ref)

What it looks for
  * files that must never be tracked (the private notes file, run output, editor/session folders)
  * attribution trailers and mentions of those files in commit messages
  * this machine's identity: home directory, user name, host name, local IP addresses (computed at run time, so this
    script contains none of them)
  * generic leftovers: private/LAN addresses, absolute home paths, drive paths, email addresses, secret-shaped strings
    (a short allowlist covers files that hold FAKE secrets on purpose: redaction tests and canaries)
  * metadata inside PNG images (text and EXIF chunks)
It prints who the commit authors are so you can confirm the identity you intend to publish."""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "browser"))

from sanitize import identity  # noqa: E402

FORBIDDEN_FILES = ("NOTES.md", ".env", ".claude", "out/", "runs/", ".venv/")
MESSAGE_PATTERNS = {
    "attribution trailer": r"(?i)co-authored-by:.*(claude|anthropic)|generated with \[?claude",
    "mention of a private file": r"NOTES\.md",
}
PLACEHOLDER_HOMES = ("/home/dev", "/home/user", "/home/u/", "/home/jo", "/home/linuxbrew", "/home/runner")
# NOTE: these patterns go to `git grep -E` (POSIX extended regex): no \d, no (?:...), no multi-line matches.
GENERIC = {
    "private or link-local address": r"\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|169\.254\.[0-9]{1,3}\.[0-9]{1,3})\b",
    "absolute home path": r"/home/[A-Za-z0-9._-]+/",
    "drive or user path": r"/mnt/[a-z]/|/Users/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\",
    "email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}\b",
}
SECRET_SHAPES = r"ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{24,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----"
FIXTURE_FILES = ("tests/test_audit.py",)  # holds fake leaks on purpose, to test this very script
FAKE_SECRET_FILES = (
    "tests/test_redact.py",
    "tests/integration/canary.sh",
    "tests/fixtures/badactor.sh",
    "src/tracewatch/redact.py",
    "tests/test_audit.py",
    "tools/audit.py",
)
OK_EMAIL = re.compile(
    r"@(?:example\.(?:com|org|net)|users\.noreply\.github\.com)$|^(?:user|alice|bob)@|git@github\.com|noreply@"
)
OK_IP = re.compile(r"^(?:10\.(?:0\.0|1\.2|9\.9)\.\d+|192\.0\.2\.\d+)$")  # documentation/test placeholders


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False).stdout


def grep(repo: Path, revs: list[str], pattern: str, *, exclude: tuple[str, ...] = ()) -> set[tuple[str, int, str]]:
    """(path, line number, line) for every match in every given revision, de-duplicated across revisions."""
    out: set[tuple[str, int, str]] = set()
    pathspec = [".", ":!uv.lock", *(f":!{e}" for e in exclude)]
    for i in range(0, len(revs), 40):
        text = git(repo, "grep", "-I", "-n", "-E", pattern, *revs[i : i + 40], "--", *pathspec)
        for line in text.splitlines():
            m = re.match(r"^[0-9a-f]{40}:([^:]+):(\d+):(.*)$", line)
            if m:
                out.add((m.group(1), int(m.group(2)), m.group(3).strip()[:140]))
    return out


def png_metadata(repo: Path, revs: list[str]) -> list[str]:
    bad = []
    seen: set[str] = set()
    for rev in revs:
        for path in git(repo, "ls-tree", "-r", "--name-only", rev).splitlines():
            if not path.lower().endswith(".png"):
                continue
            blob = git(repo, "rev-parse", f"{rev}:{path}").strip()
            if blob in seen:
                continue
            seen.add(blob)
            data = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", blob], capture_output=True).stdout
            i = 8
            while i + 8 <= len(data):
                n = struct.unpack(">I", data[i : i + 4])[0]
                kind = data[i + 4 : i + 8].decode("latin1")
                if kind in ("tEXt", "iTXt", "zTXt", "eXIf"):
                    bad.append(f"{path}: PNG {kind} chunk")
                    break
                i += 12 + n
    return bad


def run(repo: Path, ident: dict, revs: list[str] | None = None) -> list[str]:
    """All problems found, as readable lines (empty list = clean)."""
    revs = revs or git(repo, "rev-list", "--all").split()
    problems: list[str] = []
    # 1. files that must not be tracked, in any revision
    for rev in revs:
        for path in git(repo, "ls-tree", "-r", "--name-only", rev).splitlines():
            if any(path == f or path.startswith(f) for f in FORBIDDEN_FILES):
                problems.append(f"forbidden file tracked: {path} (first seen in {rev[:8]})")
    # 2. commit messages
    for rev in revs:
        msg = git(repo, "log", "-1", "--format=%B", rev)
        for label, pat in MESSAGE_PATTERNS.items():
            if re.search(pat, msg):
                problems.append(f"{label} in the message of {rev[:8]}: {msg.splitlines()[0][:60]!r}")
    # 3. identities (informational, plus a warning for a real-looking email)
    idents = {ln for ln in git(repo, "log", "--no-walk", "--format=%an <%ae> | %cn <%ce>", *revs).splitlines() if ln}
    for line in sorted(idents):
        for email in re.findall(r"<([^>]+)>", line):
            if not OK_EMAIL.search(email):
                problems.append(f"commit identity uses a non-noreply email: {email}")
    # 4. this machine's identity, in every revision
    literals = {"home directory": re.escape(ident["home"]), "repository path": re.escape(ident["repo"])}
    if len(ident["user"]) >= 3:
        literals["user name"] = rf"\b{re.escape(ident['user'])}\b"
    if len(ident["host"]) >= 3:
        literals["host name"] = rf"\b{re.escape(ident['host'])}\b"
    for ip in ident["ips"]:
        literals[f"local address {ip}"] = re.escape(ip)
    for label, pat in literals.items():
        for path, n, line in sorted(grep(repo, revs, pat)):
            problems.append(f"{label}: {path}:{n}: {line}")
    # 5. generic leftovers
    for label, pat in GENERIC.items():
        for path, n, line in sorted(grep(repo, revs, pat, exclude=FIXTURE_FILES)):
            hits = [m.group(0) for m in re.finditer(pat, line)]
            if label == "private or link-local address" and all(OK_IP.match(h) for h in hits):
                continue
            if label == "absolute home path" and all(any(h.startswith(p) for p in PLACEHOLDER_HOMES) for h in hits):
                continue
            if label == "email address" and all(OK_EMAIL.search(h) for h in hits):
                continue
            problems.append(f"{label}: {path}:{n}: {line}")
    for path, n, line in sorted(grep(repo, revs, SECRET_SHAPES, exclude=FAKE_SECRET_FILES)):
        problems.append(f"secret-shaped string: {path}:{n}: {line}")
    # 6. image metadata
    problems += png_metadata(repo, revs)
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rev", action="append", help="audit only these revisions (default: all refs)")
    ap.add_argument("--repo", default=str(ROOT))
    a = ap.parse_args()
    repo = Path(a.repo)
    revs = [git(repo, "rev-parse", r).strip() for r in a.rev] if a.rev else None
    revs_all = revs or git(repo, "rev-list", "--all").split()
    print(f"auditing {len(revs_all)} commit(s) in {repo}")
    print(
        "authors/committers:",
        *sorted({ln for ln in git(repo, "log", "--all", "--format=%an <%ae>").splitlines() if ln}),
        sep="\n  ",
    )
    problems = run(repo, identity(), revs)
    if problems:
        print(f"\n{len(problems)} problem(s):")
        for p in problems[:80]:
            print("  -", p)
        return 1
    print("\nclean: nothing found. (A clean audit is not a guarantee; screenshots are pixels, not text.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
