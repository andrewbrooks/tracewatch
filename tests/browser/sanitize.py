"""Make a model safe to show in a screenshot: no home directory, user name, host name, repository path or real
(LAN/resolver/public) IP addresses. Best effort for *screenshots*, with a hard check that the literal values of this
machine's identity are gone from the rendered page. Not a general anonymiser: do not use it to share real recordings."""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
import socket
import subprocess
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[2])
QUAD = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]|-[a-z])")


def identity() -> dict:
    """What identifies this machine, as literals (what the leak check searches for)."""
    ips = set(subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split())
    return {
        "repo": REPO,
        "home": os.path.expanduser("~"),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "ips": sorted(ips),
    }


def _doc_ip(real: str, table: dict) -> str:
    """Deterministic stand-in from the RFC 5737 documentation ranges (192.0.2/24 private-looking, 203.0.113/24 public)."""
    if real not in table:
        ip = ipaddress.ip_address(real)
        base = "192.0.2" if ip.is_private or ip.is_link_local else "203.0.113"
        n = sum(1 for v in table.values() if v.startswith(base)) + 10
        table[real] = f"{base}.{n}"
    return table[real]


def _scrub(s: str, ident: dict, table: dict) -> str:
    s = s.replace(ident["repo"], "/home/dev/project").replace(ident["home"], "/home/dev")
    s = re.sub(r"\b" + re.escape(ident["user"]) + r"\b", "dev", s)
    if len(ident["host"]) >= 3:
        s = re.sub(r"\b" + re.escape(ident["host"]) + r"\b", "devbox", s)

    def ip(m: re.Match) -> str:
        try:
            a = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)  # 999.1.1.1 or the like: not an address
        return m.group(0) if a.is_loopback or a.is_unspecified or a.is_multicast else _doc_ip(m.group(0), table)

    return QUAD.sub(ip, s)


def sanitize(obj, ident: dict | None = None, table: dict | None = None):
    ident, table = ident or identity(), table if table is not None else {}
    if isinstance(obj, str):
        return _scrub(obj, ident, table)
    if isinstance(obj, list):
        return [sanitize(x, ident, table) for x in obj]
    if isinstance(obj, dict):
        return {
            sanitize(k, ident, table) if isinstance(k, str) else k: sanitize(v, ident, table) for k, v in obj.items()
        }
    return obj


def leaks(text: str, ident: dict | None = None) -> list[str]:
    """Every identifying literal still present in `text` (empty = clean)."""
    ident = ident or identity()
    found = []
    for k in ("repo", "home"):
        if ident[k] in text:
            found.append(f"{k}: {ident[k]}")
    if re.search(r"\b" + re.escape(ident["user"]) + r"\b", text):
        found.append(f"user name: {ident['user']}")
    if len(ident["host"]) >= 3 and re.search(r"\b" + re.escape(ident["host"]) + r"\b", text):
        found.append(f"host name: {ident['host']}")
    found += [f"ip: {i}" for i in ident["ips"] if i in text]
    for m in QUAD.finditer(text):  # any other non-loopback address-looking string
        try:
            a = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if not (a.is_loopback or a.is_unspecified or a.is_multicast or str(a).startswith(("192.0.2.", "203.0.113."))):
            found.append(f"ip-like: {m.group(0)}")
    return found
