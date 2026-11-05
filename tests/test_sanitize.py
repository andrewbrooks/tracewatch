"""The screenshot sanitizer: it must remove this machine's identity and nothing that makes the page meaningful."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "browser"))
from sanitize import leaks, sanitize  # noqa: E402

IDENT = {"repo": "/home/jo/code/tw", "home": "/home/jo", "user": "jo", "host": "workbox", "ips": ["10.1.2.3"]}


def test_paths_user_host_and_addresses_are_replaced():
    m = {
        "cmd": "cat /home/jo/code/tw/x /home/jo/.ssh/id_rsa",
        "who": "jo@workbox",
        "ip": "10.1.2.3",
        "pub": "93.184.216.34",
    }
    out = sanitize(m, IDENT, {})
    assert out["cmd"] == "cat /home/dev/project/x /home/dev/.ssh/id_rsa"
    assert out["who"] == "dev@devbox"
    assert out["ip"].startswith("192.0.2.") and out["pub"].startswith("203.0.113.")
    assert not leaks(str(out), IDENT)


def test_the_same_address_always_maps_to_the_same_stand_in_and_different_ones_differ():
    t = {}
    a, b, c = (sanitize(x, IDENT, t) for x in ("10.1.2.3", "10.9.9.9", "10.1.2.3"))
    assert a == c and a != b


def test_loopback_ports_versions_and_nested_structures_are_left_alone():
    m = {"a": ["127.0.0.1:8080", {"k": "kernel 6.18.54.1-microsoft-standard", "v": "TLSv1.3 1.2.3"}], "n": 5}
    assert sanitize(m, IDENT, {}) == m


def test_the_leak_check_catches_what_is_left():
    assert leaks("see /home/jo/x", IDENT) and leaks("ssh jo@box", IDENT) and leaks("at 10.1.2.3:22", IDENT)
    assert leaks("a stray 198.18.0.7 here", IDENT)  # any non-documentation, non-loopback address
    assert not leaks("localhost 127.0.0.1 and 192.0.2.10, /home/dev/project", IDENT)
