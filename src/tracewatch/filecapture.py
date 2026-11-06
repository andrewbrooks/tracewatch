"""Contents of the files the target CREATED or WROTE, on the watched paths only (temp dirs and credential stores).

What the target writes is as attacker-controlled as anything else in a recording, so nothing here trusts it:
  * a file is read only if it is a regular file, opened component by component with O_NOFOLLOW (a symlink swapped in
    after the event cannot redirect the read), without blocking (a FIFO cannot hang the recorder);
  * at most CAP_FILE bytes per file and CAP_TOTAL for the run are kept;
  * text is made inert before it is stored: control characters, bidirectional overrides and invisible characters are
    replaced by visible `⟦\\x1b⟧` escapes, then the same redaction the rest of the recording gets is applied;
  * binary files are never stored as text, only their size, hash and first bytes.
Files that were only READ are never captured: a credential store the target merely opened stays out of the recording.

How it works: the Tracee collector hands every line to `tap`; a write/create open (or the exec of a file the target
wrote) marks the path; a small thread re-reads marked files when they change and once more when the run ends, so a
file deleted right after use is still caught if it was seen in time.

A file written, run and deleted within milliseconds is gone before Tracee's event reaches us, so a second, small
mechanism (TempWatcher) listens with inotify on the temp directories and keeps the last CAP_FILE bytes of every file
the current user closes after writing, in memory only, for BUFFER_TTL_S seconds. Nothing from that buffer is stored
unless Tracee then reports that the TRACED process wrote the same path; everything else is discarded unread by
anyone. Not covered: directories that already existed below the temp roots when the run began, and a file written
and deleted within about a tenth of a millisecond of its new directory being created."""

from __future__ import annotations

import codecs
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import select
import stat
import struct
import threading
import time
from pathlib import Path

from .model import decode_open_flags
from .redact import Redactor

FILES = "files.jsonl"
CAP_FILE = 16 * 1024  # stored bytes per file
CAP_TOTAL = 256 * 1024  # stored bytes per run
MAX_FILES = 100  # distinct paths followed
HASH_MAX = 4 * 1024 * 1024  # hash a file only if it is no bigger than this
POLL_S = 0.2
BUFFER_TTL_S = 10.0
BUFFER_MAX = 256  # entries
WATCH_MAX = 256  # inotify watches
TEMP_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")
FIRST_LOOK_S = 0.05  # a freshly opened-for-writing file is looked at after this long, then on every change

_OPEN, _EXEC = b'"eventName":"security_file_open"', b'"eventName":"sched_process_exec"'
# C0 (except \n and \t), DEL, C1, Arabic letter mark, zero-width and bidi marks/overrides/isolates, line/paragraph
# separators, the invisible operators, BOM, interlinear annotation, and the tag characters
_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f؜​-‏ -‮⁠-⁯﻿￹-￻\U000e0000-\U000e007f]")


def _escape(m: re.Match) -> str:
    c = ord(m.group(0))
    return f"⟦\\x{c:02x}⟧" if c < 0x100 else f"⟦\\u{c:04x}⟧" if c < 0x10000 else f"⟦\\U{c:08x}⟧"


def sanitize(text: str) -> str:
    """Make text safe to show anywhere: every character that can move the cursor, hide text or reorder it is replaced
    by a visible escape. Newline and tab are kept. (Applied BEFORE redaction, so hidden characters cannot be used to
    smuggle a pattern past it or to hide a tag after it.)"""
    return _UNSAFE.sub(_escape, text)


def open_nofollow(path: str) -> int | None:
    """Open an absolute path read-only without following a symlink in ANY component; None if that is not possible."""
    if not path.startswith("/") or "\x00" in path:
        return None
    parts = [p for p in path.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        return None
    cur = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if i < len(parts) - 1:
                flags |= os.O_DIRECTORY
            nxt = os.open(part, flags, dir_fd=cur)
            os.close(cur)
            cur = nxt
        return cur
    except OSError:
        os.close(cur)
        return None


def read_regular(path: str, cap: int = CAP_FILE, unchanged: tuple[int, int] | None = None) -> dict | None:
    """{size, mtime_ns, data (at most cap bytes), sha256 (None if too big)} for a regular file, else None.
    If `unchanged` (the (mtime_ns, size) seen last time) still holds, returns {"unchanged": True} without reading."""
    fd = open_nofollow(path)
    if fd is None:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if unchanged == (st.st_mtime_ns, st.st_size):
            return {"unchanged": True}
        hashing = st.st_size <= HASH_MAX
        limit = HASH_MAX if hashing else cap
        data, h, total = b"", hashlib.sha256(), 0
        while total < limit:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if len(data) < cap:
                data += chunk[: cap - len(data)]
            if hashing:
                h.update(chunk)
        return {
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "uid": st.st_uid,
            "data": data,
            "sha256": h.hexdigest() if hashing and total == st.st_size else None,
        }
    except OSError:
        return None
    finally:
        os.close(fd)


def to_text(data: bytes, truncated: bool) -> str | None:
    """The bytes as text, or None if they are not text (a NUL byte, or many undecodable bytes)."""
    if b"\x00" in data[:8192]:
        return None
    dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
    text = dec.decode(data, final=not truncated)  # a multibyte character cut by the cap is dropped, not mangled
    if text and text.count("�") > max(2, len(text) // 50):
        return None
    return text


def _event_args(line: bytes) -> tuple[dict, dict] | None:
    try:
        e = json.loads(line)
        return e, {a["name"]: a["value"] for a in e.get("args", [])}
    except (ValueError, KeyError, TypeError):
        return None


_IN_CLOSE_WRITE, _IN_MOVED_TO, _IN_CREATE, _IN_IGNORED, _IN_ISDIR = 0x8, 0x80, 0x100, 0x8000, 0x40000000
_EVENT = struct.Struct("iIII")  # struct inotify_event header: wd, mask, cookie, len


class TempWatcher(threading.Thread):
    """inotify on the temp roots and on every directory created below them while the run lasts. Each file closed after
    writing (by anyone, as the current user) is read at once into a small buffer; see the module docstring."""

    def __init__(self, roots: tuple[str, ...] = TEMP_ROOTS):
        super().__init__(daemon=True, name="temp-watcher")
        self.roots = tuple(os.path.realpath(r) for r in roots)  # Tracee reports canonical paths
        self.ready = threading.Event()
        self.stop_ev = threading.Event()
        self.lock = threading.Lock()
        self.buffer: dict[str, dict] = {}
        self.wds: dict[int, str] = {}
        self.fd = -1
        self.available = False

    def _add(self, path: str) -> None:
        if len(self.wds) >= WATCH_MAX:
            return
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(path), _IN_CLOSE_WRITE | _IN_MOVED_TO | _IN_CREATE)
        if wd >= 0:
            self.wds[wd] = path

    def run(self) -> None:
        try:
            self._libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
            self.fd = self._libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
            if self.fd < 0:
                return
            self.available = True
            for root in self.roots:
                if os.path.isdir(root):
                    self._add(root)
        except Exception:
            return
        finally:
            self.ready.set()
        try:
            while not self.stop_ev.is_set():
                if not select.select([self.fd], [], [], 0.1)[0]:
                    self._evict()
                    continue
                try:
                    chunk = os.read(self.fd, 1 << 16)
                except BlockingIOError:
                    continue
                self._handle(chunk)
        finally:
            os.close(self.fd)

    def _handle(self, chunk: bytes) -> None:
        pos = 0
        while pos + _EVENT.size <= len(chunk):
            wd, mask, _, n = _EVENT.unpack_from(chunk, pos)
            name = chunk[pos + _EVENT.size : pos + _EVENT.size + n].split(b"\0", 1)[0]
            pos += _EVENT.size + n
            if mask & _IN_IGNORED:
                self.wds.pop(wd, None)
                continue
            base = self.wds.get(wd)
            if base is None or not name:
                continue
            path = os.path.join(base, os.fsdecode(name))
            if mask & _IN_ISDIR:
                if mask & (_IN_CREATE | _IN_MOVED_TO):
                    self._adopt_dir(path)
            elif mask & (_IN_CLOSE_WRITE | _IN_MOVED_TO):
                self._remember(path)

    def _adopt_dir(self, path: str, depth: int = 0) -> None:
        """Watch a new directory, then look at what is already in it: its first files may have been written (and even
        deleted) in the moment before the watch existed."""
        self._add(path)
        if depth > 8:
            return
        try:
            with os.scandir(path) as it:
                entries = list(it)[:200]
        except OSError:
            return
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    self._adopt_dir(e.path, depth + 1)
                elif e.is_file(follow_symlinks=False):
                    self._remember(e.path)
            except OSError:
                continue

    def _remember(self, path: str) -> None:
        info = read_regular(path)
        if info is None or info["uid"] != os.getuid():
            return
        info["at"] = time.monotonic()
        with self.lock:
            self.buffer[path] = info
            while len(self.buffer) > BUFFER_MAX:
                self.buffer.pop(next(iter(self.buffer)))

    def _evict(self) -> None:
        cutoff = time.monotonic() - BUFFER_TTL_S
        with self.lock:
            for k in [k for k, v in self.buffer.items() if v["at"] < cutoff]:
                del self.buffer[k]

    def take(self, path: str) -> dict | None:
        """The last buffered read of this path, if there is a recent one."""
        with self.lock:
            v = self.buffer.get(path)
            return dict(v) if v and time.monotonic() - v["at"] <= BUFFER_TTL_S else None

    def stop(self) -> None:
        self.stop_ev.set()


class FileCapture(threading.Thread):
    def __init__(
        self,
        redactor: Redactor,
        out: Path,
        skip_prefixes: tuple[str, ...] = (),
        temp_roots: tuple[str, ...] = TEMP_ROOTS,
    ):
        super().__init__(daemon=True, name="file-capture")
        # a second Redactor with the SAME key: identical tags, and no shared counters with the collector thread
        self.redactor = Redactor(redactor.key)
        self.out = Path(out)
        self.skip = tuple(skip_prefixes)
        self.watcher = TempWatcher(temp_roots)
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.done = threading.Event()
        self.tracked: dict[str, dict] = {}  # path -> {"writers": set, "seen": (mtime_ns, size) | None, "due": mono}
        self.records: dict[str, dict] = {}
        self.stored = 0
        self.ignored = 0  # paths not followed because MAX_FILES was reached
        self.dirty = False
        self.error: str | None = None

    # ---- called from the collector thread: cheap, never raises
    def tap(self, line: bytes) -> None:
        try:
            if _OPEN in line:
                parsed = _event_args(line)
                if not parsed:
                    return
                e, a = parsed
                path = a.get("pathname") or ""
                if decode_open_flags(int(a.get("flags") or 0)) == "read" or not self._wanted(path):
                    return
                with self.lock:
                    t = self.tracked.get(path)
                    if t is None:
                        if len(self.tracked) >= MAX_FILES:
                            self.ignored += 1
                            return
                        t = self.tracked[path] = {"writers": set(), "seen": None, "due": 0.0, "snaps": 0}
                    t["writers"].add(e.get("processId"))
                    t["due"] = time.monotonic() + FIRST_LOOK_S
                self.wake.set()
            elif _EXEC in line:
                parsed = _event_args(line)
                path = (parsed[1].get("pathname") or "") if parsed else ""
                with self.lock:
                    hit = path in self.tracked
                    if hit:
                        self.tracked[path]["due"] = 0.0  # look now: a dropped file is often deleted right after it runs
                if hit:
                    self.wake.set()
        except Exception as ex:  # the collector must never be hurt by this
            self.error = repr(ex)

    def _wanted(self, path: str) -> bool:
        return bool(path) and path.startswith("/") and not path.startswith(self.skip) and len(path) < 4096

    # ---- the polling thread
    def start(self) -> None:
        self.watcher.start()
        self.watcher.ready.wait(2)  # the watches must exist before the target starts writing
        super().start()

    def run(self) -> None:
        last_write = time.monotonic()
        while not self.done.is_set():
            self.wake.wait(POLL_S)
            self.wake.clear()
            try:
                self._pass(final=False)
                if self.dirty and time.monotonic() - last_write > 2:
                    self._write()
                    last_write = time.monotonic()
            except Exception as ex:
                self.error = repr(ex)

    def finish(self) -> None:
        """Stop, look at every followed file one last time, and write files.jsonl."""
        self.done.set()
        self.wake.set()
        if self.is_alive():
            self.join(timeout=10)
        try:
            self._pass(final=True)
            self._write()
        except Exception as ex:
            self.error = repr(ex)
        self.watcher.stop()

    def _pass(self, final: bool) -> None:
        with self.lock:
            now = time.monotonic()
            paths = [p for p, t in self.tracked.items() if final or t["due"] <= now]
        for path in paths:
            self._look(path, "final" if final else "change")

    def _look(self, path: str, reason: str) -> None:
        with self.lock:
            t = self.tracked[path]
            seen = t["seen"] if path in self.records else None
            t["due"] = time.monotonic() + POLL_S  # keep polling: a later write shows as an mtime/size change
        info = read_regular(path, unchanged=seen)
        if info is None:
            info = self.watcher.take(path)  # already deleted: use what the watcher saw of it just before
            reason = "buffer"
        if info is None or info.get("unchanged"):
            return  # gone / not a regular file / nothing new: whatever was seen before stays
        mark = (info["mtime_ns"], info["size"])
        truncated = info["size"] > len(info["data"])
        text = to_text(info["data"], truncated)
        rec = {
            "path": path,
            "size": info["size"],
            "sha256": info["sha256"],
            "writers": sorted(w for w in t["writers"] if w is not None),
            "binary": text is None,
            "truncated": truncated and text is not None,
            "seen_by": reason,
            "t_mono_ns": time.monotonic_ns(),
        }
        if text is None:
            rec["head_hex"] = info["data"][:32].hex()
        else:
            clean = sanitize(text)
            rec["text"] = self.redactor.text(clean)
            rec["redacted"] = rec["text"] != clean
        with self.lock:
            old = self.records.get(path)
            self.stored -= len(old.get("text", "").encode()) if old else 0
            cost = len(rec.get("text", "").encode())
            if self.stored + cost > CAP_TOTAL:
                rec.pop("text", None)
                rec["dropped_by_cap"] = True
                cost = 0
            self.stored += cost
            t["seen"] = mark
            t["snaps"] += 1
            self.records[path] = rec
            self.dirty = True

    def _write(self) -> None:
        with self.lock:
            lines = [json.dumps(r, separators=(",", ":")) for _, r in sorted(self.records.items())]
            self.dirty = False
        tmp = self.out.with_name(self.out.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, ("\n".join(lines) + ("\n" if lines else "")).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.out)

    def summary(self) -> dict:
        with self.lock:
            recs = list(self.records.values())
        return {
            "files": len(recs),
            "binary": sum(1 for r in recs if r["binary"]),
            "truncated": sum(1 for r in recs if r["truncated"]),
            "dropped_by_cap": sum(1 for r in recs if r.get("dropped_by_cap")),
            "not_followed": self.ignored,
            "stored_bytes": self.stored,
            "redacted_files": sum(1 for r in recs if r.get("redacted")),
            "error": self.error,
        }
