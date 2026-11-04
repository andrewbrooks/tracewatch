"""Per-run directory: manifest (atomic), fsynced event log, file layout, permissions (private)."""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

from .clock import stamp

MANIFEST = "manifest.json"
EVENTS = "events.jsonl"  # the recorder's own log: component start/death, heartbeats, teardown
FLOWS = "flows.jsonl"  # proxy records (connections, flows, results)
TRACEE = "tracee.jsonl"  # Tracee events
TRACEE_ERR = "tracee.err"
MITM_LOG = "mitm.log"
CA_DIR = "ca"
CA_CERT = "ca/mitmproxy-ca-cert.pem"
CA_KEY_FILES = ("mitmproxy-ca.pem", "mitmproxy-ca.p12", "mitmproxy-dhparam.pem")  # private material


class EventLog:
    """Append-only, fsynced after every record (low volume; this is the authority on what happened)."""

    def __init__(self, path: Path):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)

    def emit(self, kind: str, **kw) -> None:
        rec = {**stamp(), "kind": kind, **kw}
        os.write(self.fd, (json.dumps(rec, separators=(",", ":")) + "\n").encode())
        os.fsync(self.fd)

    def close(self) -> None:
        os.close(self.fd)


class RunDir:
    def __init__(self, path: Path):
        self.path = Path(path)

    @classmethod
    def create(cls, root: Path, name: str | None = None) -> RunDir:
        run_id = name or f"{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
        path = Path(root) / run_id
        path.mkdir(parents=True, mode=0o700)  # raises if it exists: never reuse a run dir
        (path / CA_DIR).mkdir(mode=0o700)
        (path / "flags").mkdir(mode=0o700)
        return cls(path)

    @property
    def run_id(self) -> str:
        return self.path.name

    def p(self, name: str) -> Path:
        return self.path / name

    def write_manifest(self, m: dict) -> None:
        tmp = self.p(MANIFEST + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(m, indent=1).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.p(MANIFEST))

    def read_manifest(self) -> dict:
        return json.loads(self.p(MANIFEST).read_text())

    def remove_ca_private_material(self) -> list[str]:
        """The per-run CA key is useless after the run and is the one sensitive file reconstruction
        does not need; delete it. Returns what was removed."""
        gone = []
        for n in CA_KEY_FILES:
            f = self.p(f"{CA_DIR}/{n}")
            if f.exists():
                f.unlink()
                gone.append(n)
        return gone
