from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .recorder import Options, record
from .sweep import sweep

DEFAULT_RUNS = "out/runs"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tracewatch", description="Flight recorder for a launched process.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record", help="run a command under the recorder; recording ends when it exits")
    r.add_argument("--out", default=DEFAULT_RUNS, help=f"runs directory (default {DEFAULT_RUNS})")
    r.add_argument("--port", type=int, help="proxy port (default: a free one)")
    r.add_argument("--upstream-ca", help="extra CA the proxy trusts for upstream servers (testing)")
    r.add_argument("--name", help="run directory name (default: timestamp + random)")
    r.add_argument("--max-flows-mb", type=float, default=256, help="hard cap on flows.jsonl: nothing more is written")
    r.add_argument("--soft-flows-mb", type=float, default=64, help="soft cap on flows.jsonl: bodies stop being stored")
    r.add_argument("--max-tracee-mb", type=float, default=256, help="hard cap on tracee.jsonl")
    r.add_argument("--body-cap", type=int, default=8192, help="stored characters per body (after redaction)")
    r.add_argument("--quiet", action="store_true")
    r.add_argument("argv", nargs=argparse.REMAINDER, help="-- command [args...]")
    s = sub.add_parser("sweep", help="finalize runs whose recorder died, remove leaked containers/proxies")
    s.add_argument("--out", default=DEFAULT_RUNS)
    a = p.parse_args(argv)
    if a.cmd == "sweep":
        n = sweep(Path(a.out))
        print(f"swept {len(n)} run(s)")
        return 0
    cmd = a.argv[1:] if a.argv and a.argv[0] == "--" else a.argv
    if not cmd:
        p.error("record needs a command after --")
    return record(
        Options(
            argv=cmd,
            runs_root=Path(a.out),
            port=a.port,
            upstream_ca=a.upstream_ca,
            name=a.name,
            quiet=a.quiet,
            max_flows_bytes=int(a.max_flows_mb * 1048576),
            soft_flows_bytes=int(a.soft_flows_mb * 1048576),
            max_tracee_bytes=int(a.max_tracee_mb * 1048576),
            body_cap=a.body_cap,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
