"""What can be trusted in a run directory? Pure reading of the files; no Docker, no running processes
except one identity check on the recorder's pid.

Verdicts
  complete               finalized by the recorder, nothing lost
  complete-with-losses   finalized, but a component died, a cap was hit, the recorder stalled, or lines are
                         corrupt: the listed gaps/caps say exactly what is missing
  incomplete             the recorder died (or the manifest lies about finishing): everything after
                         `untrusted_after_mono` is untrusted, and nothing proves the run ended
  in-progress            the recorder is still alive and has not finished
  unreadable             no usable manifest

Times are CLOCK_MONOTONIC nanoseconds as recorded in events.jsonl (the wall clock steps on some hosts)."""

from __future__ import annotations

import json
from pathlib import Path

from .procinfo import same_process

HEARTBEAT_S = 2.0
STALL_FACTOR = 3.0  # a gap between heartbeats this many times the interval means the recorder stalled/suspended
SOURCES = ("flows.jsonl", "tracee.jsonl", "events.jsonl")
EXIT_CODES = {"complete": 0, "complete-with-losses": 1, "incomplete": 2, "in-progress": 3, "unreadable": 4}


def _read_jsonl(path: Path) -> tuple[list[dict], dict]:
    """-> (records, {lines, corrupt, truncated_last}); a kill can leave a half-written last line."""
    stats = {"lines": 0, "corrupt": 0, "truncated_last": False}
    if not path.exists():
        return [], {**stats, "missing": True}
    raw = path.read_bytes()
    parts = raw.split(b"\n")
    stats["truncated_last"] = bool(parts[-1])  # data after the final newline
    recs = []
    for i, line in enumerate(parts):
        if not line:
            continue
        stats["lines"] += 1
        try:
            recs.append(json.loads(line))
        except ValueError:
            if i == len(parts) - 1:
                stats["truncated_last"] = True
            else:
                stats["corrupt"] += 1
    return recs, stats


def assess(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    out: dict = {"run_dir": str(run_dir), "verdict": "unreadable", "reasons": [], "gaps": [], "caps": [], "files": {}}
    try:
        m = json.loads((run_dir / "manifest.json").read_text())
    except (OSError, ValueError):
        out["reasons"].append("manifest.json is missing or unreadable")
        return out
    ev, ev_stats = _read_jsonl(run_dir / "events.jsonl")
    ev.sort(key=lambda e: e.get("t_mono_ns", 0))
    for name in SOURCES:
        _, stats = (ev, ev_stats) if name == "events.jsonl" else _read_jsonl(run_dir / name)
        out["files"][name] = stats
    status = m.get("status")
    out["status"] = status
    at = lambda kind: next((e for e in ev if e["kind"] == kind), None)  # noqa: E731
    armed, exited, finished = at("recording_armed"), at("root_exited"), at("run_finished")
    beats = [e for e in ev if e["kind"] == "heartbeat"]
    last_beat = beats[-1]["t_mono_ns"] if beats else None
    out["window"] = {
        "start_mono": armed["t_mono_ns"] if armed else None,
        "root_exited_mono": exited["t_mono_ns"] if exited else None,
        "last_heartbeat_mono": last_beat,
    }
    if m.get("policy"):
        out["policy"] = m["policy"]
    if m.get("target_stopped"):
        out["target_stopped"] = m["target_stopped"]

    losses: list[str] = []
    # ---- how did the run end?
    if status in ("finished", "interrupted"):
        if not finished:
            verdict, why = "incomplete", "manifest says finished but events.jsonl has no run_finished"
            out["reasons"].append(why)
        else:
            verdict = "complete"
            out["end_mono"] = (exited or finished)["t_mono_ns"]
    elif status == "running":
        alive = same_process(m.get("recorder_pid", -1), m.get("recorder_start_ticks"))
        verdict = "in-progress" if alive else "incomplete"
        if not alive:
            out["reasons"].append("the recorder died without finalizing the run (not yet swept)")
    elif status == "aborted":
        verdict = "incomplete"
        out["reasons"].append("the recorder died; the run was finalized as aborted by a sweep")
    elif status == "failed_to_start":
        verdict = "incomplete"
        out["reasons"].append(f"the recording never started: {m.get('why')}")
    else:
        out["reasons"].append(f"unknown status {status!r}")
        return out
    if verdict == "incomplete" and last_beat is not None:
        # nothing after the last heartbeat (+ one interval of slack) can be vouched for
        out["untrusted_after_mono"] = last_beat + int(HEARTBEAT_S * 1e9)
        out["end_mono"] = last_beat
    if m.get("target_still_running"):
        out["reasons"].append("the target was still running (unrecorded) when the run was swept")

    # ---- gaps and caps (a gap runs from the loss to the end of the trusted window)
    end = out.get("end_mono")
    for e in ev:
        if e["kind"] == "component_died":
            src = {"mitm": "proxy", "tracee": "tracee", "tracee-collector": "tracee"}.get(
                e.get("component"), e.get("component")
            )
            out["gaps"].append(
                {"source": src, "start_mono": e["t_mono_ns"], "end_mono": end, "reason": f"{e.get('component')} died"}
            )
            losses.append(f"{src} lost")
        elif e["kind"] == "cap_reached":
            cap = e.get("cap", "?")
            out["caps"].append({"cap": cap, "at_mono": e["t_mono_ns"]})
            if cap.endswith(":hard"):
                out["gaps"].append(
                    {
                        "source": cap.split(":")[0],
                        "start_mono": e["t_mono_ns"],
                        "end_mono": end,
                        "reason": f"{cap} size cap reached",
                    }
                )
            losses.append(f"{cap} cap")
    for a, b in zip(beats, beats[1:], strict=False):
        if (b["t_mono_ns"] - a["t_mono_ns"]) / 1e9 > HEARTBEAT_S * STALL_FACTOR:
            out["gaps"].append(
                {
                    "source": "recorder",
                    "start_mono": a["t_mono_ns"],
                    "end_mono": b["t_mono_ns"],
                    "reason": f"no heartbeat for {(b['t_mono_ns'] - a['t_mono_ns']) / 1e9:.1f} s "
                    "(recorder stalled or the machine slept)",
                }
            )
            losses.append("recorder stall")
    bad = {n: s["corrupt"] for n, s in out["files"].items() if s.get("corrupt")}
    if bad:
        losses.append(f"corrupt lines {bad}")
    if verdict == "complete" and any(s.get("truncated_last") for s in out["files"].values()):
        losses.append("a file ends in a half-written line")
    if verdict == "complete" and losses:
        verdict = "complete-with-losses"
        out["reasons"] += sorted(set(losses))
    out["verdict"] = verdict
    return out
