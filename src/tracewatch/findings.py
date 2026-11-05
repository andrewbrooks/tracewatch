"""Indicators derived from a run's model. Each rule is justified only by data the recorder actually captured and
every finding cites its evidence (event ids), so a human can check it. These are indicators to be judged, not
verdicts: a rule firing means "look here", and the `why` says what the rule means and what it cannot know.

Severities: info < low < medium < high."""

from __future__ import annotations

import os

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
PER_RULE_CAP = 25  # a rule firing hundreds of times (bash -c) is summarised, not listed 500 times
STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")
CRED_CLIENTS = {
    "ssh",
    "ssh-add",
    "ssh-agent",
    "scp",
    "sftp",
    "git",
    "gpg",
    "gpg2",
    "gpg-agent",
    "aws",
    "gcloud",
    "az",
    "kubectl",
    "helm",
    "docker",
    "terraform",
    "npm",
    "pip",
    "pip3",
    "curl",
    "wget",
}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish", "ash"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php", "lua"}
CRASH_SIGNALS = {4, 6, 7, 8, 11}  # SIGILL SIGABRT SIGBUS SIGFPE SIGSEGV
REDACT_MARK = "[REDACTED:"


def _has_redaction(h: dict) -> bool:
    if REDACT_MARK in (h.get("path") or ""):
        return True
    if any(REDACT_MARK in str(v) for _, v in h.get("req_headers") or []):
        return True
    return REDACT_MARK in str((h.get("req_body") or {}).get("text") or "")


def find(model: dict) -> list[dict]:
    procs = {p["id"]: p for p in model["processes"]}
    events = model["events"]
    ev_by_id = {e["id"]: e for e in events}
    out: list[dict] = []

    def add(
        rule: str, severity: str, category: str, title: str, why: str, evidence: list[str], extra_procs=(), detail=""
    ):
        procs_ = []
        for eid in evidence:
            p = ev_by_id.get(eid, {}).get("proc")
            if p and p not in procs_:
                procs_.append(p)
        for p in extra_procs:
            if p and p not in procs_:
                procs_.append(p)
        t = min([ev_by_id[e]["t"] for e in evidence if e in ev_by_id] or [0])
        out.append(
            {
                "rule": rule,
                "severity": severity,
                "category": category,
                "title": title,
                "why": why,
                "detail": detail,
                "events": evidence,
                "procs": procs_,
                "t": t,
            }
        )

    def name_of(proc_id: str | None) -> str:
        return procs[proc_id]["name"] if proc_id in procs else "unknown process"

    # ---- file activity: drop-and-execute, staging execution, credential access
    writes = [
        e
        for e in events
        if e["kind"] == "file" and e["detail"]["mode"] in ("create", "write") and e["detail"]["category"] == "staging"
    ]
    execs = [e for e in events if e["kind"] == "exec"]
    dropped_exec: set[str] = set()
    for w in writes:
        path = w["detail"]["path"]
        for x in execs:
            if x["detail"].get("exe") == path and x["t"] >= w["t"]:
                dropped_exec.add(x["id"])
                add(
                    "drop-and-execute",
                    "high",
                    "execution",
                    f"File written then executed: {path}",
                    f"{name_of(w['proc'])} created {path} in a temporary directory and {name_of(x['proc'])} then executed it. "
                    "Staging a file and running it is a common way to run code that is not otherwise on the system.",
                    [w["id"], x["id"]],
                )
                break
    for x in execs:
        exe = x["detail"].get("exe") or ""
        if exe.startswith(STAGING) and x["id"] not in dropped_exec:
            add(
                "exec-from-staging",
                "medium",
                "execution",
                f"Executed from a temporary directory: {exe}",
                "Programs normally run from system or application directories. Execution from /tmp, /var/tmp or "
                "/dev/shm is used by installers and by malware alike.",
                [x["id"]],
            )
    for e in events:
        if e["kind"] != "file" or e["detail"]["category"] != "credential":
            continue
        n = name_of(e["proc"])
        benign = n in CRED_CLIENTS
        write = e["detail"]["mode"] in ("create", "write")
        sev = "high" if (write or not benign) else "low"
        add(
            "credential-file-access",
            sev,
            "credential",
            f"{n} {e['detail']['mode']}s a credential file: {e['detail']['path']}",
            (
                "Credential stores (SSH keys, cloud credentials, .netrc, .env, private keys) are what attackers look for. "
                + (
                    "This process is a well-known client of such files, so it is listed at low severity."
                    if benign and not write
                    else "This process is not a known client of that file."
                    if not write
                    else "A credential file was modified."
                )
            ),
            [e["id"]],
        )

    # ---- network
    for u in model["integrity"].get("unproxied", []):
        evid = [
            e["id"]
            for e in events
            if e["kind"] == "tcp" and e["detail"]["dst"] == u["dst"] and e["detail"]["port"] == u["port"]
        ]
        add(
            "unproxied-connection",
            "medium",
            "network",
            f"Connection bypassed the proxy: {u['dst']}:{u['port']}",
            "This process opened a TCP connection that did not go through the recorder's proxy (it ignored the proxy "
            "settings, or NO_PROXY matched). The kernel trace shows the connection; its content was NOT recorded.",
            evid[:50],
            detail=f"{u['count']} connection(s)",
        )
    for r in model["integrity"].get("tls_rejected", []):
        add(
            "tls-client-rejected",
            "medium",
            "network",
            f"Client refused the recorder's certificate: {r['host']}",
            "The process aborted the TLS handshake with the recorder's proxy (certificate pinning, or it does not trust "
            "the per-run CA). It still reached the network through the proxy, but its requests and responses were "
            "NOT recorded.",
            [h["event"] for h in model["http"] if h["event"] and h.get("tls_refused") and h["host"] == r["host"]][:50],
            detail=f"{r['count']} connection(s)" + (f": {r['error']}" if r.get("error") else ""),
        )
    per_host_cred: dict[str, list[str]] = {}
    for h in model["http"]:
        if not h["event"]:
            continue
        if h["scheme"] == "http" and _has_redaction(h):
            add(
                "cleartext-credentials",
                "high",
                "exposure",
                f"Credentials sent over unencrypted HTTP to {h['host']}",
                "A request on plain HTTP carried a credential (Authorization header, password or token). Anyone on the "
                "network path can read it.",
                [h["event"]],
            )
        elif h["scheme"] in ("https", "wss") and _has_redaction(h):
            per_host_cred.setdefault(h["host"], []).append(h["event"])
        err = (h.get("error") or "").lower()
        if err and any(k in err for k in ("certificate", "tls", "handshake", "ssl")):
            add(
                "tls-verification-failure",
                "medium",
                "network",
                f"TLS verification failed for {h['host']}",
                "The proxy could not verify the upstream server's TLS certificate (expired, self-signed, wrong host or "
                "untrusted issuer), so the connection was refused.",
                [h["event"]],
                detail=h["error"],
            )
        host = h["host"]
        if h["scheme"] != "tunnel" and _is_ip_literal(host) and not _is_local(host):
            add(
                "raw-ip-destination",
                "low",
                "network",
                f"Request to a raw IP address: {host}",
                "No hostname was used, so there is no DNS record and no certificate name to check.",
                [h["event"]],
            )
        up = (h.get("req_body") or {}).get("size") or 0
        if up >= 1_048_576:
            add(
                "large-upload",
                "low",
                "network",
                f"Large upload ({up / 1048576:.1f} MB) to {host}",
                "A request body of this size can be a bulk data transfer.",
                [h["event"]],
            )
    for host, evs in per_host_cred.items():
        add(
            "credentials-in-requests",
            "info",
            "exposure",
            f"Credentials seen in {len(evs)} request(s) to {host}",
            "Requests carried secrets (redacted in this recording). Over TLS this is normal for authenticated APIs.",
            evs[:50],
        )
    for w in model["websockets"]:
        if w["close_code"] == 1006 or w["clean"] is False:
            ev_id = next(
                (e["id"] for e in events if e["kind"] == "ws" and e["detail"].get("flow_id") == w["flow_id"]), None
            )
            add(
                "websocket-abnormal-close",
                "low",
                "reliability",
                f"WebSocket to {w['host']} closed without a close frame",
                "The peer vanished instead of closing cleanly (code 1006). The proxy hides this from the client.",
                [ev_id] if ev_id else [],
            )

    # ---- processes
    for e in events:
        if e["kind"] == "exec":
            if any(REDACT_MARK in str(a) for a in e["detail"].get("argv", [])):
                add(
                    "secret-in-command-line",
                    "medium",
                    "credential",
                    f"Secret passed on the command line: {name_of(e['proc'])}",
                    "Command-line arguments can be read by other local users through /proc (unless the system hides "
                    "them) and end up in shell history and logs.",
                    [e["id"]],
                )
        elif e["kind"] == "exit" and e["detail"].get("signal"):
            sig = e["detail"]["signal"]
            sev = "medium" if sig in CRASH_SIGNALS else "low"
            add(
                "killed-by-signal",
                sev,
                "reliability",
                f"{name_of(e['proc'])} {e['detail']['status']}",
                (
                    "A crash signal means the program hit a memory or logic fault, or was aborted."
                    if sig in CRASH_SIGNALS
                    else "The process was stopped by another process or the system."
                ),
                [e["id"]],
            )
    inline = []
    for e in execs:
        argv = e["detail"].get("argv") or []
        nm = os.path.basename(argv[0]) if argv else ""
        flags = argv[1:3]
        if (nm in SHELLS and "-c" in flags) or (
            nm.rstrip("0123456789.") in INTERPRETERS and any(f in flags for f in ("-c", "-e", "-r", "--eval"))
        ):
            inline.append(e)
    for e in inline[:PER_RULE_CAP]:
        add(
            "inline-code",
            "info",
            "execution",
            f"Inline code run through {name_of(e['proc'])}",
            "An interpreter or shell was given code on its command line (-c / -e). Common in scripts and installers; "
            "also how one-liners are delivered.",
            [e["id"]],
        )
    if len(inline) > PER_RULE_CAP:
        add(
            "inline-code",
            "info",
            "execution",
            f"... and {len(inline) - PER_RULE_CAP} more inline-code executions",
            "Only the first %d are listed individually." % PER_RULE_CAP,
            [e["id"] for e in inline[PER_RULE_CAP : PER_RULE_CAP + 50]],
        )
    bad_exit = [e for e in events if e["kind"] == "exit" and e["detail"].get("code") not in (0, None)]
    if bad_exit:
        add(
            "nonzero-exit",
            "info",
            "reliability",
            f"{len(bad_exit)} process(es) exited with a non-zero status",
            "A non-zero exit usually means the command failed (grep with no match also exits 1).",
            [e["id"] for e in bad_exit[:50]],
            detail=", ".join(f"{name_of(e['proc'])}={e['detail']['code']}" for e in bad_exit[:20]),
        )
    for p in procs.values():
        if p["detached"]:
            add(
                "detached-process",
                "low",
                "execution",
                f"{p['name']} (pid {p['pid']}) is not connected to the target's tree",
                "Its parent was not recorded, for example because the parent exited first and it was re-parented. A "
                "daemonised process outlives the command that started it.",
                [],
                extra_procs=[p["id"]],
            )

    # ---- the recording itself
    verdict = model["integrity"].get("verdict")
    if verdict in ("complete-with-losses", "incomplete"):
        add(
            "recording-integrity",
            "high" if verdict == "incomplete" else "medium",
            "integrity",
            f"The recording is {verdict.replace('-', ' ')}",
            "Conclusions drawn from this report may be missing activity.",
            [],
            detail="; ".join(model["integrity"].get("reasons", [])),
        )
    red = model.get("redactions") or {}
    total = sum((red.get("recorder") or {}).values()) + sum((red.get("proxy") or {}).values())
    if total:
        kinds = {**(red.get("recorder") or {})}
        for k, v in (red.get("proxy") or {}).items():
            kinds[k] = kinds.get(k, 0) + v
        add(
            "secrets-redacted",
            "info",
            "exposure",
            f"{total} secret value(s) were redacted from this recording",
            "Credentials, tokens and passwords seen in traffic or command lines were replaced by keyed tags before "
            "anything was written.",
            [],
            detail=", ".join(f"{k} x{v}" for k, v in sorted(kinds.items())),
        )

    out.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["t"], f["rule"]))
    for i, f in enumerate(out, 1):
        f["id"] = f"f{i}"
    return out


def _is_ip_literal(s: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_local(s: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(s)
        return a.is_loopback or a.is_private
    except ValueError:
        return False
