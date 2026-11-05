"""Indicators derived from a run's model. Each rule is justified only by data the recorder actually captured and
every finding cites its evidence (event ids), so a human can check it. These are indicators to be judged, not
verdicts: a rule firing means "look here", and the `why` says what the rule means and what it cannot know.

Severities: info < low < medium < high."""

from __future__ import annotations

import os
import re

from .findings_catalog import CATALOG
from .plural import pl

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
PER_RULE_CAP = 25  # a rule firing hundreds of times (bash -c) is summarised, not listed 500 times
STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")
CRED_CLIENTS = {
    "sudo",
    "visudo",
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
REDACT_MARK_URLENCODED = "%5BREDACTED%3A"

# ---- behaviour rules over command lines (the six added with the finding catalog; see findings_catalog.py)
_DL = r"(?:curl|wget|fetch|lwp-download|aria2c)"
_SUDO = r"(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?"
_SH_SINK = _SUDO + r"(?:sh|bash|zsh|dash|ksh)(?:\s+-(?:s|l|e|x|ex|xe)\b[^|;&\n]*)?\s*(?:$|[|;&)\"'])"
_IN_SINK = _SUDO + r"(?:python[\d.]*|perl|ruby|php|node)(?:\s+-)?\s*(?:$|[|;&)\"'])"  # reads the script from stdin
PIPE_TO_SHELL = [
    re.compile(rf"\b{_DL}\b[^|;&\n]*\|\s*(?:{_SH_SINK}|{_IN_SINK})"),
    re.compile(rf"\b(?:sh|bash|zsh|dash|ksh)\s+<\(\s*{_DL}\b"),
    re.compile(rf"-c\s+[\"']?\$\(\s*{_DL}\b"),
]
_SHELLISH = r"(?:ba|z|da|k)?sh"
REVERSE_SHELL = [
    re.compile(rf"\b{_SHELLISH}\s+-i\b[^\n]*(?:>&|<&|0>&1|/dev/(?:tcp|udp)/)"),
    re.compile(r"/dev/(?:tcp|udp)/[\w.:\[\]-]+/\d+[^\n]*(?:0>&1|<&|>&)|(?:0>&1|<&|>&)[^\n]*/dev/(?:tcp|udp)/"),
    re.compile(rf"\b(?:nc|ncat|netcat)\b[^\n|]*\s-[a-zA-Z]*[ec]\s*(?:\S*/)?{_SHELLISH}\b"),
    re.compile(r"\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat)\b"),
    re.compile(r"\bsocat\b[^\n]*\b(?:exec|system):", re.I),
    re.compile(
        r"\b(?:python[\d.]*|perl|ruby|php)\b[^\n]*\bsocket\b[^\n]*(?:dup2|pty\.spawn|/bin/(?:ba)?sh|subprocess)", re.I
    ),
]
_DEC = (
    r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|b64decode|decode_base64|atob)"
)
ENCODED = [
    re.compile(
        r"\bbase64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*"
        + _SUDO
        + r"(?:sh|bash|zsh|dash|python[\d.]*|perl|ruby|php|node)\b"
    ),
    re.compile(r"\bxxd\s+-r\b[^\n]*\|\s*(?:sh|bash)\b"),
    re.compile(
        rf"\b(?:eval|assert|exec|system|passthru|shell_exec)\s*\(\s*@?\s*(?:__import__\(['\"]\w+['\"]\)\.|[\w.]*\.)?{_DEC}\s*\(",
        re.I,
    ),
    re.compile(rf"\beval\s*\(\s*(?:\w+::)?{_DEC}\b", re.I),
    re.compile(r"(?:\s-(?:enc|encodedcommand)\s|FromBase64String\()", re.I),
]
_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_-]{160,}$")
SYSTEM_NAMES = {
    "sshd", "systemd", "systemd-journald", "systemd-logind", "cron", "crond", "bash", "sh", "dash", "zsh", "python3",
    "python", "perl", "nginx", "apache2", "httpd", "dbus-daemon", "rsyslogd", "udevd", "init", "login", "getty",
    "agetty", "ssh-agent", "gpg-agent", "dockerd", "containerd", "chronyd", "ntpd", "NetworkManager", "snapd", "cupsd",
}  # fmt: skip
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/nix/", "/run/", "/etc/", "/proc/")
PRIV_TOOLS = {"sudo", "su", "pkexec", "doas", "runuser"}
SCAN_TOOLS = {
    "nmap", "masscan", "zmap", "hping3", "nikto", "sqlmap", "hydra", "medusa", "gobuster", "ffuf", "dirb", "wfuzz",
    "john", "hashcat", "responder", "chisel", "ngrok", "frpc", "frps", "proxychains", "proxychains4", "socat", "nc",
    "ncat", "netcat",
}  # fmt: skip


def _has_redaction(h: dict) -> bool:
    if REDACT_MARK in (h.get("path") or ""):
        return True
    if any(REDACT_MARK in str(v) for _, v in h.get("req_headers") or []):
        return True
    body = str((h.get("req_body") or {}).get("text") or "")
    return REDACT_MARK in body or REDACT_MARK_URLENCODED in body  # form bodies carry their tags URL-encoded


class _Rules:
    """One pass of rules over a model. Each method is one family of rules; they run in a fixed order and append to
    `out`, which `find` sorts and numbers at the end."""

    def __init__(self, model: dict):
        self.model = model
        self.procs = {p["id"]: p for p in model["processes"]}
        self.events = model["events"]
        self.ev_by_id = {e["id"]: e for e in self.events}
        self.execs = [e for e in self.events if e["kind"] == "exec"]
        self.out: list[dict] = []

    def add(
        self,
        rule: str,
        severity: str,
        category: str,
        title: str,
        why: str,
        evidence: list[str],
        extra_procs=(),
        detail="",
    ):
        ev_by_id = self.ev_by_id
        procs_ = []
        for eid in evidence:
            p = ev_by_id.get(eid, {}).get("proc")
            if p and p not in procs_:
                procs_.append(p)
        for p in extra_procs:
            if p and p not in procs_:
                procs_.append(p)
        t = min([ev_by_id[e]["t"] for e in evidence if e in ev_by_id] or [0])
        self.out.append(
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

    def name_of(self, proc_id: str | None) -> str:
        return self.procs[proc_id]["name"] if proc_id in self.procs else "unknown process"

    def why_of(self, rule: str) -> str:
        c = CATALOG[rule]
        return c[
            "meaning"
        ]  # what it cannot tell you, benign look-alikes and how to check are in the rule's catalog entry

    def cmd_of(self, x: dict) -> str:
        return " ".join(x["detail"].get("argv") or [])

    def cap(self, rule: str, hits: list) -> list:
        if len(hits) > PER_RULE_CAP:
            self.add(
                rule, "info", CATALOG[rule]["category"], f"... and {len(hits) - PER_RULE_CAP} more ({rule})",
                "Only the first %d are listed individually." % PER_RULE_CAP, [h["id"] for h in hits[PER_RULE_CAP : PER_RULE_CAP + 50]],
            )  # fmt: skip
        return hits[:PER_RULE_CAP]

    def file_rules(self) -> None:
        """drop-and-execute, execution from a staging directory, credential file access."""
        add = self.add
        name_of = self.name_of
        events = self.events
        execs = self.execs
        writes = [
            e
            for e in events
            if e["kind"] == "file"
            and e["detail"]["mode"] in ("create", "write")
            and e["detail"]["category"] == "staging"
        ]
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

    def proxy_rules(self) -> None:
        """Connections that bypassed the proxy, and clients that refused its certificate."""
        add = self.add
        model = self.model
        events = self.events
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
                detail=pl(u["count"], "connection"),
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
                [h["event"] for h in model["http"] if h["event"] and h.get("tls_refused") and h["host"] == r["host"]][
                    :50
                ],
                detail=pl(r["count"], "connection") + (f": {r['error']}" if r.get("error") else ""),
            )

    def http_rules(self) -> None:
        """Per-request rules: cleartext credentials, TLS failures, raw IPs, large uploads; credentials per host."""
        add = self.add
        model = self.model
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
                f"Credentials seen in {pl(len(evs), 'request')} to {host}",
                "Requests carried secrets (redacted in this recording). Over TLS this is normal for authenticated APIs.",
                evs[:50],
            )

    def websocket_rules(self) -> None:
        """Websockets that did not close cleanly."""
        add = self.add
        model = self.model
        events = self.events
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

    def process_event_rules(self) -> None:
        """Secrets on a command line, and processes ended by a signal."""
        add = self.add
        name_of = self.name_of
        events = self.events
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

    def inline_code_rules(self) -> None:
        """Code handed to a shell or interpreter on its command line (info; capped)."""
        add = self.add
        name_of = self.name_of
        execs = self.execs
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

    def pipe_to_shell_rules(self) -> None:
        """A download piped straight into a shell or interpreter."""
        add = self.add
        name_of = self.name_of
        why_of = self.why_of
        cmd_of = self.cmd_of
        cap = self.cap
        execs = self.execs
        for x in cap("pipe-to-shell", [x for x in execs if any(r.search(cmd_of(x)) for r in PIPE_TO_SHELL)]):
            add("pipe-to-shell", "medium", "execution", f"Download piped into an interpreter ({name_of(x['proc'])})",
                why_of("pipe-to-shell"), [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip

    def reverse_shell_rules(self) -> None:
        """Command lines shaped like a reverse shell."""
        add = self.add
        name_of = self.name_of
        why_of = self.why_of
        cmd_of = self.cmd_of
        cap = self.cap
        execs = self.execs
        for x in cap("reverse-shell-shape", [x for x in execs if any(r.search(cmd_of(x)) for r in REVERSE_SHELL)]):
            add("reverse-shell-shape", "high", "execution", f"Command line shaped like a reverse shell ({name_of(x['proc'])})",
                why_of("reverse-shell-shape"), [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip

    def encoded_payload_rules(self) -> None:
        """Encoded or obfuscated code passed to an interpreter."""
        add = self.add
        name_of = self.name_of
        why_of = self.why_of
        cmd_of = self.cmd_of
        cap = self.cap
        execs = self.execs
        enc = []
        for x in execs:
            c, argv = cmd_of(x), x["detail"].get("argv") or []
            opaque = any(_OPAQUE.match(a) for a in argv[1:]) and any(f in argv[1:3] for f in ("-c", "-e", "-r", "-enc"))
            if opaque or any(r.search(c) for r in ENCODED):
                enc.append(x)
        for x in cap("encoded-payload", enc):
            add("encoded-payload", "medium", "evasion", f"Encoded code passed to an interpreter ({name_of(x['proc'])})",
                why_of("encoded-payload"), [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip

    def masquerade_rules(self) -> None:
        """A program posing as another."""
        add = self.add
        name_of = self.name_of
        why_of = self.why_of
        cmd_of = self.cmd_of
        cap = self.cap
        execs = self.execs
        for x in cap("masquerade", [x for x in execs if _masquerade(x["detail"])]):
            why, sev = _masquerade(x["detail"])
            add("masquerade", sev, "evasion", f"{name_of(x['proc'])} pretends to be something else", why_of("masquerade") + " " + why,
                [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip

    def privilege_rules(self) -> None:
        """sudo/su/pkexec/doas, and a root process under a non-root parent."""
        add = self.add
        why_of = self.why_of
        cmd_of = self.cmd_of
        execs = self.execs
        procs = self.procs
        tool_procs: set[str] = set()
        for x in execs:
            nm = os.path.basename((x["detail"].get("argv") or [""])[0]).lstrip("-")
            if nm in PRIV_TOOLS:
                tool_procs.add(x["proc"])
                root = procs.get(x["proc"], {}).get("uid") == 0
                add("privilege-change", "medium" if root else "low", "privilege",
                    f"Privilege elevation {'gained' if root else 'attempted'}: {nm}", why_of("privilege-change"), [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip
        for x in execs:
            p = procs.get(x["proc"])
            par = procs.get(p["parent"]) if p and p.get("parent") else None
            if not p or not par or x["proc"] in tool_procs or p.get("uid") != 0 or par.get("uid") in (0, None):
                continue
            anc, seen = par, set()
            while anc and anc["id"] not in seen:  # the root child of a flagged sudo is the expected consequence
                if anc["id"] in tool_procs:
                    break
                seen.add(anc["id"])
                anc = procs.get(anc["parent"]) if anc.get("parent") else None
            if anc and anc["id"] in tool_procs:
                continue
            add("privilege-change", "medium", "privilege", f"Root process started by a non-root parent: {p['name']}",
                why_of("privilege-change"), [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip

    def scanner_rules(self) -> None:
        """Scanning, brute-force and tunnelling tools."""
        add = self.add
        name_of = self.name_of
        why_of = self.why_of
        cmd_of = self.cmd_of
        cap = self.cap
        execs = self.execs
        scans = []
        for x in execs:
            argv = x["detail"].get("argv") or [""]
            nm = os.path.basename(argv[0]).lstrip("-")
            tun = nm == "ssh" and any(
                a in ("-R", "-D", "-w") or (a[:2] in ("-R", "-D") and len(a) > 2 and a[2].isdigit()) for a in argv[1:]
            )
            if nm in SCAN_TOOLS or tun:
                scans.append(x)
        for x in cap("scanner-or-tunnel-tool", scans):
            add("scanner-or-tunnel-tool", "medium", "network", f"Scanning or tunnelling tool run: {name_of(x['proc'])}",
                why_of("scanner-or-tunnel-tool"), [x["id"]], detail=cmd_of(x)[:200])  # fmt: skip

    def outcome_rules(self) -> None:
        """Non-zero exits, and processes cut off from the target tree."""
        add = self.add
        name_of = self.name_of
        events = self.events
        procs = self.procs
        bad_exit = [e for e in events if e["kind"] == "exit" and e["detail"].get("code") not in (0, None)]
        if bad_exit:
            add(
                "nonzero-exit",
                "info",
                "reliability",
                f"{pl(len(bad_exit), 'process', 'processes')} exited with a non-zero status",
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

    def recording_rules(self) -> None:
        """The recording itself: integrity, and what was redacted."""
        add = self.add
        model = self.model
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
                f"{pl(total, 'secret value')} {'was' if total == 1 else 'were'} redacted from this recording",
                "Credentials, tokens and passwords seen in traffic or command lines were replaced by keyed tags before "
                "anything was written.",
                [],
                detail=", ".join(f"{k} x{v}" for k, v in sorted(kinds.items())),
            )

    def result(self) -> list[dict]:
        out = self.out
        out.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["t"], f["rule"]))
        for i, f in enumerate(out, 1):
            f["id"] = f"f{i}"
        return out


def find(model: dict) -> list[dict]:
    r = _Rules(model)
    r.file_rules()
    r.proxy_rules()
    r.http_rules()
    r.websocket_rules()
    r.process_event_rules()
    r.inline_code_rules()
    r.pipe_to_shell_rules()
    r.reverse_shell_rules()
    r.encoded_payload_rules()
    r.masquerade_rules()
    r.privilege_rules()
    r.scanner_rules()
    r.outcome_rules()
    r.recording_rules()
    return r.result()


def _masquerade(d: dict):
    """(explanation, severity) when this exec looks like a program posing as another, else None."""
    argv, exe = d.get("argv") or [], d.get("exe") or ""
    if not argv or not exe:
        return None
    base, a0 = os.path.basename(exe), os.path.basename(argv[0]).lstrip("-")
    if exe.startswith(STAGING) and base in SYSTEM_NAMES:
        return f"{exe} runs from a temporary directory under the name of a system program.", "high"
    if exe.startswith(SYSTEM_DIRS):
        if re.fullmatch(r"\[[^\]]+\]", argv[0]):
            return f"argv[0] is {argv[0]!r}, a kernel-thread style name, but this is {exe}.", "medium"
        return None
    norm = lambda n: re.sub(r"[\d.]+$", "", n)  # noqa: E731 - python3 / python3.12 / python are the same program
    if a0 in SYSTEM_NAMES and norm(a0) != norm(base) and base != "busybox":
        return f"argv[0] claims {a0!r} but the executable is {exe}.", "medium"
    return None


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
