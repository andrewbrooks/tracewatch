"""The finding dictionary: one place that says what every rule means, what it cannot know, what benign activity looks
the same, and how much evidence stands behind it.

`status`:
  observed   fired on at least one real recording made by this project
  synthetic  implemented and unit-tested on fabricated events, never seen on a real run
Severities are the author's heuristic estimates of how much attention something deserves; they are not calibrated
against real incidents and say nothing about intent."""

from __future__ import annotations

STATUSES = ("observed", "synthetic")
CATEGORIES = ("execution", "credential", "exposure", "network", "integrity", "reliability", "evasion", "privilege")

_R = {}


def rule(id, title, category, severity, status, meaning, cannot_know, benign, check, note=""):
    _R[id] = {
        "id": id, "title": title, "category": category, "severity": severity, "status": status,
        "note": note, "meaning": meaning, "cannot_know": cannot_know, "benign": benign, "check": check,
    }  # fmt: skip


# ------------------------------------------------------------------------------------------------ execution
rule(
    "drop-and-execute",
    "File written, then executed",
    "execution",
    "high",
    "observed",
    "A process created a file in a temporary directory and a process then executed that exact path.",
    "Whether the file was fetched, generated, or copied, and whether it is malicious.",
    ["build tools and installers that unpack a helper to /tmp and run it", "test suites"],
    "Open the two cited events; read the writer's command line and where the content came from (an HTTP request just before?).",
)
rule(
    "exec-from-staging",
    "Executed from a temporary directory",
    "execution",
    "medium",
    "synthetic",
    "A program was started from /tmp, /var/tmp or /dev/shm instead of a system or application directory.",
    "Who put it there, or why.",
    ["installers, language package managers, CI runners"],
    "Look for the process that created the file; check the cited exec's parent and arguments.",
)
rule(
    "inline-code",
    "Inline code run through an interpreter",
    "execution",
    "info",
    "observed",
    "A shell or interpreter was given code on its command line (-c, -e, -r).",
    "What the code does; only its text is visible, and secrets in it are redacted.",
    ["almost every build script and installer", "one-liners typed by a person"],
    "Read the command line in the drawer; it is rarely interesting alone, mostly context for other findings.",
)
rule(
    "detached-process",
    "Process not connected to the target's tree",
    "execution",
    "low",
    "synthetic",
    "A process in the recording has no recorded parent, e.g. its parent exited first and it was re-parented.",
    "Whether it was meant to outlive the command (a daemon) or escaped by accident.",
    ["daemons and background helpers started by tools such as ssh-agent or docker"],
    "Check its start time against the root's exit; look at what it did afterwards.",
)
rule(
    "nonzero-exit",
    "Processes exited with a non-zero status",
    "reliability",
    "info",
    "observed",
    "One or more processes finished with a failure status.",
    "Why; a non-zero status is often a normal answer (grep found nothing).",
    ["grep, diff, test, and probing commands that use the exit code as an answer"],
    "Open the listed processes and see whether anything depended on them succeeding.",
)
rule(
    "killed-by-signal",
    "Process ended by a signal",
    "reliability",
    "low",
    "observed",
    "A process was terminated by a signal (crash signals such as SIGSEGV are rated higher).",
    "Whether another process sent it or the kernel did.",
    ["timeouts and orderly shutdowns (SIGTERM/SIGKILL)"],
    "For crash signals, look at the arguments and the last events before it ended.",
)
rule(
    "pipe-to-shell",
    "Download piped into an interpreter",
    "execution",
    "medium",
    "observed",
    "A command line downloads with curl/wget and feeds the result straight to a shell or interpreter "
    '(`curl ... | sh`, `sh <(curl ...)`, `sh -c "$(curl ...)"`). The downloaded code is run unread.',
    "What was downloaded: the proxy shows the response, but the command line alone cannot say it was the script.",
    ["official installers (rustup, nvm, Homebrew, Docker convenience script) are distributed exactly this way"],
    "Find the matching HTTP request in the same process tree and read the response body; check the host is the one you expect.",
)
rule(
    "reverse-shell-shape",
    "Command line shaped like a reverse shell",
    "execution",
    "high",
    "observed",
    "The arguments match well-known reverse-shell one-liners: bash -i with /dev/tcp redirection, netcat or socat "
    "executing a shell, mkfifo+nc relays, or an interpreter that wires a socket to a shell.",
    "Whether a shell really connected, to whom, and whether anyone used it. Only the command line is judged.",
    ["rare in normal work; admin and CTF tooling, or a test that deliberately demonstrates one"],
    "Check the TCP connect events of the same process tree for the destination; check the destination host.",
)
rule(
    "encoded-payload",
    "Encoded or obfuscated code passed to an interpreter",
    "evasion",
    "medium",
    "observed",
    "A command line decodes base64/hex/rot13/gzip data and runs it (`base64 -d | sh`, `eval(base64_decode(...))`, "
    "`exec(b64decode(...))`), or hands a long opaque blob to an interpreter.",
    "What the decoded code does. The redacted recording keeps the encoded text, which you can decode yourself.",
    [
        "configuration management and some installers embed scripts this way",
        "base64-encoded credentials passed to tools",
    ],
    "Decode the blob from the command line and read it. If it only echoes or sets a variable it is likely harmless.",
)
rule(
    "masquerade",
    "Process pretending to be something else",
    "evasion",
    "high",
    "observed",
    "A program with a system-tool name (sshd, cron, bash, ...) runs from a temporary directory, or its argv[0] "
    "claims a system name or kernel-thread style name that does not match the executable it really is.",
    "Intent. Some tools legitimately rewrite their process title.",
    ["multi-call binaries (busybox), launchers that set argv[0] on purpose, test fixtures"],
    "Compare the cited executable path with the name shown; check where the executable came from.",
)
rule(
    "privilege-change",
    "Privilege elevation attempted or gained",
    "privilege",
    "medium",
    "observed",
    "sudo, su, pkexec, doas or runuser was run, or a process running as root was started by a non-root parent.",
    "Whether the elevation succeeded unless the child process shows uid 0; what the elevated command was.",
    ["installers and admin scripts that call sudo", "container entrypoints"],
    "Open the cited process: is its uid 0, and what did it run afterwards?",
    note="Observed only as an attempt (a failed `sudo -n`, low severity). Root gained, and a root process under a non-root "
    "parent, have only been exercised on fabricated events.",
)
rule(
    "scanner-or-tunnel-tool",
    "Scanning, brute-force or tunnelling tool run",
    "network",
    "medium",
    "observed",
    "A program built for port scanning, credential guessing, or tunnelling/relaying traffic was executed "
    "(nmap, masscan, hydra, chisel, ngrok, socat, netcat, ssh -R/-D, ...).",
    "What it was pointed at, unless the arguments say; whether it succeeded.",
    ["network debugging by an administrator", "netcat as a simple port probe or file transfer"],
    "Read its arguments and the TCP connects made by the same process.",
)
# ------------------------------------------------------------------------------------------------ credentials
rule(
    "credential-file-access",
    "Credential file opened",
    "credential",
    "high",
    "observed",
    "A process opened a file on the credential watch list (SSH keys, cloud credentials, .netrc, .env, private keys).",
    "What it did with the contents. Reads by known clients (ssh, git, aws) are listed at low severity.",
    ["ssh, git, aws, kubectl and other clients that need the credentials they were asked to use"],
    "Is this program supposed to read that file? Look at what it connected to next.",
)
rule(
    "secret-in-command-line",
    "Secret passed on a command line",
    "credential",
    "medium",
    "observed",
    "A password, token or key was given as a command-line argument.",
    "Whether it was a real secret (the value is redacted in this recording).",
    ["quick scripts and examples; common but poor practice"],
    "Other local users can read command lines through /proc and shell history keeps them: prefer env vars or stdin.",
)
# ------------------------------------------------------------------------------------------------ exposure / network
rule(
    "cleartext-credentials",
    "Credentials over plain HTTP",
    "exposure",
    "high",
    "observed",
    "A request on unencrypted HTTP carried an Authorization header, password or token.",
    "Whether anyone was positioned to read it.",
    ["local development servers on loopback"],
    "Check the destination: loopback is low risk, anything remote is not.",
)
rule(
    "credentials-in-requests",
    "Credentials seen in requests",
    "exposure",
    "info",
    "observed",
    "Requests over TLS carried credentials (they were redacted in this recording).",
    "Whether they were valid or belonged to the user.",
    ["any authenticated API call"],
    "Informational: confirms the recorder saw and redacted secrets for those hosts.",
)
rule(
    "unproxied-connection",
    "Connection bypassed the proxy",
    "network",
    "medium",
    "observed",
    "A process opened a TCP connection that did not go through the recorder's proxy, so its content was not recorded.",
    "What was sent. The kernel trace shows only that the connection happened.",
    ["clients that ignore proxy settings, or hosts matched by NO_PROXY"],
    "Check the destination and the process; this is also what hiding traffic from an inspecting proxy looks like.",
)
rule(
    "tls-client-rejected",
    "Client refused the recorder's certificate",
    "network",
    "medium",
    "observed",
    "A process aborted the TLS handshake with the recorder's proxy (certificate pinning, or it does not trust the CA).",
    "What it sent. Its traffic was not recorded.",
    ["any client that pins certificates or ignores the per-run CA"],
    "Treat the destination as unrecorded; consider whether pinning is expected for that program.",
)
rule(
    "tls-verification-failure",
    "Upstream TLS verification failed",
    "network",
    "medium",
    "observed",
    "The proxy could not verify the server's certificate (expired, self-signed, wrong name, untrusted issuer).",
    "Whether it was a misconfiguration or an interception attempt.",
    ["test servers with self-signed certificates", "expired certificates"],
    "Read the error in the request detail and check the host's certificate independently.",
)
rule(
    "raw-ip-destination",
    "Request to a raw IP address",
    "network",
    "low",
    "synthetic",
    "A request used an IP literal, so there is no DNS record and no certificate name to check.",
    "Why a name was not used.",
    ["health checks, internal services, cloud metadata endpoints"],
    "Look at what was requested and whether the address is one you recognise.",
)
rule(
    "large-upload",
    "Large upload",
    "network",
    "low",
    "observed",
    "A request body of 1 MiB or more was sent.",
    "What it contained: bodies past the size cap are not stored.",
    ["backups, artifact uploads, telemetry"],
    "Check the destination and whether the process is expected to send data out.",
)
rule(
    "websocket-abnormal-close",
    "Websocket closed abnormally",
    "reliability",
    "low",
    "observed",
    "A websocket ended without a close handshake.",
    "Whether the peer crashed, the network dropped, or something cut it.",
    ["network hiccups, servers that drop connections"],
    "Look at the close code and the last messages.",
)
# ------------------------------------------------------------------------------------------------ the recording
rule(
    "recording-integrity",
    "The recording is incomplete or lossy",
    "integrity",
    "medium",
    "observed",
    "A component of the recorder died, a cap was hit, or traffic bypassed the proxy, so parts of the activity are missing.",
    "What happened in the gaps.",
    ["a size cap on a chatty run"],
    "Read the reasons on the Run tab; conclusions from this report may be incomplete.",
)
rule(
    "secrets-redacted",
    "Secrets were redacted",
    "exposure",
    "info",
    "observed",
    "Credentials, tokens and passwords were replaced by keyed tags before anything was written.",
    "Whether redaction caught everything: it is pattern-based.",
    ["any run that handles credentials"],
    "Informational: the counts show what kinds of secrets passed through.",
)

CATALOG = _R
