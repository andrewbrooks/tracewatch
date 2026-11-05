# Findings reference

<!-- generated from src/tracewatch/findings_catalog.py by tools/gen_findings_doc.py: do not edit by hand -->

Every finding is an **indicator for a human to judge**, not a verdict. Each rule cites the events that triggered it.
Severities are the author's rough estimates, not measurements. The evidence status says whether the rule has ever
fired on a real recording made with this project (**observed**) or has only been tested on fabricated events
(**synthetic only**).

| Rule | Category | Default severity | Evidence |
|---|---|---|---|
| [`credential-file-access`](#credential-file-access) | credential | high | observed on a real recording |
| [`secret-in-command-line`](#secret-in-command-line) | credential | medium | observed on a real recording |
| [`encoded-payload`](#encoded-payload) | evasion | medium | observed on a real recording |
| [`masquerade`](#masquerade) | evasion | high | observed on a real recording |
| [`detached-process`](#detached-process) | execution | low | synthetic only |
| [`drop-and-execute`](#drop-and-execute) | execution | high | observed on a real recording |
| [`exec-from-staging`](#exec-from-staging) | execution | medium | synthetic only |
| [`inline-code`](#inline-code) | execution | info | observed on a real recording |
| [`pipe-to-shell`](#pipe-to-shell) | execution | medium | observed on a real recording |
| [`reverse-shell-shape`](#reverse-shell-shape) | execution | high | observed on a real recording |
| [`cleartext-credentials`](#cleartext-credentials) | exposure | high | observed on a real recording |
| [`credentials-in-requests`](#credentials-in-requests) | exposure | info | observed on a real recording |
| [`secrets-redacted`](#secrets-redacted) | exposure | info | observed on a real recording |
| [`recording-integrity`](#recording-integrity) | integrity | medium | observed on a real recording |
| [`large-upload`](#large-upload) | network | low | observed on a real recording |
| [`raw-ip-destination`](#raw-ip-destination) | network | low | synthetic only |
| [`scanner-or-tunnel-tool`](#scanner-or-tunnel-tool) | network | medium | observed on a real recording |
| [`tls-client-rejected`](#tls-client-rejected) | network | medium | observed on a real recording |
| [`tls-verification-failure`](#tls-verification-failure) | network | medium | observed on a real recording |
| [`unproxied-connection`](#unproxied-connection) | network | medium | observed on a real recording |
| [`privilege-change`](#privilege-change) | privilege | medium | observed on a real recording |
| [`killed-by-signal`](#killed-by-signal) | reliability | low | observed on a real recording |
| [`nonzero-exit`](#nonzero-exit) | reliability | info | observed on a real recording |
| [`websocket-abnormal-close`](#websocket-abnormal-close) | reliability | low | observed on a real recording |

## credential-file-access

**Credential file opened** · credential · default severity high · observed on a real recording

A process opened a file on the credential watch list (SSH keys, cloud credentials, .netrc, .env, private keys).

**It cannot tell you:** What it did with the contents. Reads by known clients (ssh, git, aws) are listed at low severity.

**Often benign when:**

- ssh, git, aws, kubectl and other clients that need the credentials they were asked to use

**How to check:** Is this program supposed to read that file? Look at what it connected to next.

## secret-in-command-line

**Secret passed on a command line** · credential · default severity medium · observed on a real recording

A password, token or key was given as a command-line argument.

**It cannot tell you:** Whether it was a real secret (the value is redacted in this recording).

**Often benign when:**

- quick scripts and examples; common but poor practice

**How to check:** Other local users can read command lines through /proc and shell history keeps them: prefer env vars or stdin.

## encoded-payload

**Encoded or obfuscated code passed to an interpreter** · evasion · default severity medium · observed on a real recording

A command line decodes base64/hex/rot13/gzip data and runs it (`base64 -d | sh`, `eval(base64_decode(...))`, `exec(b64decode(...))`), or hands a long opaque blob to an interpreter.

**It cannot tell you:** What the decoded code does. The redacted recording keeps the encoded text, which you can decode yourself.

**Often benign when:**

- configuration management and some installers embed scripts this way
- base64-encoded credentials passed to tools

**How to check:** Decode the blob from the command line and read it. If it only echoes or sets a variable it is likely harmless.

## masquerade

**Process pretending to be something else** · evasion · default severity high · observed on a real recording

A program with a system-tool name (sshd, cron, bash, ...) runs from a temporary directory, or its argv[0] claims a system name or kernel-thread style name that does not match the executable it really is.

**It cannot tell you:** Intent. Some tools legitimately rewrite their process title.

**Often benign when:**

- multi-call binaries (busybox), launchers that set argv[0] on purpose, test fixtures

**How to check:** Compare the cited executable path with the name shown; check where the executable came from.

## detached-process

**Process not connected to the target's tree** · execution · default severity low · synthetic only (tested on fabricated events)

A process in the recording has no recorded parent, e.g. its parent exited first and it was re-parented.

**It cannot tell you:** Whether it was meant to outlive the command (a daemon) or escaped by accident.

**Often benign when:**

- daemons and background helpers started by tools such as ssh-agent or docker

**How to check:** Check its start time against the root's exit; look at what it did afterwards.

## drop-and-execute

**File written, then executed** · execution · default severity high · observed on a real recording

A process created a file in a temporary directory and a process then executed that exact path.

**It cannot tell you:** Whether the file was fetched, generated, or copied, and whether it is malicious.

**Often benign when:**

- build tools and installers that unpack a helper to /tmp and run it
- test suites

**How to check:** Open the two cited events; read the writer's command line and where the content came from (an HTTP request just before?).

## exec-from-staging

**Executed from a temporary directory** · execution · default severity medium · synthetic only (tested on fabricated events)

A program was started from /tmp, /var/tmp or /dev/shm instead of a system or application directory.

**It cannot tell you:** Who put it there, or why.

**Often benign when:**

- installers, language package managers, CI runners

**How to check:** Look for the process that created the file; check the cited exec's parent and arguments.

## inline-code

**Inline code run through an interpreter** · execution · default severity info · observed on a real recording

A shell or interpreter was given code on its command line (-c, -e, -r).

**It cannot tell you:** What the code does; only its text is visible, and secrets in it are redacted.

**Often benign when:**

- almost every build script and installer
- one-liners typed by a person

**How to check:** Read the command line in the drawer; it is rarely interesting alone, mostly context for other findings.

## pipe-to-shell

**Download piped into an interpreter** · execution · default severity medium · observed on a real recording

A command line downloads with curl/wget and feeds the result straight to a shell or interpreter (`curl ... | sh`, `sh <(curl ...)`, `sh -c "$(curl ...)"`). The downloaded code is run unread.

**It cannot tell you:** What was downloaded: the proxy shows the response, but the command line alone cannot say it was the script.

**Often benign when:**

- official installers (rustup, nvm, Homebrew, Docker convenience script) are distributed exactly this way

**How to check:** Find the matching HTTP request in the same process tree and read the response body; check the host is the one you expect.

## reverse-shell-shape

**Command line shaped like a reverse shell** · execution · default severity high · observed on a real recording

The arguments match well-known reverse-shell one-liners: bash -i with /dev/tcp redirection, netcat or socat executing a shell, mkfifo+nc relays, or an interpreter that wires a socket to a shell.

**It cannot tell you:** Whether a shell really connected, to whom, and whether anyone used it. Only the command line is judged.

**Often benign when:**

- rare in normal work; admin and CTF tooling, or a test that deliberately demonstrates one

**How to check:** Check the TCP connect events of the same process tree for the destination; check the destination host.

## cleartext-credentials

**Credentials over plain HTTP** · exposure · default severity high · observed on a real recording

A request on unencrypted HTTP carried an Authorization header, password or token.

**It cannot tell you:** Whether anyone was positioned to read it.

**Often benign when:**

- local development servers on loopback

**How to check:** Check the destination: loopback is low risk, anything remote is not.

## credentials-in-requests

**Credentials seen in requests** · exposure · default severity info · observed on a real recording

Requests over TLS carried credentials (they were redacted in this recording).

**It cannot tell you:** Whether they were valid or belonged to the user.

**Often benign when:**

- any authenticated API call

**How to check:** Informational: confirms the recorder saw and redacted secrets for those hosts.

## secrets-redacted

**Secrets were redacted** · exposure · default severity info · observed on a real recording

Credentials, tokens and passwords were replaced by keyed tags before anything was written.

**It cannot tell you:** Whether redaction caught everything: it is pattern-based.

**Often benign when:**

- any run that handles credentials

**How to check:** Informational: the counts show what kinds of secrets passed through.

## recording-integrity

**The recording is incomplete or lossy** · integrity · default severity medium · observed on a real recording

A component of the recorder died, a cap was hit, or traffic bypassed the proxy, so parts of the activity are missing.

**It cannot tell you:** What happened in the gaps.

**Often benign when:**

- a size cap on a chatty run

**How to check:** Read the reasons on the Run tab; conclusions from this report may be incomplete.

## large-upload

**Large upload** · network · default severity low · observed on a real recording

A request body of 1 MiB or more was sent.

**It cannot tell you:** What it contained: bodies past the size cap are not stored.

**Often benign when:**

- backups, artifact uploads, telemetry

**How to check:** Check the destination and whether the process is expected to send data out.

## raw-ip-destination

**Request to a raw IP address** · network · default severity low · synthetic only (tested on fabricated events)

A request used an IP literal, so there is no DNS record and no certificate name to check.

**It cannot tell you:** Why a name was not used.

**Often benign when:**

- health checks, internal services, cloud metadata endpoints

**How to check:** Look at what was requested and whether the address is one you recognise.

## scanner-or-tunnel-tool

**Scanning, brute-force or tunnelling tool run** · network · default severity medium · observed on a real recording

A program built for port scanning, credential guessing, or tunnelling/relaying traffic was executed (nmap, masscan, hydra, chisel, ngrok, socat, netcat, ssh -R/-D, ...).

**It cannot tell you:** What it was pointed at, unless the arguments say; whether it succeeded.

**Often benign when:**

- network debugging by an administrator
- netcat as a simple port probe or file transfer

**How to check:** Read its arguments and the TCP connects made by the same process.

## tls-client-rejected

**Client refused the recorder's certificate** · network · default severity medium · observed on a real recording

A process aborted the TLS handshake with the recorder's proxy (certificate pinning, or it does not trust the CA).

**It cannot tell you:** What it sent. Its traffic was not recorded.

**Often benign when:**

- any client that pins certificates or ignores the per-run CA

**How to check:** Treat the destination as unrecorded; consider whether pinning is expected for that program.

## tls-verification-failure

**Upstream TLS verification failed** · network · default severity medium · observed on a real recording

The proxy could not verify the server's certificate (expired, self-signed, wrong name, untrusted issuer).

**It cannot tell you:** Whether it was a misconfiguration or an interception attempt.

**Often benign when:**

- test servers with self-signed certificates
- expired certificates

**How to check:** Read the error in the request detail and check the host's certificate independently.

## unproxied-connection

**Connection bypassed the proxy** · network · default severity medium · observed on a real recording

A process opened a TCP connection that did not go through the recorder's proxy, so its content was not recorded.

**It cannot tell you:** What was sent. The kernel trace shows only that the connection happened.

**Often benign when:**

- clients that ignore proxy settings, or hosts matched by NO_PROXY

**How to check:** Check the destination and the process; this is also what hiding traffic from an inspecting proxy looks like.

## privilege-change

**Privilege elevation attempted or gained** · privilege · default severity medium · observed on a real recording

sudo, su, pkexec, doas or runuser was run, or a process running as root was started by a non-root parent.

**It cannot tell you:** Whether the elevation succeeded unless the child process shows uid 0; what the elevated command was.

**Often benign when:**

- installers and admin scripts that call sudo
- container entrypoints

**How to check:** Open the cited process: is its uid 0, and what did it run afterwards?

*Evidence note:* Observed only as an attempt (a failed `sudo -n`, low severity). Root gained, and a root process under a non-root parent, have only been exercised on fabricated events.

## killed-by-signal

**Process ended by a signal** · reliability · default severity low · observed on a real recording

A process was terminated by a signal (crash signals such as SIGSEGV are rated higher).

**It cannot tell you:** Whether another process sent it or the kernel did.

**Often benign when:**

- timeouts and orderly shutdowns (SIGTERM/SIGKILL)

**How to check:** For crash signals, look at the arguments and the last events before it ended.

## nonzero-exit

**Processes exited with a non-zero status** · reliability · default severity info · observed on a real recording

One or more processes finished with a failure status.

**It cannot tell you:** Why; a non-zero status is often a normal answer (grep found nothing).

**Often benign when:**

- grep, diff, test, and probing commands that use the exit code as an answer

**How to check:** Open the listed processes and see whether anything depended on them succeeding.

## websocket-abnormal-close

**Websocket closed abnormally** · reliability · default severity low · observed on a real recording

A websocket ended without a close handshake.

**It cannot tell you:** Whether the peer crashed, the network dropped, or something cut it.

**Often benign when:**

- network hiccups, servers that drop connections

**How to check:** Look at the close code and the last messages.
