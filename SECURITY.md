# Security notes

tracewatch is an experiment. Please read this before running it.

## It runs a privileged container

Kernel tracing uses [Tracee](https://github.com/aquasecurity/tracee) in a Docker container started with `--privileged`
and the host PID namespace. That is what lets it see processes, and it also means that container has broad access to the
machine. Only run tracewatch on a machine where that is acceptable, and review `src/tracewatch/tracee.py` first.

## It intercepts HTTPS on purpose

The target's HTTPS traffic is decrypted by an intercepting proxy using a CA created for each run (the CA's private key is
deleted when the run ends). The proxy is only used by programs that honour the proxy and CA environment variables.
tracewatch does not install the CA system-wide.

## Recordings and reports contain sensitive data

A run directory holds the command lines and the (redacted) requests and responses of whatever you recorded. Redaction is
pattern-based and will miss some secrets. Run directories and the reports built from them are written readable by you
only; **treat them as private and do not publish them**. The example reports in `docs/` were built from sanitized copies
of throw-away recordings (placeholders for paths, names and IP addresses), and each file is checked before it is written.

## The simulated intruder is harmless

`tests/fixtures/badactor.sh` simulates an attacker's session so the detection rules can be exercised: a reverse-shell-shaped
command, obfuscated payloads, `curl | sh`, a process named like a system daemon. Everything stays on the local machine
(a loopback listener and a local web server play the attacker), the credentials are decoys, and every payload only
prints a line of text. Do not point it at anything else.

## The report treats the recording as hostile

The HTML report is built so that attacker-controlled text in a recording (command lines, URLs, headers, bodies) cannot
become markup or script: text-only DOM construction, an escaped embedded data block, and a Content-Security-Policy that
forbids network access and unlisted scripts. These properties have tests. If you find a way around them, that is the kind
of report worth sending.

## Reporting a problem

If the repository is public, please use GitHub's private vulnerability reporting (the repository's **Security** tab,
**Report a vulnerability**) instead of opening a public issue. This is a hobby project, so there is no response-time
promise.
