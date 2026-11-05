# tracewatch report: `out/showcase/session.sh`

**Verdict: LOSSES** (complete-with-losses). Run `showcase`, started 2026-11-05 02:17:02 UTC (wall clock, approximate), duration 1.78 s, target exited 0.

- 1 connection to 1 destination bypassed the proxy: content not recorded

| Processes | Commands | Destinations | HTTP | WebSockets | DNS names | Watched files | High | Medium | Low | Info |
|---|---|---|---|---|---|---|---|---|---|---|
| 12 | 12 | 6 | 8 | 0 | 5 | 0 | 0 | 3 | 0 | 4 |

## Findings

_Indicators to judge, not verdicts: each cites the evidence it rests on._

|  | Rule | Finding | Process | At |
|---|---|---|---|---|
| [MED]  | `recording-integrity` | The recording is complete with losses | — | +0.000s |
| [MED]  | `secret-in-command-line` | Secret passed on the command line: curl | curl (3229239) | +0.722s |
| [MED]  | `unproxied-connection` | Connection bypassed the proxy: 203.0.113.10:443 | curl (3229262) | +1.411s |
| [info] | `secrets-redacted` | 8 secret values were redacted from this recording | — | +0.000s |
| [info] | `credentials-in-requests` | Credentials seen in 1 request to httpbin.org | curl (3229239) | +0.819s |
| [info] | `nonzero-exit` | 2 processes exited with a non-zero status | python3 (3229258) | +1.394s |
| [info] | `inline-code` | Inline code run through sh | sh (3229264) | +1.492s |

- **[MED] The recording is complete with losses**: Conclusions drawn from this report may be missing activity. _1 connection to 1 destination bypassed the proxy: content not recorded_
- **[MED] Secret passed on the command line: curl**: Command-line arguments can be read by other local users through /proc (unless the system hides them) and end up in shell history and logs.
- **[MED] Connection bypassed the proxy: 203.0.113.10:443**: This process opened a TCP connection that did not go through the recorder's proxy (it ignored the proxy settings, or NO\_PROXY matched). The kernel trace shows the connection; its content was NOT recorded. _1 connection_

## Process tree

```text
bash [3229040] +0.000s → +1.781s exited 0
   $ /bin/bash /home/dev/project/out/showcase/session.sh
├─ curl [3229229] +0.002s → +0.081s exited 0
│     $ curl -s -o /dev/null https://example.com/
├─ curl [3229231] +0.081s → +0.418s exited 0
│     $ curl -s -o /dev/null https://api.github.com/zen
├─ curl [3229235] +0.419s → +0.720s exited 0
│     $ curl -s -o /dev/null --compressed https://httpbin.org/json
├─ curl [3229239] +0.721s → +0.903s exited 0  <== MEDIUM
│     $ curl -s -o /dev/null -X POST https://httpbin.org/post -H 'Authorization: Bearer [REDACTED:bearer:82d…
├─ git [3229246] +0.903s → +1.255s exited 0
│     $ git ls-remote --heads https://github.com/git/git master
│  └─ git [3229247] +0.904s → +1.255s exited 0
│        $ /usr/lib/git-core/git remote-https https://github.com/git/git https://github.com/git/git
│     └─ git-remote-https [3229248] +0.905s → +1.254s exited 0
│           $ /usr/lib/git-core/git-remote-https https://github.com/git/git https://github.com/git/git
├─ python3 [3229258] +1.255s → +1.394s exited 1
│     $ python3 -
├─ curl [3229262] +1.394s → +1.490s exited 0  <== MEDIUM
│     $ curl -s -o /dev/null https://example.com/
└─ sh [3229264] +1.492s → +1.781s exited 2
      $ sh -c 'curl -s -o /dev/null https://api.github.com/octocat; exit 2'
   └─ curl [3229265] +1.493s → +1.780s exited 0
         $ curl -s -o /dev/null https://api.github.com/octocat
```

## Network destinations

| Via | Destination | Port | Requests | Errors | In | Out | TLS |
|---|---|---|---|---|---|---|---|
| **DIRECT (not recorded)** | `example.com` | 443 | 1 | 0 | 0 B | 0 B | — |
| proxy | `api.github.com` | 443 | 2 | 0 | 952 B | 0 B | TLSv1.3 h2 |
| proxy | `github.com` | 443 | 2 | 0 | 687 B | 129 B | TLSv1.3 h2 |
| proxy | `httpbin.org` | 443 | 2 | 0 | 906 B | 42 B | TLSv1.3 h2 |
| proxy | `example.com` | 443 | 1 | 0 | 577 B | 0 B | TLSv1.3 h2 |
| proxy | `example.org` | 443 | 1 | 1 | 17 B | 0 B | TLSv1.3 http/1.1 |

## HTTP requests

| At | Process | Method | URL | Status | Size | Time |
|---|---|---|---|---|---|---|
| +0.067s | curl (3229229) | GET | `https://example.com/` | 200 | 577 B | 13 ms |
| +0.341s | curl (3229231) | GET | `https://api.github.com/zen` | 200 | 43 B | 78 ms |
| +0.631s | curl (3229235) | GET | `https://httpbin.org/json` | 200 | 429 B | 89 ms |
| +0.819s | curl (3229239) | POST | `https://httpbin.org/post` | 200 | 477 B | 84 ms |
| +1.114s | git-remote-https (3229248) | GET | `https://github.com/git/git/info/refs?service=git-upload-pack` | 200 | 191 B | 62 ms |
| +1.177s | git-remote-https (3229248) | POST | `https://github.com/git/git/git-upload-pack` | 200 | 496 B | 76 ms |
| +1.347s | python3 (3229258) | GET | `https://example.org/` | 403 | 17 B | 13 ms |
| +1.619s | curl (3229265) | GET | `https://api.github.com/octocat` | 200 | 909 B | 160 ms |

## DNS and name resolution

_Names the proxy resolved are exact. For lookups a process makes itself, only the resolver contact is visible, not the name._

| Name | Address(es) | Ports | Lookups | Processes |
|---|---|---|---|---|
| `api.github.com` | `203.0.113.11` | 443 | 2 | curl (3229231), curl (3229265) |
| `httpbin.org` | `203.0.113.12, 203.0.113.13` | 443 | 2 | curl (3229235), curl (3229239) |
| `example.com` | `203.0.113.10` | 443 | 1 | curl (3229229) |
| `example.org` | `203.0.113.16` | 443 | 1 | python3 (3229258) |
| `github.com` | `203.0.113.14` | 443 | 1 | git-remote-https (3229248) |

| Process | Resolver contacted | Times | First |
|---|---|---|---|
| curl (3229262) | `nscd` | 4 | +1.397s |
| curl (3229229) | `nscd` | 2 | +0.007s |
| curl (3229231) | `nscd` | 2 | +0.084s |
| curl (3229235) | `nscd` | 2 | +0.422s |
| curl (3229239) | `nscd` | 2 | +0.725s |
| python3 (3229258) | `nscd` | 2 | +1.282s |
| curl (3229265) | `nscd` | 2 | +1.497s |
| python3 (3229258) | `192.0.2.10:53` | 1 | +1.283s |
| curl (3229262) | `192.0.2.10:53` | 1 | +1.397s |

_8 UDP connect() calls right after a lookup are address-selection probes (no traffic)._

## Commands

| At | PID | Parent | Command |
|---|---|---|---|
| +0.000s | 3229040 | — | `/bin/bash /home/dev/project/out/showcase/session.sh` |
| +0.002s | 3229229 | bash (3229040) | `curl -s -o /dev/null https://example.com/` |
| +0.081s | 3229231 | bash (3229040) | `curl -s -o /dev/null https://api.github.com/zen` |
| +0.419s | 3229235 | bash (3229040) | `curl -s -o /dev/null --compressed https://httpbin.org/json` |
| +0.721s | 3229239 | bash (3229040) | `curl -s -o /dev/null -X POST https://httpbin.org/post -H 'Authorization: Bearer [REDACTED:bearer:82db8e13]' -d 'user=alice&password=[REDACTED:kv:1edcd616]'` |
| +0.903s | 3229246 | bash (3229040) | `git ls-remote --heads https://github.com/git/git master` |
| +0.904s | 3229247 | git (3229246) | `/usr/lib/git-core/git remote-https https://github.com/git/git https://github.com/git/git` |
| +0.905s | 3229248 | git (3229247) | `/usr/lib/git-core/git-remote-https https://github.com/git/git https://github.com/git/git` |
| +1.255s | 3229258 | bash (3229040) | `python3 -` |
| +1.394s | 3229262 | bash (3229040) | `curl -s -o /dev/null https://example.com/` |
| +1.492s | 3229264 | bash (3229040) | `sh -c 'curl -s -o /dev/null https://api.github.com/octocat; exit 2'` |
| +1.493s | 3229265 | sh (3229264) | `curl -s -o /dev/null https://api.github.com/octocat` |

## File activity (watched paths only)

_none recorded_

## Recording integrity

Verdict **complete-with-losses**. Clock alignment: anchors (7 anchors).


## Notes and limits

- 8 opens of the recorder's own CA bundle (loaded by TLS clients) are hidden from the file list.
- File activity covers only the watched paths (credential stores and temp directories), not every open.
- DNS query names are not visible for lookups a process makes itself; names the proxy resolved are exact.
- UDP payloads (including QUIC/HTTP3) are never recorded; a UDP connect() is shown, not its traffic.
- Redaction is heuristic: treat the underlying run directory as sensitive.

_Generated by tracewatch 0.1.0, model schema 1._
