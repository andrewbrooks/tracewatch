#!/bin/bash
# A target that writes files on watched paths (and deletes some), and READS a credential file it did not write.
# usage: filecontent_workload.sh CREDENTIAL_FILE
CRED=$1
D=/tmp/tw_fc_work_$$
mkdir -p "$D"
# a "dropper": written, executed, deleted; carries a bearer token that must come out redacted
printf '#!/bin/sh\necho dropper ran\n# token: Bearer abcdefghijklmnop1234567890\n' > "$D/dropper.sh"
chmod +x "$D/dropper.sh"
"$D/dropper.sh"
rm -f "$D/dropper.sh"
# hostile text: an escape sequence that sets the terminal title and clears the screen, a bell, a right-to-left override
printf 'line one\033]0;pwned\007\033[2Jline two \342\200\256gnp.exe\n</script><img src=x onerror=alert(1)>\n' > "$D/notes.txt"
# a binary
head -c 3000 /dev/urandom > "$D/blob.bin"
# only READ: must never be captured
cat "$CRED" > /dev/null
sleep 0.5
rm -rf "$D"
