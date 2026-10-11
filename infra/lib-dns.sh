#!/usr/bin/env bash
# infra/lib-dns.sh — name-based domain helpers (LOCAL_DNS=true), sourced by
# deploy-infra.sh.
#
#   hosts_block NAME... IP   write the managed /etc/hosts block mapping each NAME
#                            to IP; with no arguments, remove the block. sudo
#                            only when the file actually changes.
#   dns_query SERVER NAME    print the first A record SERVER returns for NAME;
#                            non-zero when there is none. Plain python3 UDP:
#                            clean Ubuntu has no dig/nslookup.
#
# Why /etc/hosts as well as the name-dns server: this machine has to resolve
# keycloak.<domain> & co. during its own deploy (wait_for_http, health checks,
# the edge wizard's OIDC discovery), before the Tailscale split DNS setting,
# which needs a person in the admin console, exists.

_HOSTS_BEGIN="# BEGIN medcea-platform (managed by deploy-infra.sh — do not edit)"
_HOSTS_END="# END medcea-platform"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"

hosts_block() {
    local tmp ip
    tmp="$(mktemp)" || return 1
    awk -v b="$_HOSTS_BEGIN" -v e="$_HOSTS_END" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip' "$HOSTS_FILE" > "$tmp"
    if [[ $# -gt 0 ]]; then
        ip="${!#}"
        { echo "$_HOSTS_BEGIN"
          for name in "${@:1:$#-1}"; do printf '%s\t%s\n' "$ip" "$name"; done
          echo "$_HOSTS_END"; } >> "$tmp"
    fi
    if ! cmp -s "$tmp" "$HOSTS_FILE"; then
        # cp onto the existing file keeps its owner and mode.
        if [[ -w "$HOSTS_FILE" ]]; then
            cp "$tmp" "$HOSTS_FILE"
        else
            sudo -p "[sudo] password for %u (to update $HOSTS_FILE): " cp "$tmp" "$HOSTS_FILE"
        fi
    fi
    rm -f "$tmp"
}

dns_query() {
    python3 - "$1" "$2" <<'PYEOF'
import random, socket, struct, sys
server, name = sys.argv[1], sys.argv[2].rstrip(".")
qid = random.randint(0, 0xFFFF)
query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
query += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
query += struct.pack(">HH", 1, 1)                      # QTYPE A, QCLASS IN
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(query, (server, 53))
    data, _ = s.recvfrom(1500)
except OSError:
    sys.exit(2)
if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
    sys.exit(2)
answers = struct.unpack(">H", data[6:8])[0]
i = 12
while data[i]:                                         # skip the question name
    i += data[i] + 1
i += 5
for _ in range(answers):
    if data[i] & 0xC0 == 0xC0:                         # compressed name pointer
        i += 2
    else:
        while data[i]:
            i += data[i] + 1
        i += 1
    rtype, _cls, _ttl, rlen = struct.unpack(">HHIH", data[i:i + 10])
    i += 10
    if rtype == 1 and rlen == 4:
        print(".".join(str(b) for b in data[i:i + 4]))
        sys.exit(0)
    i += rlen
sys.exit(1)
PYEOF
}
