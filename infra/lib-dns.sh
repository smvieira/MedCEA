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
#   split_dns_target DOMAIN  print the nameserver(s) Tailscale split DNS sends
#                            DOMAIN to, one per line; nothing when there is no
#                            route or `tailscale dns status` is unavailable.
#   dns_names_check DOMAIN PLATFORM_IP NAME...
#                            does this machine resolve each NAME to PLATFORM_IP
#                            (or another address of its own)? One line per name;
#                            on failure DNS_CHECK_TODO says why and what to do,
#                            and it returns 1. Every lookup is bounded.
#
# split_dns_target exists because a rebuilt server gets a new Tailscale IP while
# the admin console keeps routing the domain to the old one: this machine still
# resolves through /etc/hosts, and every other device quietly gets no answer.
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

split_dns_target() {
    command -v tailscale >/dev/null 2>&1 || return 0
    # "Split DNS Routes:" lists "  - <domain>[.]   -> <ip>"; the format is
    # marked preliminary, so match loosely and print nothing on a surprise.
    # Bounded: a tailscaled that does not answer must never hold up a deploy.
    timeout 5 tailscale dns status 2>/dev/null | awk -v d="$1" '
        /^Split DNS Routes:/ { on = 1; next }
        on && !/^[[:space:]]*-/ { on = 0 }
        on && $1 == "-" && ($2 == d || $2 == d ".") && $3 == "->" { print $4 }'
}

# dns_names_check DOMAIN PLATFORM_IP NAME... — the platform's own names, as this
# machine resolves them (getent: /etc/hosts first, then DNS, as browsers and curl
# do). Each lookup is bounded by DNS_CHECK_TIMEOUT (5 s): with a DNS route to a
# server that does not answer (Tailscale split DNS sending DOMAIN to this server
# while nothing listens on its port 53) systemd-resolved waits, and getent with
# it. An address counts as this server's when it is PLATFORM_IP or one of
# `hostname -I` (DNS_OWN_ADDRS overrides, for tests): the ingress answers on all.
# Prints "  ✓ NAME → ADDR" or "  ✗ NAME: why" per name; on any failure sets
# DNS_CHECK_TODO (one line: the cause and the fix) and returns 1. Reads LOCAL_DNS.
DNS_CHECK_TODO=""
dns_names_check() {
    local domain="$1" ip="$2"; shift 2
    local t="${DNS_CHECK_TIMEOUT:-5}" name out addr rc own hung="" bad=0 route
    own=" $ip ${DNS_OWN_ADDRS-$(hostname -I 2>/dev/null)} "
    DNS_CHECK_TODO=""
    for name in "$@"; do
        rc=0
        out="$(timeout "$t" getent ahostsv4 "$name" 2>/dev/null)" || rc=$?
        addr="$(awk 'NR == 1 { print $1 }' <<<"$out")"
        if [[ $rc -eq 124 ]]; then
            echo "  ✗ $name: the lookup did not finish within ${t}s"
            hung=1; bad=1
        elif [[ -z "$addr" ]]; then
            echo "  ✗ $name: does not resolve on this machine"
            bad=1
        elif [[ "$own" != *" $addr "* ]]; then
            echo "  ✗ $name: resolves to $addr, not to this server ($ip)"
            bad=1
        else
            echo "  ✓ $name → $addr"
        fi
    done
    [[ $bad -eq 0 ]] && return 0

    route="$(split_dns_target "$domain" | paste -sd ' ')"
    if [[ -n "$route" && " $route " == *" $ip "* ]]; then
        if [[ "${LOCAL_DNS:-false}" == "true" ]]; then
            DNS_CHECK_TODO="Tailscale split DNS sends '$domain' to this server ($ip) and LOCAL_DNS is true, but the names do not resolve here: check name-dns (kubectl logs deploy/name-dns) and the managed block in /etc/hosts"
        elif ! dns_query "$ip" "$1" >/dev/null 2>&1; then
            DNS_CHECK_TODO="Tailscale split DNS sends '$domain' to this server ($ip), but nothing answers DNS on $ip:53 (LOCAL_DNS is not true), so every lookup of *.$domain fails or hangs: set LOCAL_DNS=\"true\" in config.env and run ./deploy-infra.sh (the platform then answers for $domain on $ip and maps the names in /etc/hosts)"
        else
            DNS_CHECK_TODO="Tailscale split DNS sends '$domain' to this server ($ip), and something answers there, but this machine does not resolve *.$domain to itself: set LOCAL_DNS=\"true\" in config.env and run ./deploy-infra.sh"
        fi
    elif [[ -n "$route" ]]; then
        DNS_CHECK_TODO="Tailscale split DNS sends '$domain' to $route, not to this server ($ip): change it at https://login.tailscale.com/admin/dns (Nameservers → the entry for '$domain'), or set LOCAL_DNS=\"true\" and run ./deploy-infra.sh"
    elif [[ "${LOCAL_DNS:-false}" == "true" ]]; then
        DNS_CHECK_TODO="*.$domain does not resolve to this server although LOCAL_DNS is true: check the managed block in /etc/hosts and that /etc/nsswitch.conf lists files before dns on its hosts: line, then run ./deploy-infra.sh"
    else
        DNS_CHECK_TODO="*.$domain does not resolve to this server ($ip): either set LOCAL_DNS=\"true\" in config.env and run ./deploy-infra.sh (the platform answers DNS for $domain on $ip and maps the names in /etc/hosts; other devices then reach it through Tailscale split DNS or the LAN router forwarding $domain to $ip), or create an A record for every <service>.$domain (or a wildcard *.$domain) pointing at $ip"
    fi
    [[ -n "$hung" ]] && DNS_CHECK_TODO+=" (a lookup hung: a DNS route, Tailscale split DNS or the router, to a server that does not answer)"
    return 1
}
