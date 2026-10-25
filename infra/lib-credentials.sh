#!/usr/bin/env bash
# infra/lib-credentials.sh — show the credentials file written by deploy-infra.sh.
#
#   show_credentials FILE   print FILE in a box with "save, then rm" advice and
#                           any credentials files left from earlier runs
#
# Sourced by deploy-infra.sh (standalone runs) and install.sh (which shows it
# once, after the apps, so it is the last thing on screen). The content goes to
# /dev/tty, never stdout: stdout is teed into logs/, and the log must not hold
# passwords. Without a terminal only the path is printed.

show_credentials() {
    local file="$1" dir f
    local Y='\033[0;33m' N='\033[0m'
    [[ -f "$file" ]] || return 0
    dir="$(dirname "$file")"
    local -a old=()
    for f in "$dir"/credentials-*.txt; do
        [[ -f "$f" && "$f" != "$file" ]] && old+=("$f")
    done

    if ! { true > /dev/tty; } 2>/dev/null; then
        echo -e "${Y}Credentials written to $file (mode 600). Save them, then delete the file.${N}"
        return 0
    fi
    {
        echo ""
        echo -e "${Y}=================================================${N}"
        echo -e "${Y} CREDENTIALS — $file${N}"
        echo -e "${Y}=================================================${N}"
        echo ""
        cat "$file"
        echo ""
        echo -e "${Y}-------------------------------------------------${N}"
        echo -e "${Y} Save these now (password manager), then remove the file:${N}"
        echo -e "     rm $file"
        if [[ ${#old[@]} -gt 0 ]]; then
            echo -e "${Y} Credentials files from earlier runs are still here too:${N}"
            printf '     rm %s\n' "${old[@]}"
        fi
        echo -e "${Y}-------------------------------------------------${N}"
    } > /dev/tty
    echo "Credentials file shown on the terminal (not logged): $file"
}

# show_ca_trust CA_FILE PLATFORM_IP PORTAL_DOMAIN — how to make each client
# trust the platform CA, with this installation's real path, host and
# fingerprint filled in. stdout on purpose: nothing here is secret (ca.crt is
# the public half; the key stays in .ca/ca.key), so it may land in the log.
show_ca_trust() {
    local ca="$1" ip="$2" portal="$3" fp hostfp
    local Y='\033[0;33m' B='\033[1m' N='\033[0m'
    [[ -f "$ca" ]] || return 0
    fp="$(openssl x509 -in "$ca" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    # Host public keys are world-readable; this is what scp shows on first contact.
    hostfp="$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $2}')"
    echo ""
    echo -e "${Y}=================================================${N}"
    echo -e "${Y} TRUST THE PLATFORM CERTIFICATE (once per device)${N}"
    echo -e "${Y}=================================================${N}"
    echo "  Every service uses HTTPS with this platform's own certificate authority."
    echo "  Until a device trusts it, browsers show \"Not secure\"."
    echo ""
    echo "  SHA-256 fingerprint (check it matches after importing):"
    echo "    $fp"
    echo ""
    echo -e "  ${B}1. Copy the certificate to the device you browse from:${N}"
    echo "    scp $(id -un)@${ip}:${ca} ./medcea-ca.crt"
    echo "  In case scp stops with \"REMOTE HOST IDENTIFICATION HAS CHANGED\": the name or IP"
    echo "  belonged to an earlier server (a rebuild or reinstall). Forget the old key, then retry:"
    echo "    ssh-keygen -R ${ip}        (or the name, if you used one instead of the IP)"
    [[ -n "$hostfp" ]] && echo "  Accept the new key only if it is this server's: ED25519 ${hostfp}"
    echo ""
    echo -e "  ${B}2. Import it:${N}"
    echo "  Windows — Chrome and Edge, just for you (no admin needed, any PowerShell):"
    echo "    certutil -user -addstore Root .\\medcea-ca.crt"
    echo "    (Windows asks to confirm — check the fingerprint above, then click Yes)"
    echo "  Windows — for every user on the PC (PowerShell as Administrator: Win+X → Terminal (Admin)):"
    echo "    certutil -addstore -f \"Root\" .\\medcea-ca.crt"
    echo "  Linux — Chrome (it has its own store; the system one is not enough):"
    echo "    sudo apt install -y libnss3-tools"
    echo "    certutil -d sql:\$HOME/.pki/nssdb -A -t \"C,,\" -n \"MedCEA Platform CA\" -i medcea-ca.crt"
    echo "    (snap Chromium: sql:\$HOME/snap/chromium/current/.pki/nssdb)"
    echo "  Linux — system, curl and other tools:"
    echo "    sudo cp medcea-ca.crt /usr/local/share/ca-certificates/medcea-platform.crt && sudo update-ca-certificates"
    echo "  macOS:"
    echo "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain medcea-ca.crt"
    echo "  Firefox (any OS, keeps its own store):"
    echo "    Settings → Privacy & Security → Certificates → View Certificates → Authorities"
    echo "    → Import → medcea-ca.crt → tick \"Trust this CA to identify websites\""
    echo ""
    echo -e "  ${B}3. Quit the browser completely (every window — Chrome may also sit in the system tray), reopen, and visit:${N}"
    echo "    https://${portal}   — no warning; issued by \"CEA Platform CA\""
    echo ""
    echo "  Reinstalls reuse this certificate authority, so a trusted device stays trusted"
    echo "  unless .ca/ is deleted (e.g. answering yes during ./install.sh --uninstall-all)."
}

# The newest credentials-*.txt in DIR, or nothing.
latest_credentials() {
    ls -t "$1"/credentials-*.txt 2>/dev/null | head -1
}
