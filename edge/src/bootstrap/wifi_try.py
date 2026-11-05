# Runs ON THE BOARD via `mpremote run`, right after the passphrase is entered, so a
# wrong one is caught while the operator is still at that question (5 Nov 2026).
# flash-device.sh prepends two lines, SSID = '...' and PSK = '...' (Python literals,
# written from its environment into a file in a mode-700 directory, removed at once).
#
# Output contract, one line, parsed by flash-device.sh:
#   WIFI<TAB>result<TAB>address
# result: GOT_IP; REFUSED (the access point turned the board away: a wrong passphrase,
# or a WPA handshake it gave up on; MicroPython on the ESP32 reports a wrong WPA2
# passphrase as STAT_WRONG_PASSWORD or as the raw ESP-IDF reason 15, so the two are one
# answer); NO_AP_FOUND; TIMEOUT (no address within 20 s); ERROR; or REASON_<n> for any
# other ESP-IDF disconnect reason. address is the board's IPv4 address on GOT_IP, else '-'.

import network
import time

w = network.WLAN(network.STA_IF)
w.active(True)
try:
    w.disconnect()
except OSError:
    pass
# Without a bound the driver retries forever and status() stays CONNECTING, so a
# refusal would never be reported; two retries and the reason comes back.
try:
    w.config(reconnects=2)
except (OSError, ValueError, TypeError):
    pass

def stat(name, default):
    return getattr(network, name, default)


CONNECTING = stat("STAT_CONNECTING", 1001)
IDLE = stat("STAT_IDLE", 1000)
GOT_IP = stat("STAT_GOT_IP", 1010)
# ESP-IDF disconnect reasons: 2 AUTH_EXPIRE, 15 4WAY_HANDSHAKE_TIMEOUT, 202 AUTH_FAIL,
# 203 ASSOC_FAIL, 204 HANDSHAKE_TIMEOUT; 201 NO_AP_FOUND and IDF 5.2's 210-212 variants.
REFUSED = {2, 15, stat("STAT_WRONG_PASSWORD", 202), stat("STAT_ASSOC_FAIL", 203),
           stat("STAT_HANDSHAKE_TIMEOUT", 204)}
NO_AP = {stat("STAT_NO_AP_FOUND", 201), 210, 211, 212}
SETTLE_MS = 3000    # a failure counts once it has lasted this long: the driver may still be
                    # retrying, and the first reads can carry the reason of an earlier attempt


def verdict(s):
    if s in REFUSED:
        return "REFUSED"
    if s in NO_AP:
        return "NO_AP_FOUND"
    return "REASON_%d" % s


result, address = "TIMEOUT", "-"
try:
    w.connect(SSID, PSK)  # noqa: F821 (prepended by flash-device.sh)
    t0 = time.ticks_ms()
    bad, bad_since = None, None
    while time.ticks_diff(time.ticks_ms(), t0) < 20000:
        if w.isconnected():
            ip = w.ifconfig()[0]
            if ip and ip != "0.0.0.0":   # associated, DHCP not answered yet: wait
                result, address = "GOT_IP", ip
                break
            bad = None
        else:
            s = w.status()
            if s in (CONNECTING, IDLE, GOT_IP):
                bad = None
            elif s != bad:
                bad, bad_since = s, time.ticks_ms()
            elif time.ticks_diff(time.ticks_ms(), bad_since) >= SETTLE_MS:
                result = verdict(s)
                break
        time.sleep_ms(200)
except OSError:
    result = "ERROR"

# Leave the radio off: the board's own boot.py joins the network after the reset
# at the end of the run, under its proper hostname.
try:
    w.disconnect()
except OSError:
    pass
w.active(False)
print("WIFI\t%s\t%s" % (result, address))
