# Runs ON THE BOARD via `mpremote run`. Prints the WiFi networks the ESP32's own
# radio can see, which is the list that matters — the provisioning host is a VM
# with no wireless interface, and even on a laptop the server's view of the RF
# environment is not the device's.
#
# Output contract, one network per line, parsed by flash-device.sh:
#   NET<TAB>ssid<TAB>rssi<TAB>authmode
# Terminated by a single line: SCAN_DONE

import network
import time

w = network.WLAN(network.STA_IF)
w.active(True)
time.sleep_ms(500)

best = {}
try:
    for net in w.scan():
        ssid = net[0]
        if isinstance(ssid, bytes):
            try:
                ssid = ssid.decode()
            except UnicodeError:
                continue
        if not ssid:
            continue  # hidden SSID — reachable only via manual entry
        rssi, auth = net[3], net[4]
        # A network on several APs or bands shows up repeatedly; keep the strongest.
        if ssid not in best or rssi > best[ssid][0]:
            best[ssid] = (rssi, auth)
except OSError as e:
    print("SCAN_ERR", e)

for ssid in sorted(best, key=lambda s: -best[s][0]):
    rssi, auth = best[ssid]
    print("NET\t%s\t%d\t%d" % (ssid, rssi, auth))

print("SCAN_DONE")
