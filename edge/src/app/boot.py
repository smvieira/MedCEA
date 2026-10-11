# Runs before main.py on every boot, including wake from deepsleep. Copied to
# the board by edge/flash-device.sh and not edited there — everything that
# differs per device is in device_cfg.py.
#
# One boot.py for both states. An UNREGISTERED board and a registered one differ
# only in what device_cfg.py says, so there is one hostname implementation, one
# WiFi path and one place where a bring-up bug can hide.
#
# WebREPL is started here deliberately, with a password generated per board and
# never committed. On an unregistered board that is a bounded exposure for
# bring-up: the board carries the marker in its name (HOSTNAME is
# cea-un-<mac6>) and has no MQTT
# credential, so it can talk to nothing. On a registered board it stays on
# because a device in a grow chamber is not somewhere anyone wants to bring a
# USB cable — and it is tracked as a known exposure in edge/README.md.

import config as cfg
import cea_edge_functions as ef

print()
print("=" * 58)
print("state      :", cfg.STATE)
print("role       :", cfg.ROLE)
print("hostname   :", cfg.hostname)

_ifc = ef.connect_wifi(cfg.wifi_ssid, cfg.wifi_pwd, cfg.hostname)

if _ifc:
    print("ip         :", _ifc[0])
    # Timestamps go into the measurement table as the reading's own time, so a
    # board with an unset clock writes rows dated 2000-01-01 that no dashboard
    # ever finds. Not fatal — the loop is still worth running.
    ef.set_device_time()
    try:
        import webrepl
        webrepl.start()  # password read from webrepl_cfg.py
        print("webrepl    : ws://%s:8266/" % _ifc[0])
    except ImportError:
        print("webrepl    : unavailable in this build")
else:
    print("ip         : NOT CONNECTED")
    print("             main.py will not reach the broker")
print("=" * 58)
print()
