"""Entry point for every registered CEA board.

One program, two roles. Which one runs is data — cfg.ROLE, written by the
onboarding wizard — not a different copy of main.py per board. That is the whole
point of the split: the fleet used to carry one edited copy of this file per
device, and they drifted.
"""

import time
import machine
import esp

import config as cfg

esp.osdebug(None)

print("\n%s  role=%s" % (cfg.hostname, cfg.ROLE))

if cfg.ROLE == "SENSE":
    import cea_sense
    cea_sense.run()
elif cfg.ROLE == "CONTROL":
    import cea_control
    cea_control.run()
else:
    # UNREGISTERED. The board is on WiFi with WebREPL up and nothing else to do;
    # it has no MQTT credential, no unit and no zone. Say so instead of
    # rebooting in a loop, because this is the state a bench board is meant to
    # sit in until an operator gives it a slot.
    print("This board is %s: no unit, no zone, no role, no MQTT." % cfg.STATE)
    print("Onboard it from the Devices tab to give it an identity.")
    while True:
        time.sleep(60)
