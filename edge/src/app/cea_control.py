"""CONTROL role: hold the chamber's relays, driven by MQTT.

The pin map is not in this file. The wizard writes actuator_config.json from the
equipment the operator said the chamber has, and everything below reads it — so
a chamber with no UV lamp simply has no UV entry, rather than a board that
cheerfully drives an unconnected GPIO.

    subscribe  <root>/<unit>/<zone>/control/#          what to do
    publish    <root>/<unit>/<zone>/control_setpoint/  what was actually done

The published half is not decoration: it is the only evidence that a command
reached hardware, and it is what the measurement table records as msg_type 'SP'.
"""

import sys
import time
import machine
import ujson
from machine import Pin

import cea_edge_functions as ef
import config as cfg

_cfgdata = {}


def load():
    global _cfgdata
    with open(cfg.ACTUATOR_CONFIG, "r") as f:
        _cfgdata = ujson.load(f)
    print("actuator config: %d pins, %d actuators"
          % (len(_cfgdata.get("pin_descriptions", {})),
             len(_cfgdata.get("actuator_definitions", {}))))
    return _cfgdata


def pin_value_convert(value):
    """Logical 'on' -> the level this relay board actually needs.

    These boards close the contact on a LOW, so the config files store logical
    values (1 = equipment running) and the inversion happens here, once. Getting
    this backwards energises every heater in the chamber at boot.
    """
    if not cfg.ACTIVE_LOW:
        return 1 if value else 0
    return 0 if value else 1


def _drive(pin_number, logical):
    Pin(int(pin_number), Pin.OUT).value(pin_value_convert(int(logical)))


def all_off(data=None):
    """Put every actuator into its OFF state. Runs at boot, before anything else.

    A reset does not reset the relays — they hold whatever the last command left
    them at, so a board that reboots mid-recipe comes back with a heater still
    energised and no one driving it.
    """
    data = data or _cfgdata
    done = []
    for name, spec in (data.get("actuator_definitions") or {}).items():
        branches = []
        if "commands" in spec and "OFF" in spec["commands"]:
            branches.append(spec["commands"]["OFF"])
        for _t, tspec in (spec.get("types") or {}).items():
            if "OFF" in tspec:
                branches.append(tspec["OFF"])
        for b in branches:
            for action in b.get("actions", []):
                try:
                    _drive(action["pin"], action.get("value", 0))
                    done.append((name, action["pin"]))
                    time.sleep_ms(50)
                except (OSError, ValueError) as e:
                    print("could not set pin %s: %s" % (action.get("pin"), e))
    print("all actuators off (%d pin writes)" % len(done))
    return done


def _actions_for(msg):
    """The pin actions one command asks for, or None if the board cannot do it."""
    tag = msg.get("tag")
    defs = _cfgdata.get("actuator_definitions") or {}
    if tag == "all_controllers_off":
        return "all_off"
    spec = defs.get(tag)
    if spec is None:
        print("no actuator %r on this board - ignoring" % tag)
        return None
    if "types" in spec:
        # A typed actuator (light) selects by value first, then by command.
        t = spec["types"].get(msg.get("value"))
        if t is None:
            print("actuator %r has no type %r" % (tag, msg.get("value")))
            return None
        branch = t.get(msg.get("command"))
    else:
        branch = (spec.get("commands") or {}).get(msg.get("command"))
    if branch is None:
        print("actuator %r has no command %r" % (tag, msg.get("command")))
        return None
    return branch.get("actions", [])


def apply(client, msg):
    """Execute one command and report every pin it moved."""
    timestamp = ef.get_timestamp()
    actions = _actions_for(msg)
    if actions is None:
        return
    if actions == "all_off":
        all_off()
        actions = []

    descriptions = _cfgdata.get("pin_descriptions") or {}
    for action in actions:
        pin_number = action.get("pin")
        description = descriptions.get(str(pin_number), "GPIO %s" % pin_number)
        try:
            _drive(pin_number, action.get("value", 0))
        except (OSError, ValueError) as e:
            print("could not set pin %s: %s" % (pin_number, e))
            continue
        report = dict(action)
        report.update({
            "unit_code": msg.get("unit_code", cfg.unit_code),
            "zone_code": msg.get("zone_code", cfg.zone_code),
            "timestamp": timestamp,
            "msg_type": "SP",
            "device_id": cfg.device_id,
            "device_dns": cfg.device_dns,
            "tag": description,
        })
        try:
            client.publish("%s/%s/%s" % (cfg.topic_pub, msg.get("tag"), description),
                           ujson.dumps(report))
        except OSError as e:
            print("could not report pin %s: %s" % (pin_number, e))
        time.sleep_ms(100)


def run():
    load()
    all_off()

    try:
        client = ef.connect_mqtt()
    except OSError:
        ef.restart_and_reconnect()

    def on_message(_topic, raw):
        try:
            msg = ujson.loads(raw)
        except (ValueError, TypeError) as e:
            print("undecodable command: %s" % e)
            return
        try:
            apply(client, msg)
        except (KeyError, ValueError) as e:
            print("bad command %r: %s" % (msg, e), file=sys.stderr)

    client.set_callback(on_message)
    client.subscribe(cfg.topic_sub)
    print("\nCONTROL loop: subscribed to %s, reporting to %s"
          % (cfg.topic_sub, cfg.topic_pub))

    while True:
        try:
            client.check_msg()
            time.sleep_ms(cfg.poll_ms)
        except OSError as e:
            # Losing the broker leaves the relays where they are, which is the
            # safe-looking wrong answer: nobody is watching the chamber any
            # more. Drop everything, then reconnect.
            print("CONTROL loop OSError: %s" % e)
            try:
                all_off()
            except Exception:
                pass
            ef.restart_and_reconnect()
        except Exception as e:
            print("FATAL in CONTROL loop: %s: %s" % (type(e).__name__, e))
            time.sleep(10)
            machine.reset()
