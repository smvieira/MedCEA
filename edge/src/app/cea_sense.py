"""SENSE role: read whatever the wizard said this board carries, publish it.

The previous main.py named one sensor at the top of the file and imported its
two functions under aliases, so a board with a different sensor was a different
copy of the program. Here the sensor list is DATA — cfg.SENSORS, written by the
onboarding wizard from the pins the operator chose — and this module is the same
on every SENSE board in the fleet.

Adding a sensor type is: an entry in edge/templates/esp32-sense.json, and a
branch in _setup/_read below.
"""

import time
import machine
import ujson
from machine import Pin

import cea_sensors as sensors
import cea_edge_functions as ef
import config as cfg

# A board that cannot read its sensor is not a board that should sit quiet
# forever; it reboots, which is the only recovery an unattended device has.
MAX_CONSECUTIVE_SENSOR_FAILURES = 5
MAX_CONSECUTIVE_MQTT_FAILURES = 10


def _setup(entry):
    """Bring one sensor up. Returns a handle, or None if it did not initialise."""
    d = entry.get("driver")
    p = entry.get("params", {})
    if d == "scd4x":
        return sensors.set_scd4x_i2c(
            i2c_id=p.get("i2c_id", 0),
            scl_pin=p["scl_pin"], sda_pin=p["sda_pin"],
            i2c_freq=p.get("i2c_freq", 400_000),
            altitude_masl=p.get("altitude_masl", 0),
            disable_auto_cal=p.get("disable_auto_cal", True))
    if d == "scd30":
        # set_scd30_i2c wants Pin objects and returns None for plain ints — the
        # template stores GPIO numbers, so wrap them here rather than teaching
        # the template about machine.Pin.
        return sensors.set_scd30_i2c(Pin(p["scl_pin"]), Pin(p["sda_pin"]))
    if d == "ground_temperature":
        ow, ds, roms = sensors.set_ground_temperature_sensor(p["data_pin"])
        return None if ds is None or not roms else (ow, ds, roms)
    if d == "water_level":
        from machine import ADC
        # width()/atten() moved between MicroPython releases and are gone on
        # some S3 builds. Missing them is not a reason to refuse the sensor.
        width = getattr(ADC, "WIDTH_12BIT", 3)
        atten = getattr(ADC, "ATTN_11DB", 3)
        _uart, power, signal = sensors.set_water_level_sensor(
            uart_id=p.get("uart_id", 1), tx_pin=p.get("tx_pin", 16),
            rx_pin=p.get("rx_pin", 17), power_pin=p["power_pin"],
            signal_pin=p["signal_pin"], adc_width=width, adc_atten=atten,
            baudrate=p.get("baudrate", 115200))
        return (power, signal)
    print("unknown sensor driver %r - skipped" % d)
    return None


def _read(entry, handle):
    """Read one sensor. Returns [(tag, value, uom), ...], empty on failure."""
    d = entry.get("driver")
    p = entry.get("params", {})
    if d == "scd4x":
        co2, temp, hum = sensors.read_scd4x_sensor(handle)
    elif d == "scd30":
        co2, temp, hum = sensors.read_scd30_sensor(handle)
    elif d == "ground_temperature":
        temp, uom = sensors.read_ground_temperature(*handle)
        return [] if temp is None else [("ground_temperature", round(temp, 2), uom)]
    elif d == "water_level":
        pct, uom = sensors.read_water_level_sensor(
            handle[0], handle[1], max_water_level=p.get("max_water_level", 1500))
        return [] if pct is None else [("water_level", pct, uom)]
    else:
        return []
    if co2 is None:
        return []
    return [("co2", round(co2, 2), "ppm"),
            ("air_temperature", round(temp, 2), "C"),
            ("air_humidity", round(hum, 2), "RH%")]


def run():
    handles = []
    for entry in cfg.SENSORS:
        h = _setup(entry)
        if h is None:
            print("sensor %r failed to initialise" % entry.get("driver"))
        else:
            handles.append((entry, h))

    if not handles:
        # Every sensor is down. Publishing nothing forever is indistinguishable
        # from a dead board, so reboot and let the retry show up in the log.
        print("CRITICAL: no sensor on this board initialised. Restarting in 15s.")
        time.sleep(15)
        machine.reset()

    try:
        client = ef.connect_mqtt()
    except OSError:
        ef.restart_and_reconnect()

    sensor_failures = 0
    mqtt_failures = 0
    last_message = 0

    print("\nSENSE loop: %d sensor(s), publishing to %s every %ds"
          % (len(handles), cfg.topic_pub, cfg.message_interval))

    while True:
        try:
            now = time.time()
            if (now - last_message) <= cfg.message_interval:
                time.sleep_ms(200)
                continue

            timestamp = ef.get_timestamp()
            readings = []
            failed = 0
            for entry, handle in handles:
                got = _read(entry, handle)
                if not got:
                    failed += 1
                readings.extend(got)

            # Partial success still counts: one dead probe must not stop the
            # other three from reporting.
            sensor_failures = sensor_failures + 1 if failed == len(handles) else 0

            if not readings:
                print("no sensor produced a reading this cycle")
            else:
                ok = True
                for tag, value, uom in readings:
                    message = {
                        "unit_code": cfg.unit_code,
                        "zone_code": cfg.zone_code,
                        "msg_type": "AP",
                        "timestamp": timestamp,
                        "device_id": cfg.device_id,
                        "device_dns": cfg.device_dns,
                        "tag": tag,
                        "value": value,
                        "UoM": uom,
                    }
                    try:
                        client.publish(cfg.topic_pub + "/" + tag, ujson.dumps(message))
                        time.sleep_ms(100)
                    except OSError as e:
                        print("publish to %s failed: %s" % (tag, e))
                        ok = False
                        break
                if ok:
                    mqtt_failures = 0
                    last_message = now
                else:
                    mqtt_failures += 1

            if sensor_failures >= MAX_CONSECUTIVE_SENSOR_FAILURES:
                print("every sensor failed %d cycles running. Restarting." % sensor_failures)
                time.sleep(5)
                machine.reset()
            if mqtt_failures >= MAX_CONSECUTIVE_MQTT_FAILURES:
                print("publishing failed %d cycles running. Restarting." % mqtt_failures)
                time.sleep(5)
                machine.reset()

        except OSError as e:
            print("SENSE loop OSError: %s" % e)
            ef.restart_and_reconnect()
        except Exception as e:
            print("FATAL in SENSE loop: %s: %s" % (type(e).__name__, e))
            time.sleep(10)
            machine.reset()
