"""SENSE role: read whatever the wizard said this board carries, publish it.

The previous main.py named one sensor at the top of the file and imported its
two functions under aliases, so a board with a different sensor was a different
copy of the program. Here the sensor list is DATA — cfg.SENSORS, written by the
onboarding wizard from the pins the operator chose — and this module is the same
on every SENSE board in the fleet.

cfg.SENSORS comes in two shapes:
  - wired (the wiring screen, WIRING_VERSION 1): the entry names its "bus" (and
    hub/channel) from device_cfg.BUSES/HUBS, its I2C "addr", and "tags" as
    [quantity, tag, uom] for what it publishes. Driven by DRIVERS below.
  - legacy (the question flow, and every board flashed before the screen): no
    "bus"; the pins are in "params". Driven by _setup/_read, unchanged.

Adding a wired sensor type is: an entry with a `bus` block in
edge/templates/esp32-sense.json, and a (setup, read) pair in DRIVERS.

Each reading goes to <topic_pub>/<tag>/<instance>, and its payload carries
"sensor": <instance>, so two sensors publishing one tag (an SHT45 and an SCD30
both on air_temperature) stay two series. The instance is the entry's "id"
(wired), or its driver with "_<n>" (its position) for a repeat of the same
driver (legacy); device_template.py names legacy component rows by the same
rule. _health and _test keep their topics and carry no "sensor".

A sensor that fails does not reboot the board: the board connects, says which
sensor is down on <topic_pub>/_health, keeps publishing the others, and tries
the failed ones again every RETRY_SECONDS. Only a broker that keeps refusing
publishes resets it. Once per boot, right after its first connect, it also
publishes a test message (TS) on <topic_pub>/_test.
"""

import time
import machine
import ujson
from machine import Pin

import cea_edge_functions as ef
import config as cfg

MAX_CONSECUTIVE_MQTT_FAILURES = 10
RETRY_SECONDS = 600
HEALTH_TAG = "_health"
ERR_MAX = 80


def _sensors():
    # Imported on first use: it pulls in the onewire, ds18x20 and SCD4x drivers,
    # RAM a board wired on the screen does not need.
    import cea_sensors
    return cea_sensors


def _err(e):
    """An exception as the health message carries it: at most ERR_MAX
    characters, no quote characters."""
    s = str(e)
    s = "%s: %s" % (type(e).__name__, s) if s else type(e).__name__
    return s.replace("'", "").replace('"', "")[:ERR_MAX]


# ---- wired drivers: (setup(i2c, addr, params) -> device, read(device, params) -> {q: value})
# setup touches the device once, so an absent or miswired one fails here and is
# reported, instead of reading as zeros later.

def _sht4x_setup(i2c, addr, p):
    import sht4x
    s = sht4x.SHT4x(i2c, addr)
    s.soft_reset()                     # as the bench test does: a known state first
    s.measure()
    return s


def _sht4x_read(s, p):
    t, rh = s.measure()
    return {"temperature": t, "humidity": rh}


# How long after a start the SCD30 may still be warming up: its first data-ready
# takes ~2 s and its first readings are often co2 0. Inside the window "nothing
# yet" is no reading, not a failure, so a boot does not publish a false "down"
# and "up" pair on _health. After it, the same states are faults.
SCD30_WARMUP_MS = 60000
SCD30_PAUSE_US = 4000
SCD30_INTERVAL_S = 2      # the bench test's measurement interval (command 0x4600)


def _scd30_setup(i2c, addr, p):
    import scd30
    # pause: the time between a command and its read. The library's 1 ms is too
    # short; the SCD30 wants ~3 ms, and the bench test ran with 4.
    s = scd30.SCD30(i2c, addr, pause=SCD30_PAUSE_US)   # NotFoundException when not on the bus
    # The interval is kept in the sensor's flash: one set to 60 s by another tool
    # would leave _scd30_read with nothing ready on most cycles. The bench test
    # sets 2 s before starting; write it only when it differs, to spare the flash.
    try:
        current = s.get_measurement_interval()
    except Exception:
        current = None
    if current != SCD30_INTERVAL_S:
        s.set_measurement_interval(SCD30_INTERVAL_S)
        time.sleep_ms(4)
    s.start_continous_measurement(0)   # a sensor fresh from the factory is not measuring
    return [s, time.ticks_ms()]


def _scd30_read(dev, p):
    s, t0 = dev
    warming = time.ticks_diff(time.ticks_ms(), t0) < SCD30_WARMUP_MS
    for _ in range(3):
        if s.get_status_ready() == 1:
            co2, t, rh = s.read_measurement()
            if co2 == 0 and warming:
                return {}
            # The bounds cea_sensors.read_scd30_sensor uses.
            if 0 < co2 < 10000 and -40 < t < 120 and 0 <= rh <= 100:
                return {"co2": co2, "temperature": t, "humidity": rh}
            raise ValueError("implausible reading co2=%.0f t=%.1f rh=%.1f" % (co2, t, rh))
        time.sleep_ms(500)
    if warming:
        return {}
    raise ValueError("no measurement ready")


def _sen0562_setup(i2c, addr, p):
    import sen0562
    return sen0562.SEN0562(i2c, addr)


def _sen0562_read(s, p):
    return {"lux": s.read()}


DRIVERS = {
    "sht4x": (_sht4x_setup, _sht4x_read),
    "scd30": (_scd30_setup, _scd30_read),
    "sen0562": (_sen0562_setup, _sen0562_read),
}


def _wired_setup(entry, buses, bus_errors):
    """Bring one wired sensor up. Returns (driver, device); raises on failure."""
    drv = DRIVERS.get(entry.get("driver"))
    if drv is None:
        raise ValueError("unknown driver %s" % entry.get("driver"))
    for ref in (entry.get("bus"), entry.get("hub")):
        if ref is not None and ref not in buses:
            e = bus_errors.get(ref)
            raise ValueError("%s: %s" % (ref, _err(e)) if e else "%s is not configured" % ref)
    i2c = buses[entry["bus"]]
    if entry.get("hub") is not None:
        import cea_bus
        i2c = cea_bus.MuxedI2C(buses[entry["hub"]], entry.get("channel"))
    return drv, drv[0](i2c, entry["addr"], entry.get("params") or {})


# ---- legacy entries: the question flow's shape, unchanged

def _setup(entry):
    """Bring one legacy sensor up. Returns a handle, or None if it did not initialise."""
    sensors = _sensors()
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
    """Read one legacy sensor. Returns [(tag, value, uom), ...], empty on failure."""
    sensors = _sensors()
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


def _bus_cfg():
    # config.py derives identity and topics; the bus layout is used only here,
    # so it is read from the generated file itself.
    if hasattr(cfg, "BUSES"):
        return cfg
    import device_cfg
    return device_cfg


class _Slot:
    """One cfg.SENSORS entry and its state: the handle (None while down), and
    ok/err as the health message reports them."""

    def __init__(self, sid, entry):
        self.id = sid
        self.entry = entry
        self.handle = None
        self.ok = False
        self.err = "not started"


class Board:

    def __init__(self, entries):
        self.slots = []
        seen = set()
        for i, e in enumerate(entries):
            # A legacy entry has no id: its driver names it (a second one of the
            # same driver gets its position). This id is also the last segment
            # of the reading topic and the payload's "sensor";
            # device_template.py's legacy component rows use the same rule.
            sid = e.get("id") or e.get("driver") or "sensor"
            if sid in seen:
                sid = "%s_%d" % (sid, i + 1)
            seen.add(sid)
            self.slots.append(_Slot(sid, e))
        self.buses = {}
        self.bus_errors = {}
        if any("bus" in e for e in entries):
            import cea_bus
            self.buses = cea_bus.build(_bus_cfg(), self.bus_errors)
        self.client = None
        self.last_message = 0
        self.last_retry = 0
        self.mqtt_failures = 0
        self.health_sent = None   # the ok flags last published, None before the first

    def start(self, slot):
        e = slot.entry
        slot.handle = None
        try:
            if "bus" in e:
                h = _wired_setup(e, self.buses, self.bus_errors)
            else:
                h = _setup(e)
        except Exception as ex:
            slot.ok, slot.err = False, _err(ex)
            print("sensor %s failed to initialise: %s" % (slot.id, slot.err))
            return
        if h is None:
            slot.ok, slot.err = False, "did not initialise"
            print("sensor %r failed to initialise" % e.get("driver"))
            return
        slot.handle, slot.ok, slot.err = h, True, None

    def start_all(self, failed_only=False):
        for s in self.slots:
            if not (failed_only and s.ok):
                self.start(s)
        self.last_retry = time.time()

    def read(self, slot):
        """[(tag, value, uom, instance), ...] for one sensor; sets its ok/err."""
        e = slot.entry
        try:
            if "bus" in e:
                drv, dev = slot.handle
                vals = drv[1](dev, e.get("params") or {})
                got = []
                for q, tag, uom in e.get("tags", []):
                    v = vals.get(q)
                    if v is not None:
                        got.append((tag, round(v, 2), uom, slot.id))
                slot.ok, slot.err = True, None
                return got
            got = [(tag, v, uom, slot.id) for tag, v, uom in _read(e, slot.handle)]
        except Exception as ex:
            slot.ok, slot.err = False, _err(ex)
            print("sensor %s: %s" % (slot.id, slot.err))
            return []
        # A legacy reader says "failed" by returning nothing.
        slot.ok, slot.err = (True, None) if got else (False, "no reading")
        return got

    def _message(self, timestamp, tag, sensor):
        return {
            "unit_code": cfg.unit_code,
            "zone_code": cfg.zone_code,
            "msg_type": "AP",
            "timestamp": timestamp,
            "device_id": cfg.device_id,
            "device_dns": cfg.device_dns,
            "sensor": sensor,
            "tag": tag,
        }

    def health(self, timestamp):
        """Publish <topic_pub>/_health when a sensor's ok flag changed since the
        last one (or none was sent yet). False when the publish failed: it is
        tried again next cycle. Node-RED stores it in medcea.measurement as
        msg_type HB, set from the topic; it carries the board's ip and mac."""
        flags = [s.ok for s in self.slots]
        if flags == self.health_sent:
            return True
        message = ef.status_message("HB", HEALTH_TAG, timestamp)
        message["sensors"] = [{"id": s.id, "ok": s.ok, "err": s.err} for s in self.slots]
        try:
            self.client.publish(cfg.topic_pub + "/" + HEALTH_TAG, ujson.dumps(message))
        except OSError as e:
            print("publish to %s failed: %s" % (HEALTH_TAG, e))
            return False
        self.health_sent = flags
        return True

    def cycle(self, now):
        """One sampling cycle: retry what is down when due, read, publish."""
        if now - self.last_retry >= RETRY_SECONDS:
            self.start_all(failed_only=True)
        timestamp = ef.get_timestamp()
        readings = []
        for s in self.slots:
            if s.handle is not None:
                readings.extend(self.read(s))

        ok = True
        published = False
        if not readings:
            print("no sensor produced a reading this cycle")
        else:
            for tag, value, uom, sid in readings:
                message = self._message(timestamp, tag, sid)
                message["value"] = value
                message["UoM"] = uom
                try:
                    self.client.publish(cfg.topic_pub + "/" + tag + "/" + sid,
                                        ujson.dumps(message))
                    time.sleep_ms(100)
                except OSError as e:
                    print("publish to %s/%s failed: %s" % (tag, sid, e))
                    ok = False
                    break
            published = ok
        if ok:
            before = self.health_sent
            ok = self.health(timestamp)
            published = published or (ok and before != self.health_sent)
        if ok and not published:
            # Nothing went out, and umqtt.simple sends no PINGREQ by itself: the
            # broker would drop a board silent for 1.5 x keepalive, and the first
            # publish after that can vanish into the half-closed socket. As the
            # CONTROL loop does: read what came back (the last PINGRESP; a closed
            # connection raises here), then ping.
            try:
                self.client.check_msg()
                self.client.ping()
                published = True
            except OSError as e:
                print("MQTT keepalive failed: %s" % e)
                ok = False

        # A failed publish (or keepalive) leaves last_message alone, so the next
        # cycle comes at once and a broker that is gone reaches the reset
        # quickly, as before. A cycle with nothing to publish still counts as
        # done: without the old reboot loop, a board with every sensor down
        # would otherwise re-read them every 200 ms.
        if not ok:
            self.mqtt_failures += 1
        else:
            if published:
                self.mqtt_failures = 0
            self.last_message = now


def run():
    board = Board(cfg.SENSORS)
    board.start_all()

    try:
        board.client = ef.connect_mqtt()
    except OSError:
        ef.restart_and_reconnect()

    # Once per boot, after the first connect (a lost broker resets the board, so
    # the next connect is the next boot's): a TS on _test, findable in the MQTT
    # Explorer and in medcea.measurement. A failed one counts as a failed publish.
    if not ef.publish_test(board.client):
        board.mqtt_failures += 1
    # At boot, whatever came up: a board whose every sensor is down still says so.
    if not board.health(ef.get_timestamp()):
        board.mqtt_failures += 1

    print("\nSENSE loop: %d of %d sensor(s) up, publishing to %s every %ds"
          % (sum(1 for s in board.slots if s.ok), len(board.slots),
             cfg.topic_pub, cfg.message_interval))

    while True:
        try:
            now = time.time()
            if (now - board.last_message) <= cfg.message_interval:
                time.sleep_ms(200)
                continue

            board.cycle(now)

            if board.mqtt_failures >= MAX_CONSECUTIVE_MQTT_FAILURES:
                print("publishing failed %d cycles running. Restarting." % board.mqtt_failures)
                time.sleep(5)
                machine.reset()

        except OSError as e:
            print("SENSE loop OSError: %s" % e)
            ef.restart_and_reconnect()
        except Exception as e:
            print("FATAL in SENSE loop: %s: %s" % (type(e).__name__, e))
            time.sleep(10)
            machine.reset()
