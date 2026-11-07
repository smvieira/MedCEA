"""The SENSE firmware (edge/src/app/cea_sense.py and the wired drivers) under CPython.

machine, utime/time, ujson, ubinascii, network, ntptime, umqtt.simple and device_cfg
are fakes injected into sys.modules for each test (cea_edge_functions is the real file,
its connect_mqtt and restart_and_reconnect replaced); the I2C bus is FakeBus, which models a
TCA9548A hub (one control byte, a bit per channel) and, behind it, an SHT45 (CRC'd
six-byte frames), an SCD30 (the register protocol scd30.py speaks) and a DFRobot
SEN0562 (BH1750). config.py, cea_bus.py, sht4x.py, sen0562.py, scd30.py,
cea_sense.py and cea_control.py are the real files.
"""

import importlib
import io
import json
import os
import shutil
import struct
import tempfile
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "edge", "src", "app")
HUB = 0x70


def crc8(b0, b1):
    """Sensirion CRC-8 (poly 0x31, init 0xFF), written independently of the firmware."""
    crc = 0xFF
    for b in (b0, b1):
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x31) if crc & 0x80 else (crc << 1)
            crc &= 0xFF
    return crc


def words(*ws):
    out = b""
    for w in ws:
        hi, lo = (w >> 8) & 0xFF, w & 0xFF
        out += bytes([hi, lo, crc8(hi, lo)])
    return out


# ---------------------------------------------------------------- devices --

class SHT45:
    def __init__(self, t, rh):
        self.set(t, rh)
        self.bad_crc = False
        self.pending = None
        self.resets = 0
        self.busy = 0           # reads still NACKed (converting), as the real sensor does

    def set(self, t, rh):
        self.t_raw = round((t + 45) * 65535 / 175)
        self.rh_raw = round((rh + 6) * 65535 / 125)

    def write(self, data):
        if data == b"\x94":
            self.resets += 1
            self.pending = None
            return
        assert data == b"\xfd", data
        self.pending = words(self.t_raw, self.rh_raw)

    def read(self, n):
        if self.busy:
            self.busy -= 1
            raise OSError(19, "ENODEV")
        assert n == 6 and self.pending is not None
        d = bytearray(self.pending)
        self.pending = None
        if self.bad_crc:
            d[2] ^= 0xFF
        return bytes(d)


class SCD30:
    def __init__(self, co2, t, rh, interval=2):
        self.values = (co2, t, rh)
        self.cmd = None
        self.started = False
        self.not_ready = 0      # status reads still answering "not ready"
        self.zeros = 0          # measurements still reading co2 0 (warming up)
        self.interval = interval   # seconds, kept in the sensor's flash
        self.writes = []        # (command, argument or None), in order

    def write(self, data):
        self.cmd = (data[0] << 8) | data[1]
        arg = None
        if len(data) == 5:
            assert crc8(data[2], data[3]) == data[4]
            arg = (data[2] << 8) | data[3]
        self.writes.append((self.cmd, arg))
        if self.cmd == 0x0010:
            assert arg is not None
            self.started = True
        if self.cmd == 0x4600 and arg is not None:
            self.interval = arg

    def read(self, n):
        if self.cmd == 0x4600:
            return words(self.interval)[:n]
        if self.cmd == 0x0202:
            if self.not_ready:
                self.not_ready -= 1
                return words(0)[:n]
            return words(1 if self.started else 0)[:n]
        if self.cmd == 0x0300:
            out = b""
            values = self.values
            if self.zeros:
                self.zeros -= 1
                values = (0.0,) + values[1:]
            for v in values:
                raw = struct.pack(">f", v)
                out += words((raw[0] << 8) | raw[1], (raw[2] << 8) | raw[3])
            return out[:n]
        raise AssertionError("SCD30 read after command %r" % self.cmd)


class SEN0562:
    """A BH1750: after power loss it is powered down, still ACKs and returns the
    power-on data register (0) until a mode command starts a conversion."""

    def __init__(self, raw):
        self.raw = raw
        self.mode = None
        self.writes = 0

    def write(self, data):
        assert data == b"\x10", data
        self.mode = data[0]
        self.writes += 1

    def power_loss(self):
        self.mode = None

    def read(self, n):
        assert n == 2
        if self.mode != 0x10:
            return b"\x00\x00"
        return bytes([self.raw >> 8, self.raw & 0xFF])


class FakeBus:
    """An I2C bus with a TCA9548A at HUB (and, after add_hub, more of them): the
    root segment plus the channels each hub's control byte opens. Hubs know
    nothing of each other, as on the wire: two hubs with a channel open each put
    both channels on the bus. Two devices answering one address is a collision,
    which a test must never cause."""

    def __init__(self):
        self.masks = {HUB: 0}
        self.root = {}
        self.chans = {}
        self.hub_chans = {HUB: self.chans}
        self.log = []          # ("sel", byte) for HUB, ("sel", byte, hub) for another | ("dev", addr, mask)

    @property
    def mask(self):
        return self.masks[HUB]

    def add_hub(self, addr):
        self.masks[addr] = 0
        self.hub_chans[addr] = {}

    def put(self, ch, addr, dev, hub=HUB):
        self.hub_chans[hub].setdefault(ch, {})[addr] = dev
        return dev

    def _visible(self):
        seen = dict((a, [d]) for a, d in self.root.items())
        for hub, chans in self.hub_chans.items():
            seen.setdefault(hub, []).append("hub")
            for ch, devs in chans.items():
                if self.masks[hub] & (1 << ch):
                    for a, d in devs.items():
                        seen.setdefault(a, []).append(d)
        return seen

    def _dev(self, addr):
        found = self._visible().get(addr, [])
        if not found:
            raise OSError(19, "ENODEV")
        if len(found) > 1:
            raise AssertionError("address collision at 0x%02x, mask 0x%02x" % (addr, self.mask))
        self.log.append(("dev", addr, self.mask))
        return found[0]

    def writeto(self, addr, buf, stop=True):
        if addr in self.masks:
            self.masks[addr] = buf[0]
            self.log.append(("sel", buf[0]) if addr == HUB else ("sel", buf[0], addr))
            return 1
        self._dev(addr).write(bytes(buf))
        return len(buf)

    def readfrom(self, addr, n, stop=True):
        return self._dev(addr).read(n)

    def writeto_mem(self, addr, memaddr, buf, addrsize=8):
        self._dev(addr).write(memaddr.to_bytes(addrsize // 8, "big") + bytes(buf))

    def scan(self):
        return sorted(self._visible())


# ---------------------------------------------------------------- the fakes --

class Reset(BaseException):
    """machine.reset(): a BaseException so the firmware's `except Exception` cannot eat it."""


class StopLoop(BaseException):
    pass


class Clock:
    def __init__(self):
        self.ms = 1_000_000
        self.budget = None

    def module(self, name):
        m = types.ModuleType(name)
        m.time = lambda: self.ms // 1000
        m.sleep = lambda s: self.advance(int(s * 1000))
        m.sleep_ms = self.advance
        m.sleep_us = lambda us: self.advance(us // 1000)
        m.ticks_ms = lambda: self.ms
        m.ticks_diff = lambda a, b: a - b
        m.localtime = lambda *a: (2026, 11, 6, 12, 0, 0, 3, 310)
        return m

    def advance(self, ms):
        self.ms += max(0, int(ms))
        if self.budget is not None:
            self.budget -= 1
            if self.budget < 0:
                raise StopLoop()


class Pin:
    OUT, IN, OPEN_DRAIN, PULL_UP = 1, 0, 2, 1

    def __init__(self, n, *a, **kw):
        self.n = n

    def value(self, v=None):
        return 0 if v is None else None

    def __eq__(self, other):
        return isinstance(other, Pin) and other.n == self.n


class FakeClient:
    def __init__(self):
        self.sent = []
        self.fail = False
        self.pings = 0
        self.closed = False     # the broker closed the session: the next read sees EOF
        self.fail_topics = ()   # topic suffixes whose publish fails (the rest go out)

    def check_msg(self):
        if self.closed:
            raise OSError(-1)

    def ping(self):
        if self.fail:
            raise OSError(113, "EHOSTUNREACH")
        self.pings += 1

    def publish(self, topic, payload):
        if self.fail or any(topic.endswith(x) for x in self.fail_topics):
            raise OSError(113, "EHOSTUNREACH")
        self.sent.append((topic, json.loads(payload)))

    def topics(self):
        return [t for t, _ in self.sent]

    def set_callback(self, fn):
        self.callback = fn

    def subscribe(self, topic):
        self.subscribed = topic

    keepalive = 90

    def health(self):
        return [p for t, p in self.sent if t.endswith("/_health")]

    def tests(self):
        return [(t, p) for t, p in self.sent if t.endswith("/_test")]

    def readings(self):
        return dict((p["tag"], p) for t, p in self.sent
                    if not t.endswith("/_health") and not t.endswith("/_test"))


class FakeWlan:
    """network.WLAN(STA_IF) as the HB/TS metadata reads it; broken=True makes every
    call raise, as a port without the attribute or a driver error would."""

    def __init__(self):
        self.connected = True
        self.addr = "192.168.1.57"
        self.mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        self.broken = False

    def _check(self):
        if self.broken:
            raise OSError(-1, "wifi driver")

    def isconnected(self):
        self._check()
        return self.connected

    def ifconfig(self):
        self._check()
        return (self.addr, "255.255.255.0", "192.168.1.1", "192.168.1.1")

    def config(self, key):
        self._check()
        assert key == "mac", key
        return self.mac


REFERENCE = dict(
    BUSES=[{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9, "freq": 100000, "impl": "hw"}],
    HUBS=[{"id": "mux0", "kind": "tca9548a", "bus": "i2c0", "addr": HUB}],
    SENSORS=[
        {"id": "sht45_1", "driver": "sht4x", "bus": "i2c0", "hub": "mux0", "channel": 0,
         "addr": 0x44, "params": {},
         "tags": [["temperature", "air_temperature", "C"], ["humidity", "air_humidity", "RH%"]]},
        {"id": "scd30_1", "driver": "scd30", "bus": "i2c0", "hub": "mux0", "channel": 1,
         "addr": 0x61, "params": {}, "tags": [["co2", "co2", "ppm"]]},
        {"id": "lux_1", "driver": "sen0562", "bus": "i2c0", "hub": "mux0", "channel": 2,
         "addr": 0x23, "params": {}, "tags": [["lux", "light_intensity", "lx"]]},
    ])


class FirmwareCase(unittest.TestCase):

    def load(self, device_cfg, legacy_sensors=None):
        """Import the firmware against fresh fakes. Returns (cea_sense, client)."""
        self.clock = Clock()
        self.buses_made = []
        self.resets = 0
        bus = self.bus

        def soft_i2c(**kw):
            self.buses_made.append(("soft", kw))
            return bus

        def hw_i2c(i, **kw):
            self.buses_made.append(("hw", i, kw))
            return bus

        def reset():
            self.resets += 1
            raise Reset()

        machine = types.ModuleType("machine")
        machine.Pin = Pin
        machine.SoftI2C = soft_i2c
        machine.I2C = hw_i2c
        machine.reset = reset
        machine.unique_id = lambda: b"\xaa\xbb\xcc\xdd\xee\xff"

        dc = types.ModuleType("device_cfg")
        base = dict(ROLE="SENSE", UNIT_CODE="UNIT01", ZONE_CODE="ZONE01",
                    HOSTNAME="unit01-s-zone01", WIFI_SSID="x", WIFI_PSK="x",
                    MQTT_HOST="10.0.0.1", MQTT_PORT=31884, TOPIC_ROOT="medcea",
                    MESSAGE_INTERVAL=30)
        base.update(device_cfg)
        for k, v in base.items():
            setattr(dc, k, v)

        self.client = FakeClient()
        self.wlan = FakeWlan()
        network = types.ModuleType("network")
        network.STA_IF = 0
        network.WLAN = lambda i: self.wlan
        ntptime = types.ModuleType("ntptime")
        ntptime.settime = lambda: None
        umqtt = types.ModuleType("umqtt")
        simple = types.ModuleType("umqtt.simple")
        simple.MQTTClient = simple.MQTTException = None
        umqtt.simple = simple

        mods = {
            "machine": machine, "device_cfg": dc, "network": network, "ntptime": ntptime,
            "umqtt": umqtt, "umqtt.simple": simple,
            "ujson": json, "ubinascii": __import__("binascii"),
            "time": self.clock.module("time"), "utime": self.clock.module("utime"),
        }
        if legacy_sensors is not None:
            mods["cea_sensors"] = legacy_sensors
        for name in ("config", "cea_edge_functions", "cea_sense", "cea_control",
                     "cea_bus", "sht4x", "sen0562", "scd30"):
            mods[name] = None
        quiet = mock.patch("sys.stdout", io.StringIO())   # the firmware prints its progress
        quiet.start()
        self.addCleanup(quiet.stop)
        patcher = mock.patch.dict(sys.modules)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, m in mods.items():
            if m is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = m
        path = mock.patch.object(sys, "path", [APP] + sys.path)
        path.start()
        self.addCleanup(path.stop)
        ef = importlib.import_module("cea_edge_functions")
        ef.connect_mqtt = lambda: self.client

        def restart_and_reconnect():
            reset()
        ef.restart_and_reconnect = restart_and_reconnect
        # MicroPython's struct.unpack accepts a buffer longer than the format,
        # and scd30.py relies on it (">H" over a word and its CRC); CPython's
        # needs the exact length. unpack_from is the MicroPython behaviour.
        importlib.import_module("scd30").struct = types.SimpleNamespace(
            pack=struct.pack, unpack=lambda fmt, buf: struct.unpack_from(fmt, buf))
        return importlib.import_module("cea_sense")

    def boot(self, sense):
        board = sense.Board(sense.cfg.SENSORS)
        board.start_all()
        board.client = self.client
        self.assertTrue(board.health("2026-11-06 12:00:00"))
        return board

    def reference_bus(self):
        self.bus = FakeBus()
        self.sht = self.bus.put(0, 0x44, SHT45(21.5, 55.0))
        self.scd = self.bus.put(1, 0x61, SCD30(612.0, 22.0, 50.0))
        self.lux = self.bus.put(2, 0x23, SEN0562(1200))

    def assert_select_discipline(self, expect_ch):
        """Every device access happens with exactly its channel open, and the hub
        is written only when the channel changes."""
        mask = 0
        for ev in self.bus.log:
            if ev[0] == "sel":
                self.assertNotEqual(ev[1], mask, "select written without a channel change")
                mask = ev[1]
            else:
                _, addr, m = ev
                self.assertEqual(m, mask)
                self.assertIn(m, [1 << c for c in expect_ch[addr]],
                              "0x%02x accessed with mask 0x%02x" % (addr, m))


class SensorDriverTest(FirmwareCase):

    def test_sht45_is_reset_at_setup_and_a_busy_read_is_retried(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        self.assertEqual(self.sht.resets, 1)
        self.sht.busy = 2                  # two NACKs, the third read answers
        board.cycle(self.clock.ms // 1000)
        self.assertIn("air_temperature", self.client.readings())
        self.sht.busy = 3                  # three NACKs: a failed read, health says so
        board.cycle(self.clock.ms // 1000 + 60)
        self.assertFalse([s for s in board.slots if s.id == "sht45_1"][0].ok)

    def test_scd30_waits_4_ms_between_a_command_and_its_read(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        dev = [s for s in board.slots if s.id == "scd30_1"][0].handle[1][0]
        self.assertEqual(dev.pause, 4000)

    def test_crc_matches_the_datasheet_vector(self):
        self.bus = FakeBus()
        self.load({})
        import sht4x
        self.assertEqual(sht4x.crc8(0xBE, 0xEF), 0x92)

    def test_sen0562_each_read_starts_a_conversion_and_waits(self):
        self.bus = FakeBus()
        dev = self.bus.root[0x23] = SEN0562(1200)
        self.load({})
        import sen0562
        s = sen0562.SEN0562(self.bus, 0x23)
        for _ in range(2):
            t0, w0 = self.clock.ms, dev.writes
            self.assertAlmostEqual(s.read(), 1000.0)
            self.assertGreaterEqual(self.clock.ms - t0, 180)
            self.assertEqual(dev.writes, w0 + 1)

    def test_sen0562_recovers_from_a_power_loss_by_itself(self):
        # Powered down after a brown-out, it answers 0 without an error; set up
        # only once, it would publish 0 lux with ok True for ever.
        self.bus = FakeBus()
        dev = self.bus.root[0x23] = SEN0562(1200)
        self.load({})
        import sen0562
        s = sen0562.SEN0562(self.bus, 0x23)
        s.read()
        dev.power_loss()
        self.assertAlmostEqual(s.read(), 1000.0)

    def test_mux_forgets_its_channel_after_a_bus_error(self):
        self.bus = FakeBus()
        self.load({})
        import cea_bus
        mux = cea_bus.Tca9548a(self.bus, HUB)
        ch3 = cea_bus.MuxedI2C(mux, 3)
        with self.assertRaises(OSError):
            ch3.readfrom(0x44, 6)           # nothing there
        self.assertIsNone(mux.ch)
        self.bus.put(3, 0x44, SHT45(20, 50)).write(b"\xfd")
        ch3.readfrom(0x44, 6)
        self.assertEqual([e for e in self.bus.log if e[0] == "sel"], [("sel", 8), ("sel", 8)])


    def test_a_hub_closes_its_siblings_before_it_opens(self):
        self.bus = FakeBus()
        self.bus.add_hub(0x71)
        self.load({})
        import cea_bus
        hubs = cea_bus.build(types.SimpleNamespace(
            BUSES=[{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9}],
            HUBS=[{"id": "mux0", "kind": "tca9548a", "bus": "i2c0", "addr": HUB},
                  {"id": "mux1", "kind": "tca9548a", "bus": "i2c0", "addr": 0x71}]))
        a, b = hubs["mux0"], hubs["mux1"]
        self.assertIs(a.siblings, b.siblings)
        a.select(0)
        b.select(3)
        self.assertEqual(self.bus.masks, {HUB: 0, 0x71: 8})
        b.select(3)                         # already open: no bus write
        a.select(0)
        self.assertEqual(self.bus.masks, {HUB: 1, 0x71: 0})
        self.assertEqual(self.bus.log[-2:], [("sel", 0, 0x71), ("sel", 1)])

    def test_a_sibling_that_cannot_close_stops_the_select(self):
        self.bus = FakeBus()
        self.load({})
        import cea_bus
        hubs = cea_bus.build(types.SimpleNamespace(
            BUSES=[{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9}],
            HUBS=[{"id": "mux0", "kind": "tca9548a", "bus": "i2c0", "addr": HUB},
                  {"id": "mux1", "kind": "tca9548a", "bus": "i2c0", "addr": 0x71}]))
        with self.assertRaises(OSError) as ctx:    # 0x71 is not on this bus
            hubs["mux0"].select(0)
        self.assertIn("0x71", str(ctx.exception))
        self.assertEqual(self.bus.mask, 0)         # mux0 opened nothing


class WiredBoardTest(FirmwareCase):

    def test_same_address_behind_two_hubs(self):
        # wiring.validate lets one address sit behind two different hubs
        # (fixture ok-two-hubs-same-addr-behind): only one channel may be open.
        self.bus = FakeBus()
        self.bus.add_hub(0x71)
        self.bus.put(0, 0x44, SHT45(18.0, 40.0))
        self.bus.put(0, 0x44, SHT45(26.0, 70.0), hub=0x71)
        cfg = dict(REFERENCE)
        cfg["HUBS"] = REFERENCE["HUBS"] + [
            {"id": "mux1", "kind": "tca9548a", "bus": "i2c0", "addr": 0x71}]
        cfg["SENSORS"] = [
            {"id": "sht_a", "driver": "sht4x", "bus": "i2c0", "hub": "mux0", "channel": 0,
             "addr": 0x44, "params": {}, "tags": [["temperature", "t_a", "C"], ["humidity", "h_a", "RH%"]]},
            {"id": "sht_b", "driver": "sht4x", "bus": "i2c0", "hub": "mux1", "channel": 0,
             "addr": 0x44, "params": {}, "tags": [["temperature", "t_b", "C"], ["humidity", "h_b", "RH%"]]},
        ]
        sense = self.load(cfg)
        board = self.boot(sense)
        for _ in range(2):
            board.cycle(self.clock.ms // 1000)
        self.assertEqual([s["ok"] for s in self.client.health()[-1]["sensors"]], [True, True])
        got = self.client.readings()
        self.assertAlmostEqual(got["t_a"]["value"], 18.0, places=1)
        self.assertAlmostEqual(got["t_b"]["value"], 26.0, places=1)
        self.assertAlmostEqual(got["h_b"]["value"], 70.0, places=1)

    def test_reference_board_publishes_every_published_tag(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        # One hardware I2C(0) for the bus, as the design template renders it,
        # with the 250 ms timeout the SCD30's clock stretching needs.
        self.assertEqual(len(self.buses_made), 1)
        kind, hw_id, kw = self.buses_made[0]
        self.assertEqual((kind, hw_id, kw["freq"], kw["timeout"]), ("hw", 0, 100000, 250000))
        self.assertEqual((kw["scl"].n, kw["sda"].n), (9, 8))
        self.assertTrue(self.scd.started)

        board.cycle(self.clock.ms // 1000)
        got = self.client.readings()
        self.assertEqual(sorted(got), ["air_humidity", "air_temperature", "co2", "light_intensity"])
        self.assertAlmostEqual(got["air_temperature"]["value"], 21.5, places=1)
        self.assertAlmostEqual(got["air_humidity"]["value"], 55.0, places=1)
        self.assertAlmostEqual(got["co2"]["value"], 612.0, places=1)
        self.assertAlmostEqual(got["light_intensity"]["value"], 1000.0, places=1)
        self.assertEqual(got["light_intensity"]["UoM"], "lx")
        self.assertEqual(got["co2"]["msg_type"], "AP")
        self.assertIn("medcea/UNIT01/ZONE01/sense/co2", self.client.topics())
        self.assertEqual(set(got["co2"]), {"unit_code", "zone_code", "msg_type", "timestamp",
                                           "device_id", "device_dns", "tag", "value", "UoM"})
        self.assert_select_discipline({0x44: [0], 0x61: [1], 0x23: [2]})

    def test_reference_is_what_the_design_template_renders(self):
        # REFERENCE stands for the shipped chamber design map; if the template
        # changes, the firmware tests must follow it.
        self.assertEqual(REFERENCE, shipped_cfg("sense-hub-sht45-scd30-lux"))

    def test_reference_board_on_software_i2c(self):
        # No shipped template uses SoftI2C, but the wiring tool offers it: the
        # same board must build one SoftI2C with the same 250 ms timeout and read.
        self.reference_bus()
        cfg = dict(REFERENCE)
        cfg["BUSES"] = [dict(REFERENCE["BUSES"][0], impl="soft")]
        sense = self.load(cfg)
        board = self.boot(sense)
        self.assertEqual(len(self.buses_made), 1)
        kind, kw = self.buses_made[0]
        self.assertEqual((kind, kw["freq"], kw["timeout"]), ("soft", 100000, 250000))
        board.cycle(self.clock.ms // 1000)
        self.assertEqual(sorted(self.client.readings()),
                         ["air_humidity", "air_temperature", "co2", "light_intensity"])

        h = self.client.health()
        self.assertEqual(len(h), 1, "health only at boot while nothing changes")
        self.assertEqual(h[0]["msg_type"], "HB")
        self.assertEqual(h[0]["tag"], "_health")
        self.assertNotIn("value", h[0])
        self.assertEqual(h[0]["sensors"], [{"id": "sht45_1", "ok": True, "err": None},
                                           {"id": "scd30_1", "ok": True, "err": None},
                                           {"id": "lux_1", "ok": True, "err": None}])
        self.assertEqual(self.resets, 0)

    def test_two_sht45_at_one_address_on_two_channels(self):
        self.bus = FakeBus()
        self.bus.put(0, 0x44, SHT45(18.0, 40.0))
        self.bus.put(1, 0x44, SHT45(26.0, 70.0))
        cfg = dict(REFERENCE)
        cfg["SENSORS"] = [
            {"id": "sht_a", "driver": "sht4x", "bus": "i2c0", "hub": "mux0", "channel": 0,
             "addr": 0x44, "params": {}, "tags": [["temperature", "t_a", "C"], ["humidity", "h_a", "RH%"]]},
            {"id": "sht_b", "driver": "sht4x", "bus": "i2c0", "hub": "mux0", "channel": 1,
             "addr": 0x44, "params": {}, "tags": [["temperature", "t_b", "C"], ["humidity", "h_b", "RH%"]]},
        ]
        sense = self.load(cfg)
        board = self.boot(sense)
        for _ in range(2):
            board.cycle(self.clock.ms // 1000)
        got = self.client.readings()
        self.assertAlmostEqual(got["t_a"]["value"], 18.0, places=1)
        self.assertAlmostEqual(got["h_a"]["value"], 40.0, places=1)
        self.assertAlmostEqual(got["t_b"]["value"], 26.0, places=1)
        self.assertAlmostEqual(got["h_b"]["value"], 70.0, places=1)
        mask = 0
        for ev in self.bus.log:     # alternating channels: a select before every access
            if ev[0] == "sel":
                self.assertNotEqual(ev[1], mask)
                mask = ev[1]
        sels = [e for e in self.bus.log if e[0] == "sel"]
        devs = [e for e in self.bus.log if e[0] == "dev"]
        self.assertGreaterEqual(len(sels), 4)
        self.assertTrue(all(m in (1, 2) for _, _, m in devs))

    def test_bad_crc_gives_no_reading_and_health_says_so(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        self.sht.bad_crc = True
        board.cycle(self.clock.ms // 1000)
        got = self.client.readings()
        self.assertNotIn("air_temperature", got)
        self.assertNotIn("air_humidity", got)
        self.assertIn("co2", got)               # the others still report
        self.assertIn("light_intensity", got)
        h = self.client.health()
        self.assertEqual(len(h), 2)
        sht = h[-1]["sensors"][0]
        self.assertEqual((sht["id"], sht["ok"]), ("sht45_1", False))
        self.assertIn("CRC", sht["err"])
        # Healthy again: one more health message, flipped back.
        self.sht.bad_crc = False
        board.cycle(self.clock.ms // 1000)
        self.assertEqual(len(self.client.health()), 3)
        self.assertTrue(self.client.health()[-1]["sensors"][0]["ok"])

    def test_init_failure_reports_and_does_not_reset(self):
        self.reference_bus()
        del self.bus.chans[0][0x44]             # the SHT45 is not plugged in
        sense = self.load(REFERENCE)
        self.clock.budget = 1000                # ~200 s of the main loop
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertEqual(self.resets, 0)
        h = self.client.health()
        self.assertGreaterEqual(len(h), 1)
        sht = h[0]["sensors"][0]
        self.assertFalse(sht["ok"])
        self.assertTrue(sht["err"].startswith("OSError"), sht["err"])
        self.assertTrue(h[0]["sensors"][1]["ok"])
        self.assertIn("co2", self.client.readings())
        self.assertEqual(len(h), 1, "no flip, no second health message")

    def test_nothing_comes_up_still_connects_and_reports(self):
        self.bus = FakeBus()                    # an empty hub
        sense = self.load(REFERENCE)
        self.clock.budget = 400
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertEqual(self.resets, 0)
        h = self.client.health()
        self.assertEqual([s["ok"] for s in h[0]["sensors"]], [False, False, False])
        self.assertEqual(self.client.readings(), {})

    def test_a_failed_sensor_is_retried_after_ten_minutes(self):
        self.reference_bus()
        sht = self.bus.chans[0].pop(0x44)
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        self.bus.put(0, 0x44, sht)              # plugged in after boot
        board.cycle(self.clock.ms // 1000)
        self.assertNotIn("air_temperature", self.client.readings())
        self.clock.advance(sense.RETRY_SECONDS * 1000)
        board.cycle(self.clock.ms // 1000)
        self.assertIn("air_temperature", self.client.readings())
        self.assertTrue(self.client.health()[-1]["sensors"][0]["ok"])

    def test_a_missing_bus_is_named_in_health(self):
        self.reference_bus()
        cfg = dict(REFERENCE)
        cfg["SENSORS"] = [dict(REFERENCE["SENSORS"][0], bus="i2c9", hub=None, channel=None)]
        sense = self.load(cfg)
        board = self.boot(sense)
        err = self.client.health()[0]["sensors"][0]["err"]
        self.assertIn("i2c9", err)

    def test_scd30_warming_up_is_no_reading_not_a_failure(self):
        self.reference_bus()
        self.scd.not_ready = 3              # the first data-ready takes ~2 s
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        board.cycle(self.clock.ms // 1000)
        self.assertNotIn("co2", self.client.readings())
        self.scd.zeros = 1                  # then a first reading of co2 0
        board.cycle(self.clock.ms // 1000)
        self.assertNotIn("co2", self.client.readings())
        board.cycle(self.clock.ms // 1000)
        self.assertIn("co2", self.client.readings())
        self.assertEqual(len(self.client.health()), 1, "no false down/up pair on _health")
        # Past the window the same states are faults.
        self.clock.advance(sense.SCD30_WARMUP_MS)
        self.scd.zeros = 1
        board.cycle(self.clock.ms // 1000)
        self.assertFalse(self.client.health()[-1]["sensors"][1]["ok"])

    def test_a_quiet_cycle_keeps_the_session_alive(self):
        self.bus = FakeBus()                    # nothing comes up: nothing to publish
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        for _ in range(3):
            board.cycle(self.clock.ms // 1000)
            self.clock.advance(31000)
        self.assertEqual(self.client.pings, 3)
        self.assertEqual(board.mqtt_failures, 0)
        # The broker dropped the session: noticed at the next quiet cycle, and
        # counted like a failed publish, so the board resets instead of
        # writing its next readings into a dead socket.
        self.client.closed = True
        before = board.last_message
        board.cycle(self.clock.ms // 1000)
        self.assertEqual(board.mqtt_failures, 1)
        self.assertEqual(board.last_message, before)

    def test_a_cycle_that_publishes_does_not_ping(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        board.cycle(self.clock.ms // 1000)
        self.assertEqual(self.client.pings, 0)

    def test_repeated_publish_failures_still_reset(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        self.client.fail = True
        self.clock.budget = 100000
        with self.assertRaises(Reset):
            sense.run()
        self.assertEqual(self.resets, 1)

    def test_health_err_has_no_quotes_and_is_short(self):
        self.bus = FakeBus()
        sense = self.load({})
        e = sense._err(ValueError("it's \"broken\" " + "x" * 200))
        self.assertNotIn("'", e)
        self.assertNotIn('"', e)
        self.assertLessEqual(len(e), 80)
        self.assertTrue(e.startswith("ValueError: its broken"))
        # And through the health message, from a driver that raises with quotes.
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        self.sht.read = lambda n: (_ for _ in ()).throw(OSError("bus 'stuck' \"low\""))
        board.cycle(self.clock.ms // 1000)
        err = self.client.health()[-1]["sensors"][0]["err"]
        self.assertNotIn("'", err)
        self.assertNotIn('"', err)


def shipped_cfg(slug):
    """BUSES/HUBS/SENSORS as onboarding renders them from a shipped board template."""
    sys.path.insert(0, os.path.join(ROOT, "edge", "src", "host"))
    try:
        import device_template
        import wiring
    finally:
        sys.path.pop(0)
    with open(os.path.join(ROOT, "edge", "templates", "boards", slug + ".json"), encoding="utf-8") as f:
        doc = json.load(f)["wiring"]
    tpl = device_template.load("SENSE")
    cfg = wiring.render_sense(doc, tpl, base_topic="medcea/UNIT01/ZONE01")["cfg"]
    return {k: cfg[k] for k in ("BUSES", "HUBS", "SENSORS")}


class BenchBoardTest(FirmwareCase):
    """The wiring the owner's bench test passed on (6 Nov 2026), from its shipped
    template: hardware I2C(0) with a 250 ms timeout, TCA9548A 0x70, SHT45 on ch7,
    SCD30 on ch6, nothing on ch0-5 and nothing but the hub on the root bus."""

    def test_the_bench_template_reads_both_sensors_on_their_channels(self):
        self.bus = FakeBus()
        self.sht = self.bus.put(7, 0x44, SHT45(20.8, 48.0))
        self.scd = self.bus.put(6, 0x61, SCD30(655.0, 21.0, 47.0))
        sense = self.load(shipped_cfg("sense-hub-bench-sht45-scd30"))
        board = self.boot(sense)
        self.assertEqual(len(self.buses_made), 1)
        kind, hw_id, kw = self.buses_made[0]
        self.assertEqual((kind, hw_id, kw["freq"], kw["timeout"]), ("hw", 0, 100000, 250000))
        self.assertEqual((kw["scl"].n, kw["sda"].n), (9, 8))
        board.cycle(self.clock.ms // 1000)
        got = self.client.readings()
        self.assertEqual(sorted(got), ["air_humidity", "air_temperature", "co2"])
        self.assertAlmostEqual(got["air_temperature"]["value"], 20.8, places=1)
        self.assertAlmostEqual(got["co2"]["value"], 655.0, places=1)
        self.assert_select_discipline({0x44: [7], 0x61: [6]})
        self.assertEqual(self.client.health()[0]["sensors"],
                         [{"id": "sht45_1", "ok": True, "err": None},
                          {"id": "scd30_1", "ok": True, "err": None}])
        self.assertEqual(self.resets, 0)
        # Interval already 2 s (the factory default): read, not rewritten.
        self.assertNotIn((0x4600, 2), self.scd.writes)
        self.assertIn((0x0010, 0), self.scd.writes)

    def test_a_stored_long_interval_is_set_to_2_s_before_the_start(self):
        # The SCD30 keeps its interval in flash. One left at 60 s by another tool
        # gets the bench test's 2 s, written before the start command, as the bench does.
        self.bus = FakeBus()
        self.bus.put(7, 0x44, SHT45(20.8, 48.0))
        self.scd = self.bus.put(6, 0x61, SCD30(655.0, 21.0, 47.0, interval=60))
        sense = self.load(shipped_cfg("sense-hub-bench-sht45-scd30"))
        self.boot(sense)
        w = self.scd.writes
        self.assertIn((0x4600, 2), w)
        self.assertLess(w.index((0x4600, 2)), w.index((0x0010, 0)))
        self.assertEqual(self.scd.interval, 2)

    def test_a_sensor_on_the_wrong_channel_is_reported_down(self):
        # The bench test's own failure: a cable in another port. The board says so
        # in _health and keeps reading the other sensor.
        self.bus = FakeBus()
        self.bus.put(5, 0x44, SHT45(20.8, 48.0))
        self.scd = self.bus.put(6, 0x61, SCD30(655.0, 21.0, 47.0))
        sense = self.load(shipped_cfg("sense-hub-bench-sht45-scd30"))
        board = self.boot(sense)
        h = {s["id"]: s for s in self.client.health()[0]["sensors"]}
        self.assertFalse(h["sht45_1"]["ok"])
        self.assertTrue(h["scd30_1"]["ok"])
        board.cycle(self.clock.ms // 1000)
        self.assertEqual(sorted(self.client.readings()), ["co2"])


class LegacyBoardTest(FirmwareCase):

    def test_legacy_scd30_goes_through_the_old_path(self):
        self.bus = FakeBus()
        calls = []
        legacy = types.ModuleType("cea_sensors")

        def set_scd30_i2c(scl, sda):
            calls.append(("set", scl, sda))
            return "handle"

        def read_scd30_sensor(h):
            calls.append(("read", h))
            return 700.0, 23.456, 48.0
        legacy.set_scd30_i2c = set_scd30_i2c
        legacy.read_scd30_sensor = read_scd30_sensor

        sense = self.load({"SENSORS": [{"driver": "scd30", "params": {"scl_pin": 9, "sda_pin": 8},
                                        "tags": ["co2", "air_temperature", "air_humidity"]}]},
                          legacy_sensors=legacy)
        board = self.boot(sense)
        board.cycle(self.clock.ms // 1000)
        self.assertEqual(calls[0][0], "set")
        self.assertIsInstance(calls[0][1], Pin)          # wrapped as before
        self.assertEqual((calls[0][1].n, calls[0][2].n), (9, 8))
        self.assertEqual(calls[1], ("read", "handle"))
        got = self.client.readings()
        self.assertEqual(sorted(got), ["air_humidity", "air_temperature", "co2"])
        self.assertEqual(got["air_temperature"]["value"], 23.46)
        self.assertEqual(got["co2"]["UoM"], "ppm")
        # No bus layer at all: no cea_bus, no SoftI2C from cea_sense.
        self.assertNotIn("cea_bus", sys.modules)
        self.assertEqual(self.buses_made, [])
        self.assertEqual(self.client.health()[0]["sensors"],
                         [{"id": "scd30", "ok": True, "err": None}])

    def test_legacy_sensor_that_does_not_initialise(self):
        self.bus = FakeBus()
        legacy = types.ModuleType("cea_sensors")
        legacy.set_scd30_i2c = lambda scl, sda: None
        sense = self.load({"SENSORS": [{"driver": "scd30", "params": {"scl_pin": 9, "sda_pin": 8},
                                        "tags": ["co2"]}]}, legacy_sensors=legacy)
        self.clock.budget = 400
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertEqual(self.resets, 0)
        self.assertEqual(self.client.health()[0]["sensors"],
                         [{"id": "scd30", "ok": False, "err": "did not initialise"}])


# The fields every reading has (cea_sense.Board._message); HB and TS add ip and mac.
READING_KEYS = {"unit_code", "zone_code", "msg_type", "timestamp", "device_id", "device_dns", "tag"}


class StatusMessageTest(FirmwareCase):
    """HB and TS carry a reading's metadata plus ip and mac, built once in
    cea_edge_functions.status_message; AP readings and SP reports do not change."""

    def test_health_carries_the_reading_metadata_and_ip_and_mac(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        self.boot(sense)
        h = self.client.health()[0]
        self.assertEqual(set(h), READING_KEYS | {"ip", "mac", "sensors"})
        self.assertEqual((h["msg_type"], h["tag"]), ("HB", "_health"))
        self.assertEqual((h["unit_code"], h["zone_code"]), ("UNIT01", "ZONE01"))
        self.assertEqual((h["device_id"], h["device_dns"]), ("aabbccddeeff", "unit01-s-zone01"))
        self.assertEqual(h["timestamp"], "2026-11-06 12:00:00")
        self.assertEqual(h["ip"], "192.168.1.57")
        self.assertEqual(h["mac"], "aa:bb:cc:dd:ee:ff")
        # medcea.device.serial_number's form is the MAC without separators.
        self.assertEqual(h["mac"].replace(":", ""), h["device_id"])

    def test_ip_and_mac_are_null_when_unreadable(self):
        self.bus = FakeBus()
        sense = self.load({})
        ef = sense.ef
        self.wlan.connected = False
        m = ef.status_message("HB", "_health")
        self.assertIsNone(m["ip"])
        self.assertEqual(m["mac"], "aa:bb:cc:dd:ee:ff")
        self.wlan.connected, self.wlan.addr = True, "0.0.0.0"
        self.assertIsNone(ef.status_message("HB", "_health")["ip"])
        self.wlan.broken = True
        m = ef.status_message("TS", "_test")
        self.assertEqual((m["ip"], m["mac"]), (None, None))
        # A port whose network module has no WLAN at all.
        del sys.modules["network"].WLAN
        m = ef.status_message("TS", "_test")
        self.assertEqual((m["ip"], m["mac"]), (None, None))
        self.assertEqual(m["device_id"], "aabbccddeeff")

    def test_an_ap_reading_is_unchanged(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        board = self.boot(sense)
        board.cycle(self.clock.ms // 1000)
        topic, co2 = [(t, p) for t, p in self.client.sent if t.endswith("/co2")][0]
        self.assertEqual(topic, "medcea/UNIT01/ZONE01/sense/co2")
        self.assertEqual(co2, {"unit_code": "UNIT01", "zone_code": "ZONE01", "msg_type": "AP",
                               "timestamp": "2026-11-06 12:00:00", "device_id": "aabbccddeeff",
                               "device_dns": "unit01-s-zone01", "tag": "co2",
                               "value": 612.0, "UoM": "ppm"})
        self.assertEqual(list(co2), ["unit_code", "zone_code", "msg_type", "timestamp",
                                     "device_id", "device_dns", "tag", "value", "UoM"])

    def test_firmware_is_null_when_unreadable(self):
        self.bus = FakeBus()
        sense = self.load({})
        with mock.patch("os.uname", side_effect=AttributeError("uname")):
            self.assertIsNone(sense.ef._firmware())


class BootTestMessageTest(FirmwareCase):

    def capture_board(self, sense, stop_at_first_cycle=False):
        """sense.Board, recorded; optionally stopped before its first cycle."""
        boards = []
        orig = sense.Board

        class Board(orig):
            def __init__(self, *a):
                orig.__init__(self, *a)
                boards.append(self)

            def cycle(self, now):
                if stop_at_first_cycle:
                    raise StopLoop()
                orig.cycle(self, now)
        sense.Board = Board
        return boards

    def test_one_test_message_after_the_first_connect(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        self.clock.budget = 3000                # many cycles
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertGreater(len(self.client.readings()), 0)
        tests = self.client.tests()
        self.assertEqual(len(tests), 1, "once per boot, never per cycle")
        topic, ts = tests[0]
        self.assertEqual(self.client.sent[0][0], topic, "the first message after the connect")
        self.assertEqual(topic, "medcea/UNIT01/ZONE01/sense/_test")
        self.assertEqual(set(ts), READING_KEYS | {"ip", "mac", "source", "firmware"})
        self.assertEqual((ts["msg_type"], ts["tag"], ts["source"]), ("TS", "_test", "board-boot"))
        self.assertEqual((ts["ip"], ts["mac"]), ("192.168.1.57", "aa:bb:cc:dd:ee:ff"))
        self.assertEqual(ts["firmware"], os.uname().release)
        self.assertEqual(ts["device_dns"], "unit01-s-zone01")

    def test_a_failed_test_message_counts_and_resets_nothing(self):
        self.reference_bus()
        sense = self.load(REFERENCE)
        self.client.fail_topics = ("/_test",)
        boards = self.capture_board(sense, stop_at_first_cycle=True)
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertEqual(self.resets, 0)
        self.assertEqual(boards[0].mqtt_failures, 1)
        self.assertEqual(len(self.client.health()), 1, "the boot health still goes out")
        # And the board carries on publishing; the next good cycle clears the count.
        self.reference_bus()
        sense = self.load(REFERENCE)
        self.client.fail_topics = ("/_test",)
        boards = self.capture_board(sense)
        self.clock.budget = 1000
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertEqual(self.resets, 0)
        self.assertIn("co2", self.client.readings())
        self.assertEqual(boards[0].mqtt_failures, 0)

    def test_a_board_with_nothing_up_still_sends_it(self):
        self.bus = FakeBus()
        sense = self.load(REFERENCE)
        self.clock.budget = 400
        with self.assertRaises(StopLoop):
            sense.run()
        self.assertEqual(len(self.client.tests()), 1)


ACTUATORS = {
    "pin_descriptions": {"5": "heater_relay"},
    "actuator_definitions": {
        "heater": {"commands": {"ON": {"actions": [{"pin": 5, "value": 1}]},
                                "OFF": {"actions": [{"pin": 5, "value": 0}]}}}},
}


class ControlBoardTest(FirmwareCase):

    def load_control(self):
        tmp = tempfile.mkdtemp(prefix="cea-control-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "actuator_config.json")
        with open(path, "w") as f:
            json.dump(ACTUATORS, f)
        self.bus = FakeBus()
        self.load({"ROLE": "CONTROL", "HOSTNAME": "unit01-c-zone01", "ACTUATOR_CONFIG": path})
        return importlib.import_module("cea_control")

    def test_boot_test_message_on_control_setpoint(self):
        control = self.load_control()
        self.clock.budget = 2000   # past the first keepalive ping (45 s)
        with self.assertRaises(StopLoop):
            control.run()
        self.assertEqual(self.client.subscribed, "medcea/UNIT01/ZONE01/control/#")
        tests = self.client.tests()
        self.assertEqual(len(tests), 1)
        topic, ts = tests[0]
        # A CONTROL board may write only control_setpoint/#.
        self.assertEqual(topic, "medcea/UNIT01/ZONE01/control_setpoint/_test")
        self.assertEqual(set(ts), READING_KEYS | {"ip", "mac", "source", "firmware"})
        self.assertEqual((ts["msg_type"], ts["source"], ts["device_dns"]),
                         ("TS", "board-boot", "unit01-c-zone01"))
        self.assertEqual(self.client.health(), [], "no HB from a CONTROL board")
        self.assertGreater(self.client.pings, 0)

    def test_a_failed_test_message_does_not_reset_control(self):
        control = self.load_control()
        self.client.fail_topics = ("/_test",)
        self.clock.budget = 2000   # past the first keepalive ping (45 s)
        with self.assertRaises(StopLoop):
            control.run()
        self.assertEqual(self.resets, 0)
        self.assertEqual(self.client.tests(), [])
        self.assertGreater(self.client.pings, 0)

    def test_an_sp_report_is_unchanged(self):
        control = self.load_control()
        control.load()
        control.apply(self.client, {"tag": "heater", "command": "ON"})
        self.assertEqual(len(self.client.sent), 1)
        topic, sp = self.client.sent[0]
        self.assertEqual(topic, "medcea/UNIT01/ZONE01/control_setpoint/heater/heater_relay")
        self.assertEqual(sp, {"pin": 5, "value": 1, "unit_code": "UNIT01", "zone_code": "ZONE01",
                              "timestamp": "2026-11-06 12:00:00", "msg_type": "SP",
                              "device_id": "aabbccddeeff", "device_dns": "unit01-c-zone01",
                              "tag": "heater_relay"})
        self.assertEqual(list(sp), ["pin", "value", "unit_code", "zone_code", "timestamp",
                                    "msg_type", "device_id", "device_dns", "tag"])


class CopyStepTest(unittest.TestCase):

    def test_flash_device_copies_every_top_level_module(self):
        """flash-device.sh copies $APP_DIR/*.py, so the new modules reach the board."""
        with open(os.path.join(ROOT, "edge", "flash-device.sh")) as f:
            src = f.read()
        self.assertIn('for f in "$APP_DIR"/*.py; do', src)
        for name in ("cea_bus.py", "sht4x.py", "sen0562.py", "scd30.py", "cea_sense.py"):
            self.assertTrue(os.path.exists(os.path.join(APP, name)), name)


if __name__ == "__main__":
    unittest.main()
