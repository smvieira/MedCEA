"""The buses a wired SENSE board carries: device_cfg.BUSES and device_cfg.HUBS.

Written by the onboarding wizard from the wiring screen (schema version 1). One
bus object per bus id, however many sensors hang off it, and one Tca9548a per
hub. A sensor behind a hub gets a MuxedI2C, which looks to its driver exactly
like an I2C bus, so a driver (scd30.SCD30 included) never knows there is a hub.
"""

from machine import Pin, SoftI2C, I2C

I2C_TIMEOUT_US = 250000


def make_bus(b, hw_id=0):
    """One I2C bus from a BUSES entry. SoftI2C unless impl is "hw".

    The timeout is for clock stretching: the SCD30 holds SCL for up to ~150 ms
    (once a day; ~30 ms otherwise), and both drivers' defaults call that a dead
    bus. 250 ms on either is what the owner's bench test of 6 Nov 2026 ran with
    (hardware I2C(0), TCA9548A, SHT45 and SCD30 behind it: every check passed)."""
    scl, sda = Pin(b["scl"]), Pin(b["sda"])
    freq = b.get("freq", 100000)
    if b.get("impl", "soft") == "hw":
        return I2C(hw_id, scl=scl, sda=sda, freq=freq, timeout=I2C_TIMEOUT_US)
    return SoftI2C(scl=scl, sda=sda, freq=freq, timeout=I2C_TIMEOUT_US)


class Tca9548a:
    """TCA9548A 1-to-8 I2C hub: one control byte, one bit per channel.

    The open channel is remembered so a select costs a bus write only when it
    changes. None means "not known" (start, or a write that failed): the next
    select writes whatever it is asked for.

    Hubs on one bus are siblings (build() gives them one shared list): a channel
    left open on one is on the wire together with the channel the next opens on
    another. So a select first closes every sibling that is open or not known.
    That is the rule wiring.validate counts on when it lets the same address sit
    behind two different hubs: only one hub channel is ever open on a bus."""

    def __init__(self, i2c, addr=0x70, siblings=None):
        self.i2c = i2c
        self.addr = addr
        self.ch = None
        self.siblings = siblings if siblings is not None else [self]
        if self not in self.siblings:
            self.siblings.append(self)

    def select(self, ch):
        if ch == self.ch:
            return
        for h in self.siblings:
            if h is not self and h.ch != -1:
                try:
                    h.deselect()
                except OSError as e:
                    # Its channel may still be open: refuse rather than read two
                    # devices at once, and say which hub is in the way.
                    raise OSError("hub 0x%02X did not close its channel (%s)" % (h.addr, e))
        self.ch = None
        self.i2c.writeto(self.addr, bytes([1 << ch]))
        self.ch = ch

    def deselect(self):
        self.ch = None
        self.i2c.writeto(self.addr, b"\x00")
        self.ch = -1

    def forget(self):
        self.ch = None


class MuxedI2C:
    """One channel of a hub, with the I2C methods the drivers call. Each selects
    the channel first; an OSError forgets the hub's state, so a hub that reset
    (brown-out) is selected again rather than trusted."""

    def __init__(self, mux, ch):
        if not 0 <= ch <= 7:
            raise ValueError("hub channel %s out of range" % ch)
        self.mux = mux
        self.ch = ch

    def _do(self, name, args, kw):
        self.mux.select(self.ch)
        try:
            return getattr(self.mux.i2c, name)(*args, **kw)
        except OSError:
            self.mux.forget()
            raise

    def writeto(self, *a, **kw):
        return self._do("writeto", a, kw)

    def readfrom(self, *a, **kw):
        return self._do("readfrom", a, kw)

    def readfrom_into(self, *a, **kw):
        return self._do("readfrom_into", a, kw)

    def writeto_mem(self, *a, **kw):
        return self._do("writeto_mem", a, kw)

    def readfrom_mem(self, *a, **kw):
        return self._do("readfrom_mem", a, kw)

    def readfrom_mem_into(self, *a, **kw):
        return self._do("readfrom_mem_into", a, kw)

    def scan(self):
        # Lists the channel's devices plus everything on the root segment (the
        # hub itself included): what a driver's "am I there" check expects.
        return self._do("scan", (), {})


def build(cfg, errors=None):
    """bus id -> bus object, hub id -> Tca9548a, from cfg.BUSES and cfg.HUBS.

    A bus or hub that cannot be built is left out and its exception put in
    `errors` (id -> exception), so the sensors on it report why instead of the
    whole board stopping."""
    out = {}
    hubs_on = {}    # bus id -> the hubs on it, shared by them as their siblings
    hw = 0
    for b in getattr(cfg, "BUSES", []):
        try:
            if b.get("kind", "i2c") != "i2c":
                raise ValueError("bus kind %s is not supported" % b.get("kind"))
            out[b["id"]] = make_bus(b, hw)
            if b.get("impl", "soft") == "hw":
                hw += 1
        except Exception as e:
            if errors is not None:
                errors[b.get("id")] = e
    for h in getattr(cfg, "HUBS", []):
        bus = out.get(h.get("bus"))
        try:
            if h.get("kind", "tca9548a") != "tca9548a":
                raise ValueError("hub kind %s is not supported" % h.get("kind"))
            if bus is None:
                raise ValueError("bus %s is not available" % h.get("bus"))
            out[h["id"]] = Tca9548a(bus, h.get("addr", 0x70),
                                    hubs_on.setdefault(h.get("bus"), []))
        except Exception as e:
            if errors is not None:
                errors[h.get("id")] = e
    return out
