"""
i2c_hub_test.py : MedCEA Instrumentation Node, I2C hub bench test (MicroPython)

Target   ESP32-S3-DevKitC-1 (N8R8 or N16R8), MicroPython ESP32_GENERIC_S3-SPIRAM_OCT
Bus      I2C SDA = GPIO8, SCL = GPIO9, 100 kHz (Edge Layer Implementation, Table 3)
Hub      TCA9548A at 0x70 (SparkFun Qwiic Mux, BOB-16784), design channel map:
           ch0  Sensirion SHT45      0x44   air temperature and RH
           ch1  Sensirion SCD30      0x61   CO2 (NDIR), secondary T and RH
           ch2  DFRobot SEN0562      0x23   illuminance (BH1750), not fitted in this test
           ch3 to ch7 spare
         CONFIG currently holds the bench wiring (SHT45 ch7, SCD30 ch6). Set SHT45_CH,
         SCD30_CH and LUX_CH back to the design map for the chamber build.

What the test does
  1. Scans the root bus and checks that only the hub answers.
  2. Selects each hub channel in turn, reads the control register back,
     scans behind the channel and compares with the expected device map.
     Any device visible on a channel where it does not belong is a FAIL
     (this is the failure-isolation property the hub was adopted for).
  3. Reads the SHT45 serial number and N high-precision measurements (CRC checked).
  4. Reads the SCD30 firmware version, starts continuous measurement at the
     configured interval and reads N measurements (CRC checked, IEEE-754 decode).
  5. Runs N interleaved hub-switch cycles (ch0 read, ch1 read) and reports
     the error count and worst-case transaction latency.
  6. Prints a PASS / FAIL summary.

Usage
  Thonny: open this file, interpreter "MicroPython (ESP32)", press F5 (runs it on the board)
  mpremote connect COMx run i2c_hub_test.py        (one-off, output on the console)
  mpremote connect COMx cp i2c_hub_test.py :main.py (runs at every boot)
  >>> import i2c_hub_test                          (from the REPL, then i2c_hub_test.main())

Edit the CONFIG block for a different channel map or sample count.
"""

import sys
import time
import struct

from machine import Pin, I2C, SoftI2C

REVISION = "2026-11-06 rev3 (bench defaults SHT45 ch7, SCD30 ch6)"

# --------------------------------------------------------------------------- CONFIG
PIN_SDA = 8
PIN_SCL = 9
I2C_FREQ = 100000           # SCD30 maximum is 100 kHz, design value in Table 3
I2C_TIMEOUT_US = 250000     # SCD30 clock-stretches up to 30 ms, 150 ms once per day
USE_SOFT_I2C = False        # set True if the hardware I2C reports ETIMEDOUT on the SCD30
I2C_PORT = 0                # hardware controller id (0 or 1), ignored for SoftI2C

HUB_ADDR = 0x70
SHT45_ADDR = 0x44
SCD30_ADDR = 0x61
LUX_ADDR = 0x23

# Hub channel of each sensor, set to the BENCH wiring of 6 Nov 2026 (SHT45 ch7, SCD30 ch6).
# Design map for the chamber build (Edge Layer note, Section 2.2): SHT45 ch0, SCD30 ch1,
# SEN0562 ch2. The expected device map of the isolation check is derived from these lines at
# run time, so every channel not named here must be empty.
SHT45_CH = 7
SCD30_CH = 6
LUX_CH = None               # set to 2 once the SEN0562 is fitted

N_SAMPLES = 5               # single-sensor samples per device
N_CYCLES = 20               # interleaved hub-switch cycles
SCD30_INTERVAL_S = 2        # 2 to 1800 s, default 2 s
SCD30_PRESSURE_MBAR = 0     # 0 disables ambient pressure compensation, else 700 to 1400
STOP_SCD30_AT_END = False   # continuous mode is the operational state and persists in NVM
TEST_SHT45_HEATER = False   # one 200 mW / 1 s heater pulse (creep mitigation command check)
LOG_CSV = False             # append cycle rows to /i2c_hub_test.csv on the node flash
# ---------------------------------------------------------------------------

# Sensirion command set (SHT4x datasheet, SCD30 interface description)
SHT45_MEASURE_HIGH = 0xFD
SHT45_READ_SERIAL = 0x89
SHT45_SOFT_RESET = 0x94
SHT45_HEATER_200MW_1S = 0x39

SCD30_START_CONT = 0x0010
SCD30_STOP_CONT = 0x0104
SCD30_SET_INTERVAL = 0x4600
SCD30_DATA_READY = 0x0202
SCD30_READ_MEAS = 0x0300
SCD30_READ_FW = 0xD100
SCD30_SOFT_RESET = 0xD304

results = []     # (check name, passed bool, detail string)


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print("[{}] {}{}".format("PASS" if ok else "FAIL", name, (" : " + detail) if detail else ""))


def crc8(data):
    """Sensirion CRC-8: polynomial 0x31, init 0xFF, no reflection, no final XOR."""
    crc = 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def words_from_frame(buf):
    """Split a Sensirion frame of (MSB, LSB, CRC) triplets into 16-bit words, verifying CRC."""
    if len(buf) % 3:
        raise ValueError("frame length {} is not a multiple of 3".format(len(buf)))
    words = []
    for i in range(0, len(buf), 3):
        if crc8(buf[i:i + 2]) != buf[i + 2]:
            raise ValueError("CRC error in word {} ({})".format(i // 3, hexs(buf)))
        words.append((buf[i] << 8) | buf[i + 1])
    return words


def hexs(buf):
    return " ".join("{:02X}".format(b) for b in buf)


def configured_channels():
    """Address -> (sensor name, config variable, configured channel), read at call time."""
    return {
        SHT45_ADDR: ("SHT45", "SHT45_CH", SHT45_CH),
        SCD30_ADDR: ("SCD30", "SCD30_CH", SCD30_CH),
        LUX_ADDR: ("SEN0562", "LUX_CH", LUX_CH),
    }


def expected_map():
    """Channel -> set of expected addresses, built from the channel settings at call time."""
    m = {}
    for addr, (_, _, ch) in configured_channels().items():
        if ch is not None:
            m.setdefault(ch, set()).add(addr)
    return m


# --------------------------------------------------------------------------- bus and hub
def make_bus():
    if USE_SOFT_I2C:
        bus = SoftI2C(scl=Pin(PIN_SCL), sda=Pin(PIN_SDA), freq=I2C_FREQ, timeout=I2C_TIMEOUT_US)
        kind = "SoftI2C"
    else:
        bus = I2C(I2C_PORT, scl=Pin(PIN_SCL), sda=Pin(PIN_SDA), freq=I2C_FREQ, timeout=I2C_TIMEOUT_US)
        kind = "I2C({})".format(I2C_PORT)
    print("Bus: {} SDA=GPIO{} SCL=GPIO{} {} kHz timeout {} ms".format(
        kind, PIN_SDA, PIN_SCL, I2C_FREQ // 1000, I2C_TIMEOUT_US // 1000))
    return bus


class Hub:
    """TCA9548A: one control byte, bit n enables downstream channel n."""

    def __init__(self, bus, addr=HUB_ADDR):
        self.bus = bus
        self.addr = addr

    def select(self, ch):
        mask = 0 if ch is None else (1 << ch)
        self.bus.writeto(self.addr, bytes([mask]))
        return mask

    def read_mask(self):
        return self.bus.readfrom(self.addr, 1)[0]

    def deselect(self):
        self.select(None)


def scan_downstream(bus):
    """Addresses that answer, excluding the hub itself (it is always visible upstream)."""
    return sorted(a for a in bus.scan() if a != HUB_ADDR)


# --------------------------------------------------------------------------- SHT45
class SHT45:
    def __init__(self, bus, addr=SHT45_ADDR):
        self.bus = bus
        self.addr = addr

    def _cmd(self, cmd, wait_ms, nbytes=6, retries=3):
        self.bus.writeto(self.addr, bytes([cmd]))
        time.sleep_ms(wait_ms)
        for attempt in range(retries):
            try:
                return self.bus.readfrom(self.addr, nbytes)
            except OSError:
                if attempt == retries - 1:
                    raise
                time.sleep_ms(2)   # sensor NACKs while still busy

    def soft_reset(self):
        self.bus.writeto(self.addr, bytes([SHT45_SOFT_RESET]))
        time.sleep_ms(2)

    def serial_number(self):
        w = words_from_frame(self._cmd(SHT45_READ_SERIAL, 1))
        return (w[0] << 16) | w[1]

    @staticmethod
    def convert(words):
        t = -45.0 + 175.0 * words[0] / 65535.0
        rh = -6.0 + 125.0 * words[1] / 65535.0
        rh = min(100.0, max(0.0, rh))
        return t, rh

    def measure(self):
        """High repeatability measurement, completes in under 10 ms."""
        return self.convert(words_from_frame(self._cmd(SHT45_MEASURE_HIGH, 10)))

    def heater_pulse_200mw_1s(self):
        """200 mW for 1 s, the datasheet returns one high-precision measurement at the end."""
        return self.convert(words_from_frame(self._cmd(SHT45_HEATER_200MW_1S, 1100)))


# --------------------------------------------------------------------------- SCD30
class SCD30:
    def __init__(self, bus, addr=SCD30_ADDR):
        self.bus = bus
        self.addr = addr

    def _write(self, cmd, arg=None):
        buf = bytearray([cmd >> 8, cmd & 0xFF])
        if arg is not None:
            hi, lo = arg >> 8, arg & 0xFF
            buf += bytes([hi, lo, crc8(bytes([hi, lo]))])
        self.bus.writeto(self.addr, buf)
        time.sleep_ms(4)   # the sensor needs about 3 ms before it will answer

    def _read(self, cmd, nbytes):
        self._write(cmd)
        return self.bus.readfrom(self.addr, nbytes)

    def firmware_version(self):
        w = words_from_frame(self._read(SCD30_READ_FW, 3))[0]
        return w >> 8, w & 0xFF

    def set_interval(self, seconds):
        self._write(SCD30_SET_INTERVAL, seconds)

    def get_interval(self):
        return words_from_frame(self._read(SCD30_SET_INTERVAL, 3))[0]

    def start_continuous(self, pressure_mbar=0):
        self._write(SCD30_START_CONT, pressure_mbar)

    def stop_continuous(self):
        self._write(SCD30_STOP_CONT)

    def data_ready(self):
        return words_from_frame(self._read(SCD30_DATA_READY, 3))[0] == 1

    @staticmethod
    def convert(words):
        """Six words (CO2, T, RH as big-endian IEEE-754 pairs) to floats."""
        vals = []
        for i in range(0, 6, 2):
            vals.append(struct.unpack(">f", struct.pack(">HH", words[i], words[i + 1]))[0])
        return tuple(vals)   # co2 ppm, temperature degC, RH %

    def read_measurement(self):
        return self.convert(words_from_frame(self._read(SCD30_READ_MEAS, 18)))

    def wait_and_read(self, timeout_ms):
        t0 = time.ticks_ms()
        while time.ticks_diff(time.ticks_ms(), t0) < timeout_ms:
            if self.data_ready():
                return self.read_measurement()
            time.sleep_ms(100)
        raise OSError("SCD30 data not ready within {} ms".format(timeout_ms))


# --------------------------------------------------------------------------- test steps
def step_root_scan(bus, hub):
    print("\n--- 1. Root bus scan")
    try:
        hub.deselect()
    except OSError as e:
        record("Hub 0x70 answers on root bus", False, "no ACK ({})".format(e))
        return False
    found = sorted(bus.scan())
    print("root bus: {}".format([hex(a) for a in found]))
    record("Hub 0x70 answers on root bus", HUB_ADDR in found)
    extra = [a for a in found if a != HUB_ADDR]
    record("No device bypasses the hub on the root bus", not extra,
           "" if not extra else "unexpected {}".format([hex(a) for a in extra]))
    return HUB_ADDR in found


def step_channel_map(bus, hub):
    print("\n--- 2. Per-channel scan and isolation")
    exp_all = expected_map()
    located = {}     # address -> channels on which it answered
    all_ok = True
    for ch in range(8):
        hub.select(ch)
        mask = hub.read_mask()
        expected = exp_all.get(ch, set())
        try:
            found = set(scan_downstream(bus))
        except OSError as e:
            found = set()
            print("ch{}: scan error {}".format(ch, e))
        for a in found:
            located.setdefault(a, []).append(ch)
        mask_ok = mask == (1 << ch)
        missing = expected - found
        unexpected = found - expected
        ok = mask_ok and not missing and not unexpected
        all_ok = all_ok and ok
        detail = "mask 0x{:02X}, found {}".format(mask, [hex(a) for a in sorted(found)])
        if missing:
            detail += ", missing {}".format([hex(a) for a in sorted(missing)])
        if unexpected:
            detail += ", UNEXPECTED {}".format([hex(a) for a in sorted(unexpected)])
        record("ch{} map".format(ch), ok, detail)
    hub.deselect()
    record("Hub deselect returns mask 0x00", hub.read_mask() == 0)
    for addr, (name, var, ch_cfg) in configured_channels().items():
        chans = located.get(addr, [])
        if chans and ch_cfg not in chans:
            print("HINT: {} (0x{:02X}) answers on ch{} but {} = {}. If that port is intended, "
                  "set {} = {} and rerun, otherwise move the cable.".format(
                      name, addr, ",".join(str(c) for c in chans), var, ch_cfg, var, chans[0]))
    return all_ok


def step_sht45(bus, hub):
    print("\n--- 3. SHT45 on ch{}".format(SHT45_CH))
    hub.select(SHT45_CH)
    s = SHT45(bus)
    try:
        s.soft_reset()
        sn = s.serial_number()
        record("SHT45 serial number read", True, "0x{:08X}".format(sn))
    except (OSError, ValueError) as e:
        record("SHT45 serial number read", False, "{} (check SHT45_CH = {})".format(e, SHT45_CH))
        return False
    good = 0
    for i in range(N_SAMPLES):
        try:
            t, rh = s.measure()
            plausible = -10.0 <= t <= 60.0 and 0.0 <= rh <= 100.0
            good += 1 if plausible else 0
            print("  SHT45 #{:d}: T = {:6.2f} degC  RH = {:6.2f} %{}".format(
                i + 1, t, rh, "" if plausible else "  (out of plausible range)"))
        except (OSError, ValueError) as e:
            print("  SHT45 #{:d}: error {}".format(i + 1, e))
        time.sleep_ms(200)
    record("SHT45 measurements valid", good == N_SAMPLES, "{}/{} good".format(good, N_SAMPLES))
    if TEST_SHT45_HEATER:
        try:
            t_before, rh_before = s.measure()
            t_heat, rh_heat = s.heater_pulse_200mw_1s()
            time.sleep_ms(1500)
            t_after, rh_after = s.measure()
            print("  heater: before {:.2f}/{:.1f}  during {:.2f}/{:.1f}  after {:.2f}/{:.1f}".format(
                t_before, rh_before, t_heat, rh_heat, t_after, rh_after))
            record("SHT45 heater pulse 200 mW / 1 s", t_heat > t_before + 0.5,
                   "dT = {:+.2f} degC".format(t_heat - t_before))
        except (OSError, ValueError) as e:
            record("SHT45 heater pulse 200 mW / 1 s", False, str(e))
    return True


def step_scd30(bus, hub):
    print("\n--- 4. SCD30 on ch{}".format(SCD30_CH))
    hub.select(SCD30_CH)
    c = SCD30(bus)
    try:
        major, minor = c.firmware_version()
        record("SCD30 firmware version read", True, "{}.{}".format(major, minor))
    except (OSError, ValueError) as e:
        record("SCD30 firmware version read", False,
               "{} (ENODEV: check SCD30_CH = {}, ETIMEDOUT: set USE_SOFT_I2C = True)".format(e, SCD30_CH))
        return None
    try:
        c.set_interval(SCD30_INTERVAL_S)
        interval = c.get_interval()
        record("SCD30 measurement interval set", interval == SCD30_INTERVAL_S, "{} s".format(interval))
        c.start_continuous(SCD30_PRESSURE_MBAR)
        record("SCD30 continuous measurement started", True,
               "pressure compensation {}".format("off" if SCD30_PRESSURE_MBAR == 0 else
                                                  "{} mbar".format(SCD30_PRESSURE_MBAR)))
    except (OSError, ValueError) as e:
        record("SCD30 configuration", False, str(e))
        return None
    good = 0
    counted = 0
    attempts = 0
    while counted < N_SAMPLES and attempts < N_SAMPLES + 2:
        attempts += 1
        try:
            co2, t, rh = c.wait_and_read((SCD30_INTERVAL_S + 3) * 1000)
            if co2 < 1.0 and counted == 0:
                # the first datum after power-up or restart can be 0 ppm while the NDIR cell settles
                print("  SCD30 warm-up datum discarded: CO2 = {:.1f} ppm".format(co2))
                continue
            counted += 1
            plausible = 300.0 <= co2 <= 10000.0 and -10.0 <= t <= 60.0 and 0.0 <= rh <= 100.0
            good += 1 if plausible else 0
            print("  SCD30 #{:d}: CO2 = {:7.1f} ppm  T = {:6.2f} degC  RH = {:6.2f} %{}".format(
                counted, co2, t, rh, "" if plausible else "  (out of plausible range)"))
        except (OSError, ValueError) as e:
            counted += 1
            print("  SCD30 #{:d}: error {}".format(counted, e))
    record("SCD30 measurements valid", good == N_SAMPLES, "{}/{} good".format(good, N_SAMPLES))
    return c


def step_cycles(bus, hub, sht_ok, scd):
    print("\n--- 5. Interleaved hub switching, {} cycles".format(N_CYCLES))
    if not sht_ok and scd is None:
        record("Hub switching cycles error-free", False,
               "skipped, neither sensor answered on its configured channel")
        return
    if not sht_ok or scd is None:
        print("  only the {} is reachable, cycles exercise a single channel".format(
            "SCD30" if not sht_ok else "SHT45"))
    s = SHT45(bus)
    errors = 0
    worst_ms = 0
    log = None
    if LOG_CSV:
        log = open("/i2c_hub_test.csv", "a")
        log.write("cycle,ms,sht45_t,sht45_rh,scd30_co2,scd30_t,scd30_rh\n")
    for i in range(N_CYCLES):
        t0 = time.ticks_ms()
        row = [i + 1]
        if sht_ok:
            try:
                hub.select(SHT45_CH)
                t, rh = s.measure()
                row += ["{:.2f}".format(t), "{:.2f}".format(rh)]
            except (OSError, ValueError) as e:
                errors += 1
                row += ["ERR", "ERR"]
                print("  cycle {} SHT45 error {}".format(i + 1, e))
        else:
            row += ["", ""]
        try:
            if scd is not None:
                hub.select(SCD30_CH)
            if scd is not None and scd.data_ready():
                co2, t2, rh2 = scd.read_measurement()
                row += ["{:.1f}".format(co2), "{:.2f}".format(t2), "{:.2f}".format(rh2)]
            else:
                row += ["", "", ""]   # SCD30 publishes every SCD30_INTERVAL_S, not every cycle
        except (OSError, ValueError) as e:
            errors += 1
            row += ["ERR", "ERR", "ERR"]
            print("  cycle {} SCD30 error {}".format(i + 1, e))
        dt = time.ticks_diff(time.ticks_ms(), t0)
        worst_ms = max(worst_ms, dt)
        row.insert(1, dt)
        line = ",".join(str(x) for x in row)
        print("  " + line)
        if log:
            log.write(line + "\n")
        time.sleep_ms(500)
    if log:
        log.close()
        print("  CSV appended to /i2c_hub_test.csv")
    hub.deselect()
    record("Hub switching cycles error-free", errors == 0,
           "{} errors in {} cycles, worst cycle {} ms".format(errors, N_CYCLES, worst_ms))


def summary():
    print("\n=== SUMMARY")
    n_ok = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        print("  {:4s} {}".format("PASS" if ok else "FAIL", name))
    print("  {}/{} checks passed : {}".format(n_ok, len(results),
                                            "ALL PASS" if n_ok == len(results) else "FAILURES PRESENT"))
    return n_ok == len(results)


def main():
    results.clear()
    print("MedCEA Instrumentation Node : I2C hub bench test, script {}".format(REVISION))
    print("MicroPython {} on {}".format(sys.version, sys.platform))
    bus = make_bus()
    hub = Hub(bus)
    if not step_root_scan(bus, hub):
        print("Hub not found. Check SDA/SCL (GPIO8/GPIO9), 3.3 V, pull-ups and the Qwiic cable, then rerun.")
        return summary()
    print("Channel map: SHT45 ch{}, SCD30 ch{}, SEN0562 {}".format(
        SHT45_CH, SCD30_CH, "not fitted" if LUX_CH is None else "ch{}".format(LUX_CH)))
    step_channel_map(bus, hub)
    sht_ok = step_sht45(bus, hub)
    scd = step_scd30(bus, hub)
    step_cycles(bus, hub, sht_ok, scd)
    if scd is not None and STOP_SCD30_AT_END:
        hub.select(SCD30_CH)
        try:
            scd.stop_continuous()
            print("SCD30 continuous measurement stopped")
        except OSError as e:
            print("SCD30 stop failed: {}".format(e))
        hub.deselect()
    return summary()


if __name__ == "__main__":
    main()
