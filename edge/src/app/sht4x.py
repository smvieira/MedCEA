"""Sensirion SHT4x (SHT45) temperature and humidity, I2C.

One command (0xFD: measure, high precision), 10 ms, six bytes back: two words,
each followed by its CRC-8 (poly 0x31, init 0xFF). A word whose CRC does not
match is not a reading: measure() raises rather than publish a corrupt value.
The sensor NACKs a read while it is still converting, so the read is tried up
to three times, 2 ms apart (as the owner's bench test does).
"""

import time

CMD_MEASURE_HIGH = 0xFD
CMD_SOFT_RESET = 0x94
READ_TRIES = 3


def crc8(b0, b1):
    crc = 0xFF
    for byte in (b0, b1):
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x31) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


class SHT4x:

    def __init__(self, i2c, addr=0x44):
        self.i2c = i2c
        self.addr = addr

    def soft_reset(self):
        self.i2c.writeto(self.addr, bytes([CMD_SOFT_RESET]))
        time.sleep_ms(2)

    def _read(self, n):
        for i in range(READ_TRIES):
            try:
                return self.i2c.readfrom(self.addr, n)
            except OSError:
                if i == READ_TRIES - 1:
                    raise
                time.sleep_ms(2)

    def measure(self):
        """(temperature C, relative humidity %). Raises OSError (bus) or
        ValueError (CRC)."""
        self.i2c.writeto(self.addr, bytes([CMD_MEASURE_HIGH]))
        time.sleep_ms(10)
        d = self._read(6)
        if crc8(d[0], d[1]) != d[2] or crc8(d[3], d[4]) != d[5]:
            raise ValueError("SHT4x CRC mismatch")
        t = -45 + 175 * ((d[0] << 8) | d[1]) / 65535
        rh = -6 + 125 * ((d[3] << 8) | d[4]) / 65535
        return t, min(100.0, max(0.0, rh))
