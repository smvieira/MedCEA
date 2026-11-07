"""DFRobot SEN0562, the IP68 ambient light sensor (a BH1750 inside), I2C 0x23.

As DFRobot's wiki example does it: write 0x10 (continuous, high resolution),
then read two bytes; lux = raw / 1.2. The mode is written again before every
read, not once: a BH1750 that lost power (its own 5 V rail, a replugged cable)
comes back powered down and still answers with two bytes, the last value or 0,
so a sensor set up only once would publish a frozen reading with nothing to say
it is wrong. A fresh mode write means a fresh conversion, which takes up to
180 ms, so every read waits that long (well inside a 30 s interval).
"""

import time

MODE_CONT_HIGH_RES = 0x10
MEASURE_MS = 180


class SEN0562:

    def __init__(self, i2c, addr=0x23):
        self.i2c = i2c
        self.addr = addr
        # Touches the sensor once, so an absent one fails at setup.
        self.i2c.writeto(self.addr, bytes([MODE_CONT_HIGH_RES]))

    def read(self):
        """Illuminance in lux. Raises OSError when the sensor does not answer."""
        self.i2c.writeto(self.addr, bytes([MODE_CONT_HIGH_RES]))
        time.sleep_ms(MEASURE_MS)
        d = self.i2c.readfrom(self.addr, 2)
        return ((d[0] << 8) | d[1]) / 1.2
