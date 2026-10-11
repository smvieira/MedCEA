import time
from scd30 import SCD30 # Make sure this library is available
# NOTE (MedCEA): the original module imported `config` here for retry
# counts it never read. Dropped: config.py now imports the generated
# device_cfg, and a driver importing the device's identity back would be a
# cycle for nothing.
import onewire
import ds18x20
import ubinascii
import machine 
from machine import ADC, UART, SoftI2C,I2C, Pin
from scd4x import SCD4xSensirion
from sensor_pack_2.bus_service import I2cAdapter

# --- Constants for Retry Logic ---
SCDx_READ_RETRIES = 3
SCDx_RETRY_DELAY_MS = 500  # Milliseconds to wait between retries

# read_scd30_sensor() below reads SCD30_-prefixed names that the fleet copy of
# this module never defined, so the SCD30 path raised NameError on its first
# call and the sensor looked like a wiring fault. Defined here rather than by
# renaming the uses, so this file stays diffable against the fleet copy.
SCD30_READ_RETRIES = SCDx_READ_RETRIES
SCD30_RETRY_DELAY_MS = SCDx_RETRY_DELAY_MS


# --- Constants for Retry Logic ---


def set_scd4x_i2c(i2c_id=0, scl_pin=17, sda_pin=18, i2c_freq=400_000, altitude_masl=160, disable_auto_cal=True):
    """
    Initializes and configures an SCD40 CO2 sensor over I2C.

    Args:
        i2c_id (int): The I2C bus ID (e.g., 0 or 1).  Defaults to 1.
        scl_pin (int): The SCL pin number. Defaults to 17.
        sda_pin (int): The SDA pin number. Defaults to 18.
        i2c_freq (int): The I2C frequency. Defaults to 400000.
        altitude_masl (int):  Meters Above Sea Level (MASL). Defaults to 160.
        disable_auto_cal (bool):  True to disable auto-calibration, False to enable. Defaults to True.

    Returns:
        sensor: Returns the initialized SCD4X sensor object.  This allows you to
               easily read data from the sensor after it has been set up.
               Returns None on error.
    """
    try:
        # Initialize I2C
        i2c = I2C(i2c_id, scl=Pin(scl_pin), sda=Pin(sda_pin), freq=i2c_freq)
        adaptor = I2cAdapter(i2c)

        # Initialize the SCD4X sensor.  Error handling is crucial here.
        try:
            sensor = SCD4xSensirion(adaptor)
        except Exception as e:
            print(f"Error initializing SCD40: {e}")
            return None  # Exit if sensor initialization fails

        # Force sensor to IDLE mode before configuration.  This is important!
        sensor.start_measurement(start=False, single_shot=False) #  Use the correct method name
        sid = sensor.get_id()  # Use serial_number, not get_id()
        print(f"Sensor serial number: {sid}")

        temperature_offset = sensor.get_temperature_offset()
        
        print(f"Get temperature offset from sensor: {temperature_offset:.2f} Celsius")  # Format output

        print(f"Set my place M.A.S.L. to {altitude_masl} meter")
        sensor.altitude = altitude_masl
        masl = sensor.altitude
        print(f"Get M.A.S.L. from sensor: {masl} meter")

        # data ready.  Use data_ready property.
        if sensor.get_data_status():
            print("Measurement data can be read!")
        else:
            print("Measurement data missing!")

        # Disable auto-calibration if requested
        sensor.set_auto_calibration(value= not disable_auto_cal)
        if not disable_auto_cal:
            print("The automatic self-calibration is ON!")
        else:
            print("The automatic self-calibration is OFF!")
            
        return sensor # Return the sensor object
    except Exception as e:
        print(f"An error occurred: {e}")
        return None  # Return None on any error

def read_scd4x_sensor(sensor):
    wt = sensor.get_conversion_cycle_time()
    print(f"conversion cycle time [ms]: {wt}")
    print("Periodic measurement started")
    sensor.start_measurement(start=True, single_shot=False) 
    time.sleep_ms(wt)
    
    for attempt in range(SCDx_READ_RETRIES):
        try:
            # Crucial: Check if data is ready before reading
            if sensor.get_data_status() == 1:
                # Data is ready, attempt to read
                measurement = sensor.get_measurement_value()
                if measurement and len(measurement) == 3:
                    co2, temp, hum = measurement
                    # Add basic plausibility checks
                    if co2 > 0 and co2 < 10000 and temp > -40 and temp < 120 and hum >= 0 and hum <= 100:
                        print(f"SCD30 Read OK (Attempt {attempt + 1}): CO2={co2:.1f}, T={temp:.1f}, RH={hum:.1f}")
                        sensor.start_measurement(start=False, single_shot=False) 
                        return co2, temp, hum
                    else:
                        # Reading successful but values seem unrealistic
                        print(f"Warning: Unrealistic SCD30 values (Attempt {attempt + 1}): {measurement}. Retrying...")
                        # Continue to the retry delay below
                else:
                    # read_measurement returned None or unexpected format
                    print(f"Warning: Invalid measurement format received (Attempt {attempt + 1}): {measurement}. Retrying...")
                    # Continue to the retry delay below
            else:
                # Data not ready yet
                print(f"SCDx data not ready (Attempt {attempt + 1}). Waiting...")
                # Fall through to the retry delay, sensor might be measuring

        except Exception as e:
            # Handles I2C communication errors (often OSError) or library issues
            print(f"Error reading SCDx sensor (Attempt {attempt + 1}/{SCDx_READ_RETRIES}): {type(e).__name__}: {e}")

        # Wait before the next retry (if it's not the last attempt)
        if attempt < SCDx_READ_RETRIES - 1:
            print(f"Waiting {SCDx_RETRY_DELAY_MS}ms before next attempt...")
            time.sleep_ms(SCDx_RETRY_DELAY_MS)

    # If loop completes without returning, all retries failed
    print(f"Failed to read SCDx sensor after {SCDx_READ_RETRIES} attempts.")
    return None, None, None



def set_scd30_i2c(scl_pin, sda_pin):
    """Sets up the SCD30 sensor via I2C with error handling."""
    try:
        # Ensure pins are valid Pin objects if they aren't already
        if not isinstance(scl_pin, Pin) or not isinstance(sda_pin, Pin):
             print("Error: SCL/SDA pins must be Pin objects.")
             # Or attempt to create them:
             # scl_pin = Pin(scl_pin)
             # sda_pin = Pin(sda_pin)
             return None

        i2c = SoftI2C(scl=scl_pin, sda=sda_pin, freq=100000) # Standard I2C frequency
        sensor = SCD30(i2c, 0x61) # Default SCD30 I2C address

        # Optional: Configure sensor settings here if needed
        # sensor.set_measurement_interval(SCD30_MEASUREMENT_INTERVAL_S)
        # sensor.start_periodic_measurement() # Start measurements if not auto-started
        # sensor.set_automatic_self_calibration(asc_enabled=True) # Recommended

        print("SCD30 Sensor initialized.")
        # Wait briefly for sensor to be ready for first reading
        print("Waiting for initial SCD30 reading readiness...")
        # It might take a few seconds after power-on/init
        initial_wait_time = 5 # seconds
        for _ in range(initial_wait_time * 2): # Check readiness periodically
            if sensor.get_status_ready() == 1:
                print("SCD30 ready.")
                break
            else:
                print("Warning: SCD30 did not become ready within the initial wait time.")
                time.sleep_ms(500)
            # Proceed anyway, the read function will handle retries/readiness check
        return sensor
    except Exception as e:
        print(f"CRITICAL: Error initializing SCD30 sensor: {e}")
        print("Check I2C wiring (SCL/SDA), power, and sensor address (0x61).")
        return None # Return None to indicate setup failure



def read_scd30_sensor(sensor):
    """
    Reads CO2, temperature, and humidity data from the SCD30 sensor.

    This function continuously polls the SCD30 sensor until it indicates
    that measurement data is ready. Once data is available, it reads the
    CO2 concentration, temperature, and humidity values and formats them
    into strings with specific precision.

    Returns:
        tuple: A tuple containing three strings:
               - co2_str (str): CO2 concentration formatted to 3 decimal places.
               - temp_str (str): Temperature formatted to 1 decimal place.
               - hum_str (str): Humidity formatted to 1 decimal place.

    Raises:
        Exception: If any error occurs during sensor communication or data
                   processing, it might propagate from the underlying
                   `scd30` library functions. Refer to the `scd30` library
                   documentation for specific exceptions.

    Note:
        - This function assumes the SCD30 sensor has been properly initialized
          prior to calling it.
        - The formatting of the sensor values into strings is done within this
          function. Consider separating data acquisition and data formatting
          for greater code flexibility.

    Example:
        co2_value, temperature_value, humidity_value = read_sensor()
        print(f"CO2: {co2_value} ppm, Temperature: {temperature_value} C, Humidity: {humidity_value} %")
    """
    if sensor is None:
        print("Error: SCD30 sensor object is None. Cannot read.")
        return None, None, None

    for attempt in range(SCD30_READ_RETRIES):
        try:
            # Crucial: Check if data is ready before reading
            if sensor.get_status_ready() == 1:
                # Data is ready, attempt to read
                measurement = sensor.read_measurement()
                if measurement and len(measurement) == 3:
                    co2, temp, hum = measurement
                    # Add basic plausibility checks
                    if co2 > 0 and co2 < 10000 and temp > -40 and temp < 120 and hum >= 0 and hum <= 100:
                        print(f"SCD30 Read OK (Attempt {attempt + 1}): CO2={co2:.1f}, T={temp:.1f}, RH={hum:.1f}")
                        return co2, temp, hum
                    else:
                        # Reading successful but values seem unrealistic
                        print(f"Warning: Unrealistic SCD30 values (Attempt {attempt + 1}): {measurement}. Retrying...")
                        # Continue to the retry delay below

                else:
                    # read_measurement returned None or unexpected format
                    print(f"Warning: Invalid measurement format received (Attempt {attempt + 1}): {measurement}. Retrying...")
                    # Continue to the retry delay below

            else:
                # Data not ready yet
                print(f"SCD30 data not ready (Attempt {attempt + 1}). Waiting...")
                # Fall through to the retry delay, sensor might be measuring

        except Exception as e:
            # Handles I2C communication errors (often OSError) or library issues
            print(f"Error reading SCD30 sensor (Attempt {attempt + 1}/{SCD30_READ_RETRIES}): {type(e).__name__}: {e}")

        # Wait before the next retry (if it's not the last attempt)
        if attempt < SCD30_READ_RETRIES - 1:
            print(f"Waiting {SCD30_RETRY_DELAY_MS}ms before next attempt...")
            time.sleep_ms(SCD30_RETRY_DELAY_MS)

    # If loop completes without returning, all retries failed
    print(f"Failed to read SCD30 sensor after {SCD30_READ_RETRIES} attempts.")
    return None, None, None


def set_water_level_sensor(uart_id, tx_pin, rx_pin, power_pin, signal_pin, adc_width, adc_atten, baudrate=115200):
    """
    Initializes the water level sensor and related peripherals (UART, power control, ADC).

    This function configures the UART communication (though it's not used in the
    water level reading itself, so its purpose here might need clarification),
    power control, and ADC for reading data from a water level sensor.
    It allows customization of UART settings and ADC properties.

    Args:
        uart_id (int): The ID of the UART peripheral to use (e.g., 1 or 2).
                       Note: This UART is initialized but not used in the
                       'read_water_level_sensor' function as provided.
                       Its purpose should be clarified.
        baudrate (int): The baud rate for UART communication.
        tx_pin (machine.Pin): The Pin object for the UART TX line.
        rx_pin (machine.Pin): The Pin object for the UART RX line.
        power_pin (machine.Pin): The Pin object to control the sensor's power.
        signal_pin (machine.Pin): The Pin object connected to the sensor's analog output.
        adc_width (int, optional): The ADC width (resolution).
                                  Defaults to ADC.WIDTH_12BIT.
        adc_atten (int, optional): The ADC attenuation.
                                  Defaults to ADC.ATTN_11DB.

    Returns:
        tuple: A tuple containing:
            uart (machine.UART): The initialized UART object.
                                 Note: This UART is initialized but not used
                                 in the provided 'read_water_level_sensor'
                                 function.
            power (machine.Pin): The Pin object for power control.
            signal (machine.ADC): The initialized ADC object.

    Raises:
        Exception: If any error occurs during peripheral initialization,
                   it might propagate from the underlying machine or ADC
                   library functions. Refer to their documentation for
                   specific exceptions.

    Note:
        - Ensure that the provided pin numbers are valid and not already
          in use by other peripherals.
        - The power control pin is initially set to LOW (0) to turn off
          the sensor.
        - The ADC attenuation is set to 11 dB, which corresponds to an
          input range up to approximately 3.3V. Adjust this if your
          sensor's output range is different.
        - The purpose of initializing the UART in this function when it's
          not used in 'read_water_level_sensor' should be clarified.
          If it's intended for a different communication method with the
          sensor, that should be documented.

    Example:
        >>> from machine import Pin
        >>> uart_to_use, sensor_power, sensor_signal = setup_water_level_sensor(
        ...     uart_id=1,
        ...     baudrate=115200,
        ...     tx_pin=Pin(16),
        ...     rx_pin=Pin(17),
        ...     power_pin=Pin(5),
        ...     signal_pin=Pin(34)
        ... )
    """

    # Initialize UART
#    tx_pin=Pin(tx_pin)
#    from machine import SoftI2C, Pin, ADC, UART
    uart = UART(uart_id, baudrate=baudrate, tx=tx_pin, rx=rx_pin)

    # Setup power pin
    power = Pin(power_pin, Pin.OUT)
    power.value(0)  # Initially turn off the sensor

    # Setup ADC
    signal = ADC(Pin(signal_pin))
    signal.width(adc_width)
    signal.atten(adc_atten)

    return uart, power, signal


def read_water_level_sensor(power, signal, max_water_level=1500):
    """
    Reads the water level from the sensor and calculates it as a percentage.

    This function controls the power to the water level sensor, reads the analog
    value from the sensor using the ADC, and calculates the water level as a
    percentage relative to a maximum water level.

    Args:
        power (machine.Pin): The Pin object used to control the sensor's power.
        signal (machine.ADC): The initialized ADC object used to read the sensor's output.
        max_water_level (int, optional): The maximum ADC reading corresponding to 100%
                                      water level. Defaults to 1500.

    Returns:
        tuple: A tuple containing:
            water_level_pct (int): The water level as a percentage (0-100).
            UoM (str): The unit of measure for the water level, which is always '%'.

    Raises:
        Exception: If any error occurs during power control or ADC reading,
                   it might propagate from the underlying machine or ADC
                   library functions. Refer to their documentation for
                   specific exceptions.

    Note:
        - It's crucial that the 'max_water_level' value is calibrated for
          your specific sensor and setup. This value represents the ADC reading
          when the water level is at its maximum.
        - The sensor is powered on briefly to take a reading and then powered
          off to conserve power.

    Example:
        >>> from machine import Pin, ADC
        >>> # Assuming 'sensor_power' and 'sensor_signal' are initialized Pin and ADC objects
        >>> water_pct, unit = read_water_level_sensor(sensor_power, sensor_signal, max_water_level=2000)
        >>> print(f"Water level: {water_pct} {unit}")
    """
    power.value(1)  # Power on the sensor
    time.sleep_ms(10)  # Wait 10ms for sensor to stabilize
    value = signal.read()  # Read the analog value (0-4095 range on ESP32)
    power.value(0)  # Power off the sensor
    water_level_pct = int(value / max_water_level * 100)
    UoM = '%'
    return water_level_pct, UoM




def set_ground_temperature_sensor(groundtemp_data_pin):
    """
    Initializes the DS18B20 temperature sensor on a OneWire bus.

    This function sets up the OneWire communication and creates a DS18X20
    object for interacting with the temperature sensor.

    Args:
        data_pin (machine.Pin): The Pin object connected to the DS18B20 data line.

    Returns:
        tuple: A tuple containing:
            ow (onewire.OneWire): The initialized OneWire object.
            ds (ds18x20.DS18X20): The initialized DS18X20 object.
            sensor_addresses (list): A list of the addresses of the DS18B20 sensors
                                     found on the OneWire bus.

    Raises:
        Exception: If any error occurs during OneWire or DS18X20 initialization,
                   it might propagate from the underlying machine, onewire, or ds18x20
                   library functions. Refer to their documentation for specific exceptions.

    Note:
        - Ensure that the provided pin number is valid and not already in use by other peripherals.
        - This function scans for DS18B20 devices on the OneWire bus and stores their addresses.
          If you have multiple sensors, you can use these addresses to read from specific sensors.

    Example:
        >>> from machine import Pin
        >>> data_pin = Pin(17)
        >>> ow, ds, addresses = setup_ground_temperature_sensor(data_pin)
        >>> print("Found DS18B20 devices:", addresses)
    """
    try:
        dat = machine.Pin(groundtemp_data_pin)
        ow = onewire.OneWire(dat)
        ds = ds18x20.DS18X20(ow)
        roms = ds.scan()
        print('Found DS18B20 devices: ', [ubinascii.hexlify(rom).decode() for rom in roms])
        if not roms:
             print("WARNING: No DS18B20 sensors detected!")
        return ow, ds, roms
    except Exception as e:
        print(f"Error setting up DS18B20: {e}")
        # Optional: Trigger a reset if setup fails critically
        # print("Critical sensor setup failed. Restarting.")
        # time.sleep(5)
        # machine.reset()
        return None, None, [] # Return safely


def read_ground_temperature(ow, ds, sensor_addresses):
    """
    Reads the temperature from the DS18B20 sensor(s).

    This function triggers a temperature conversion on the DS18B20 sensor(s)
    and then reads the temperature values. If there are multiple sensors on the
    bus, it reads the temperature from each sensor.

    Args:
        ow (onewire.OneWire): The initialized OneWire object.
        ds (ds18x20.DS18X20): The initialized DS18X20 object.
        sensor_addresses (list): A list of the addresses of the DS18B20 sensors
                                 on the OneWire bus (obtained from setup_ground_temperature_sensor).

    Returns:
        tuple or dict: If there's only one sensor, returns a tuple:
                       (temperature (float), unit_of_measure (str)).
                       If there are multiple sensors, returns a dictionary where
                       keys are sensor addresses (bytes) and values are
                       (temperature (float), unit_of_measure (str)) tuples.

    Raises:
        Exception: If any error occurs during temperature conversion or reading,
                   it might propagate from the underlying ds18x20 library functions.
                   Refer to its documentation for specific exceptions.

    Note:
        - The temperature conversion process requires a delay (750ms). This function
          includes that delay.
        - If you have multiple sensors, this function returns a dictionary, allowing
          you to identify the temperature from each sensor.

    Example (Single Sensor):
        >>> from machine import Pin
        >>> data_pin = Pin(17)
        >>> ow, ds, addresses = setup_ground_temperature_sensor(data_pin)
        >>> temp, unit = read_ground_temperature(ow, ds, addresses)
        >>> print(f"Ground Temperature: {temp} {unit}")

    Example (Multiple Sensors):
        >>> from machine import Pin
        >>> data_pin = Pin(17)
        >>> ow, ds, addresses = setup_ground_temperature_sensor(data_pin)
        >>> temps = read_ground_temperature(ow, ds, addresses)
        >>> for addr, (temp, unit) in temps.items():
        ...     print(f"Sensor {addr}: {temp} {unit}")
    """
#    import time
#    import ubinascii
    SENSOR_READ_RETRIES = 3
    SENSOR_RETRY_DELAY_MS = 200 # Milliseconds to wait between retries
    DS18B20_CONVERSION_TIME_MS = 750 # Standard conversion time
    if not ds or not sensor_addresses:
        print("Error: DS18B20 sensor not initialized or no addresses found.")
        return None, "C"

    temperatures = {}
    unit = "C" # Standard unit for DS18B20

    # Request temperature conversion for all sensors
    try:
        ds.convert_temp()
    except onewire.OneWireError as e:
        print(f"Error starting temperature conversion: {e}")
        return None, unit # Fail early if conversion command fails

    # Wait for conversion to complete
    time.sleep_ms(DS18B20_CONVERSION_TIME_MS)

    # Read temperature from each sensor with retries
    successful_reads = 0
    total_temp = 0.0

    for rom in sensor_addresses:
        rom_str = ubinascii.hexlify(rom).decode()
        temp = None
        for attempt in range(SENSOR_READ_RETRIES):
            try:
                temp = ds.read_temp(rom)
                # Basic validation (DS18B20 range is -55 to +125 C)
                if temp < -55.0 or temp > 125.0:
                    print(f"Warning: Unrealistic temp {temp}°C from {rom_str} (Attempt {attempt+1}). Retrying...")
                    # Treat unrealistic temp as a read error for retry purposes
                    if attempt < SENSOR_READ_RETRIES - 1:
                         time.sleep_ms(SENSOR_RETRY_DELAY_MS)
                    temp = None # Ensure it's marked as failed if last attempt
                    continue # Go to next attempt

                # If read is successful and plausible
                print(f"Successfully read {temp}°C from {rom_str} (Attempt {attempt+1})")
                successful_reads += 1
                total_temp += temp
                break # Exit retry loop for this sensor

            except Exception as e: # Catch CRC error or others
                print(f"Error reading sensor {rom_str} (Attempt {attempt + 1}/{SENSOR_READ_RETRIES}): {e}")
                if attempt < SENSOR_READ_RETRIES - 1:
                    time.sleep_ms(SENSOR_RETRY_DELAY_MS) # Wait before retrying
                else:
                    print(f"Failed to read sensor {rom_str} after {SENSOR_READ_RETRIES} attempts.")
                    # temp remains None

        # Optional: Store individual temps if needed
        temperatures[rom_str] = temp

    # Calculate average or return None
    if successful_reads > 0:
        avg_temp = total_temp / successful_reads
        return avg_temp, unit
    else:
        print("Error: Failed to get any valid temperature readings after retries.")
        return None, unit

