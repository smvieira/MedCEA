# Import the ntptime module for setting the device time via NTP (Network Time Protocol).
import ntptime
# Import the utime module for working with time and dates.
import utime
# Import the network module for working wlan.
import network
# Import the CEA configurations.
import config as cfg
# Import the MQTT module
from umqtt.simple import MQTTClient

import machine
 

def _set_hostname_early(name):
  """network.hostname() is module-level and must be set before the interface
  comes up, so it gets its own attempt before WLAN() exists."""
  import network
  try:
    network.hostname(name)
    return "network.hostname"
  except (AttributeError, ValueError, OSError) as e:
    # Not silent. A hostname that does not stick was the cause of a real bug:
    # the board kept MicroPython's default 'mpy-esp32s3', registered THAT with
    # DHCP, and every name the provisioning script printed was wrong.
    # MicroPython caps the hostname length, and an over-long name raises here.
    print("hostname: network.hostname(%r) refused: %s" % (name, e))
    return None


def _set_hostname_late(w, name):
  """Fallbacks for older firmware: the deprecated config(hostname=) form, then
  dhcp_hostname as understood by the UNIT01 WROOM-32 boards."""
  for key in ("hostname", "dhcp_hostname"):
    try:
      w.config(**{key: name})
      return "config(%s=)" % key
    except (ValueError, OSError) as e:
      print("hostname: config(%s=%r) refused: %s" % (key, name, e))
  return None


def _read_hostname(w):
  import network
  try:
    return network.hostname()
  except (AttributeError, OSError):
    pass
  for key in ("hostname", "dhcp_hostname"):
    try:
      return w.config(key)
    except (ValueError, OSError, KeyError):
      continue
  return None


def connect_wifi(ssid, password, hostname=None, timeout=30):
  """Join a network under a name the router will actually register.

  Pass cfg.hostname (unit01-s-zone01): letters, digits and hyphens only, as
  RFC 1123 requires — DHCP servers quietly drop or mangle anything else. It is
  the board's one name, so it is also the device_dns in its payloads.

  Returns the ifconfig tuple, or None if the board did not associate.
  """
  import network
  how = _set_hostname_early(hostname) if hostname else None

  wlan = network.WLAN(network.STA_IF)
  wlan.active(True)
  if hostname and how is None:
    how = _set_hostname_late(wlan, hostname)

  # Report what actually stuck, BEFORE DHCP uses it. The name the board
  # registers is whatever this returns, not whatever was asked for.
  actual = _read_hostname(wlan)
  if hostname and actual != hostname:
    print("hostname: WANTED %r, BOARD REPORTS %r" % (hostname, actual))
  print("hostname   :", actual, "(via %s)" % how if how else "(NOT SET)")

  if not wlan.isconnected():
    print("Connecting to network...")
    wlan.connect(ssid, password)
    t0 = utime.ticks_ms()
    # Bounded. The fleet copy spun on `while not connected: pass`, so a wrong
    # passphrase was a board that looked alive and never said why.
    while not wlan.isconnected():
      if utime.ticks_diff(utime.ticks_ms(), t0) > timeout * 1000:
        print("wifi: timed out joining %r after %ds" % (ssid, timeout))
        return None
      utime.sleep_ms(250)

  print("Network config:", {
    "mac": wlan.config("mac"),
    "ssid": wlan.config("essid"),
    "channel": wlan.config("channel"),
  }, wlan.ifconfig())
  return wlan.ifconfig()


# Get current timestamp.
def get_timestamp():
    """ Returns the current timestamp string"""
    t = utime.localtime()
    return '{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}'.format(t[0], t[1], t[2], t[3], t[4], t[5])


# Define a function to set the device's real-time clock (RTC) using NTP.
def set_device_time():
    """Sets the device time using NTP and prints the current timestamp."""
    try:
        # Attempt to synchronize the device's time with an NTP server.
        ntptime.settime()
        # Get the current time as a tuple representing (year, month, day, hour, minute, second, weekday, yearday).
        current_time = utime.localtime()
        # Format the time tuple into a human-readable string with the format YYYY-MM-DD HH:MM:SS.
        # We unpack the first six elements of the tuple (year to second) into the format string.
        timestamp_str = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(*current_time[:6])
        # Print a message indicating that the time has been set and display the current timestamp.
        print("Time set to:", timestamp_str)
        # Return True to indicate that the time setting was successful.
        return True
    # Catch any OSError exceptions that might occur during the NTP time setting process.
    # This can happen if there is no network connection or if the NTP server cannot be reached.
    except OSError as e:
        # Print an error message indicating that setting the time via NTP failed and show the specific error.
        print(f"Error setting time via NTP: {e}")
        # Provide a helpful suggestion to check the internet connection.
        print("Make sure you have a working internet connection.")
        # Return False to indicate that the time setting failed.
        return False
    
def connect_mqtt():
    """
    Establishes a connection to the MQTT broker.

    This function initializes an MQTT client using the configuration parameters
    defined in the 'cfg' object (specifically 'cfg.client_id' and 'cfg.mqtt_server').
    It attempts to connect to the broker and prints a success message upon
    successful connection.

    Returns:
        MQTTClient: An instance of the MQTTClient object, representing the
                    connection to the broker.

    Raises:
        OSError: If an error occurs during the connection attempt (e.g.,
                connection refused, network issues). This exception is
                raised by the 'client.connect()' method.

    Example:
        client = connect_mqtt()  # Establishes the MQTT connection
    """
    global client_id, mqtt_server
    # user/password: this board's own broker credential (device_cfg.py). A
    # refused CONNACK raises OSError, the caller restarts the board, and the
    # retry lands once the credential row has reached the broker (seconds).
    client = MQTTClient(cfg.client_id, cfg.mqtt_server, cfg.mqtt_port,
                        user=cfg.mqtt_user, password=cfg.mqtt_pass,
                        keepalive=max(60, 3 * cfg.message_interval))
    client.connect()
    print('Connected to %s MQTT broker' % (cfg.mqtt_server))
    return client

def restart_and_reconnect():
    
    """
    Handles connection failures by restarting the device.

    This function is called when the connection to the MQTT broker fails.
    It prints an error message to the console, waits for 10 seconds, and
    then initiates a hard reset of the MicroPython device using
    'machine.reset()'. This is a simple but effective way to attempt
    to recover from transient network or broker issues.

    Note:
        This is a forceful recovery method. Any unsaved data or ongoing
        operations will be lost upon restart. Consider implementing more
        sophisticated reconnection strategies (e.g., exponential backoff)
        for production environments.

    Example:
        except OSError as e:
            print(f"MQTT connection error: {e}")
            restart_and_reconnect()  # Attempt to recover
    """
    print('Failed to connect to MQTT broker. Reconnecting...')
    utime.sleep(10)
    machine.reset()

