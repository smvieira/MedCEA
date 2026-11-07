# Import the ntptime module for setting the device time via NTP (Network Time Protocol).
import ntptime
# Import the utime module for working with time and dates.
import utime
# Import the network module for working wlan.
import network
import ujson
# Import the CEA configurations.
import config as cfg
# Import the MQTT module
from umqtt.simple import MQTTClient, MQTTException

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


TEST_TAG = "_test"


def _wlan_ip():
    """The board's address on its network, or None (not connected, no WLAN)."""
    try:
        w = network.WLAN(network.STA_IF)
        if not w.isconnected():
            return None
        ip = w.ifconfig()[0]
        return ip if ip and ip != "0.0.0.0" else None
    except Exception:
        return None


def _wlan_mac():
    """The station MAC as aa:bb:cc:dd:ee:ff, or None."""
    try:
        import ubinascii
        return ubinascii.hexlify(network.WLAN(network.STA_IF).config("mac"), ":").decode().lower()
    except Exception:
        return None


def _firmware():
    try:
        import os
        return os.uname().release
    except Exception:
        return None


def status_message(msg_type, tag, timestamp=None):
    """The metadata of a health (HB) or test (TS) message: the fields of a reading
    (cea_sense.Board._message) plus the board's ip and mac, None when unreadable.

    The one builder for both roles, so the two cannot drift. Readings (AP) and
    CONTROL's reports (SP) do not use it and carry no ip or mac: their payloads
    are what Node-RED and the measurement views have always read."""
    return {
        "unit_code": cfg.unit_code,
        "zone_code": cfg.zone_code,
        "msg_type": msg_type,
        "timestamp": timestamp or get_timestamp(),
        "device_id": cfg.device_id,
        "device_dns": cfg.device_dns,
        "tag": tag,
        "ip": _wlan_ip(),
        "mac": _wlan_mac(),
    }


def publish_test(client, source="board-boot"):
    """One TS message on <topic_pub>/_test (sense/_test, or control_setpoint/_test,
    the only class a CONTROL board may write). Node-RED stores it as TS from the
    topic. False when the publish failed: the caller counts it, it resets nothing."""
    message = status_message("TS", TEST_TAG)
    message["source"] = source
    message["firmware"] = _firmware()
    try:
        client.publish(cfg.topic_pub + "/" + TEST_TAG, ujson.dumps(message))
    except OSError as e:
        print("publish to %s failed: %s" % (TEST_TAG, e))
        return False
    return True


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
    # refused CONNACK is turned into OSError below, the caller restarts the board,
    # and the retry lands once the credential row has reached the broker (seconds).
    # TLS (5 Nov 2026): the broker's LAN port takes TLS only, so the password never
    # crosses the LAN in clear. A board flashed before then has no MQTT_TLS_NAME and
    # cannot connect until it is onboarded again.
    tls = {}
    if cfg.mqtt_tls_name:
        tls = {"ssl": _tls_context(), "ssl_params": {"server_hostname": cfg.mqtt_tls_name}}
    client = MQTTClient(cfg.client_id, cfg.mqtt_server, cfg.mqtt_port,
                        user=cfg.mqtt_user, password=cfg.mqtt_pass,
                        keepalive=max(60, 3 * cfg.message_interval), **tls)
    try:
        client.connect()
    except (MQTTException, AssertionError) as e:
        # A refused login (CONNACK rc 4/5: the credential has not reached the broker
        # yet, the device is inactive, or a newer onboarding replaced the password) is
        # MQTTException, not OSError: the callers restart the board only on OSError,
        # so it used to leave the board at the REPL until someone power-cycled it.
        raise OSError("broker refused the connection: %r" % (e.args[0] if e.args else e,))
    print('Connected to %s MQTT broker%s' % (cfg.mqtt_server, " (TLS, %s)" % cfg.mqtt_tls_name if tls else ""))
    return client


MQTT_CA_FILE = "mqtt_ca.der"   # the platform CA, copied by edge/flash-device.sh


def _tls_context():
    """A TLS context that accepts only the broker's certificate: signed by the platform CA
    (MQTT_CA_FILE) and named cfg.mqtt_tls_name (checked by wrap_socket's server_hostname).

    The certificate's dates are checked too, so a clock still at 2000 (NTP not answered
    at boot) refuses even the right certificate: try NTP once more, and raise OSError
    when the clock is still unset, so the caller restarts the board and tries again."""
    import ssl
    if utime.localtime()[0] < 2025:
        set_device_time()
        if utime.localtime()[0] < 2025:
            raise OSError("clock not set (NTP did not answer): the broker's certificate cannot be checked")
    with open(MQTT_CA_FILE, "rb") as f:
        ca = f.read()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca)
    return ctx

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

