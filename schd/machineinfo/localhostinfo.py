#  Hardware information

import socket
import netifaces

def get_computer_name():
    """Gets the computer's hostname."""
    try:
        hostname = socket.gethostname()
        return hostname
    except Exception as e:
        print(f"Error getting hostname: {e}")
        return None

def get_mac_address(interface=None):
    """Gets the MAC address of the specified interface, or the first available."""
    try:
        if interface:
            mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
            return mac
        else:
            for interface in netifaces.interfaces():
                try:
                    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                    return mac
                except KeyError:
                    pass #Interface doesn't have a MAC address.
                except ValueError:
                    pass #Interface has no addresses.
            return None #No MAC found on any interface.
    except AttributeError:
        print("netifaces not installed. Install with: pip install netifaces")
        return None
    except Exception as e:
        print(f"Error getting MAC address: {e}")
        return None

def get_default_interface():
    """Gets the default network interface."""
    try:
        gws = netifaces.gateways()
        default_gateway = gws['default'][netifaces.AF_INET][0]
        default_interface = gws['default'][netifaces.AF_INET][1]
        return default_interface
    except Exception as e:
        print(f"Error getting default interface: {e}")
        return None