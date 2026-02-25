import pywifi
import time
from pywifi import const


def get_security_type(network):
    if not network.akm:
        return "Open"

    if const.AKM_TYPE_WPA2PSK in network.akm:
        return "WPA2"
    elif const.AKM_TYPE_WPA3PSK in network.akm:
        return "WPA3"
    elif const.AKM_TYPE_WPAPSK in network.akm:
        return "WPA"
    else:
        return "Unknown"


def scan_networks():
    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()

    if not interfaces:
        print("No WiFi interface found.")
        return []

    iface = interfaces[0]

    print("Scanning for WiFi networks...\n")
    iface.scan()
    time.sleep(3)

    results = iface.scan_results()

    unique_networks = {}

    for network in results:
        ssid = network.ssid

        if not ssid:
            continue

        security_type = get_security_type(network)

        if ssid not in unique_networks or network.signal > unique_networks[ssid]["signal"]:
            unique_networks[ssid] = {
                "ssid": ssid,
                "signal": network.signal,
                "security": security_type
            }

    return list(unique_networks.values())