import requests
import netifaces

def lookup_mac_vendor(mac, config):
    """Best effort MAC OUI lookup (cached)."""
    mac = mac.upper().replace(":", "").replace("-", "")
    cache = getattr(lookup_mac_vendor, "_cache", {})
    url = config.get('oui_lookup_url', "https://api.macvendors.com/")
    if mac in cache:
        return cache[mac]
    try:
        resp = requests.get(
            f"{url}{mac}",
            timeout=5,
            verify=True,
            headers={'User-Agent': 'passive-network-scanner/1.0'}
        )
        if resp.status_code == 200:
            vendor = resp.text.strip()
            cache[mac] = vendor
            setattr(lookup_mac_vendor, "_cache", cache)
            return vendor
    except (requests.RequestException, requests.Timeout) as e:
        # Silently fail for network errors
        pass
    return "Unknown"

def validate_interface(iface):
    """Validate that network interface exists."""
    try:
        available = netifaces.interfaces()
        if iface not in available:
            raise ValueError(f"Interface '{iface}' not found. Available: {', '.join(available)}")
        return True
    except Exception as e:
        raise ValueError(f"Failed to validate interface: {e}")

def get_local_ip(iface=None):
    # Placeholder: could use netifaces, but avoid dependencies
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
        s.close()
        return IP
    except Exception:
        return "127.0.0.1"