import time
import socket
from .utils import lookup_mac_vendor

class DeviceManager:
    def __init__(self, db, config):
        self.db = db
        self.config = config
        self.mac_ip_table = {}   # MAC: [IP, last_seen]
        self.devices = {}        # MAC: full profile

    def _resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def learn_from_packet(self, pkt):
        now = int(time.time())
        mac = None
        ip = None
        vendor = None
        hostname = ""
        os_guess = ""

        # Extract data (ARP, DHCP, IP)
        if pkt.haslayer('ARP'):
            mac = pkt['ARP'].hwsrc
            ip = pkt['ARP'].psrc
        elif pkt.haslayer('IP'):
            mac = pkt.src if hasattr(pkt, 'src') else None
            ip = pkt['IP'].src

        # OUI
        if mac:
            vendor = lookup_mac_vendor(mac, self.config)
        if ip:
            hostname = self._resolve_hostname(ip)

        # OS fingerprint (quick guess based on TTL)
        if pkt.haslayer('IP'):
            ttl = pkt['IP'].ttl
            if ttl >= 128:
                os_guess = "Windows"
            elif ttl >= 64:
                os_guess = "Linux/Unix"
            else:
                os_guess = "Unknown"

        if mac and ip:
            existing = self.devices.get(mac, {})
            profile = {
                'mac': mac,
                'ip': ip,
                'hostname': hostname or existing.get('hostname', ""),
                'vendor': vendor or existing.get('vendor', ""),
                'last_seen': now,
                'first_seen': existing.get('first_seen', now),
                'os_guess': os_guess or existing.get('os_guess', ""),
            }
            self.devices[mac] = profile
            self.db.add_or_update_device(profile)

    def active_devices(self):
        return list(self.devices.values())