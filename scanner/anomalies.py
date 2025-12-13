import time
from collections import defaultdict

class AnomalyEngine:
    def __init__(self, db, device_mgr, config):
        self.db = db
        self.device_mgr = device_mgr
        self.config = config
        self.arp_watcher = defaultdict(set)    # IP: set(MAC)
        self.mac_ips = defaultdict(set)        # MAC: set(IP)
        self.burst_counter = []
        self.last_alerts = {}

    def check_packet(self, pkt):
        ts = int(time.time())
        alert = None

        # Traffic burst logic
        self.burst_counter.append(ts)
        # Clear if over window (1s)
        self.burst_counter = [t for t in self.burst_counter if ts-t < 1]
        threshold = self.config.get('traffic_burst_threshold', 120)
        if len(self.burst_counter) > threshold:
            alert = {
                'ts': ts,
                'type': 'burst',
                'desc': f"Traffic burst: {len(self.burst_counter)} pkts/sec",
            }
            if self._recently_alerted('burst', 10) is False:
                self.db.add_anomaly(alert)
                self.last_alerts['burst'] = ts
                return alert

        # ARP spoofing detection
        if pkt.haslayer('ARP'):
            ip = pkt['ARP'].psrc
            mac = pkt['ARP'].hwsrc
            self.arp_watcher[ip].add(mac)
            if len(self.arp_watcher[ip]) > 1:
                alert = {
                    'ts': ts,
                    'type': 'arp_spoof',
                    'desc': f"Multiple MACs ({self.arp_watcher[ip]}) detected for IP {ip}"
                }
                if self._recently_alerted(f"arp_{ip}", 180) is False:
                    self.db.add_anomaly(alert)
                    self.last_alerts[f"arp_{ip}"] = ts
                    return alert

        # Duplicate MAC detection
        if pkt.haslayer('IP') and hasattr(pkt, 'src'):
            mac = pkt.src
            ip = pkt['IP'].src
            self.mac_ips[mac].add(ip)
            if len(self.mac_ips[mac]) > 3:
                alert = {
                    'ts': ts,
                    'type': 'mac_clone',
                    'desc': f"MAC {mac} used by multiple IPs: {self.mac_ips[mac]}"
                }
                if self._recently_alerted(f"mac_{mac}", 300) is False:
                    self.db.add_anomaly(alert)
                    self.last_alerts[f"mac_{mac}"] = ts
                    return alert

        # Rogue DHCP detection
        if pkt.haslayer('DHCP'):
            mac = pkt.src if hasattr(pkt, 'src') else None
            options = pkt['DHCP'].options
            op_types = [x[0] for x in options if isinstance(x, tuple)]
            if 'message-type' in op_types:
                mtype = dict(options).get('message-type')
                if mtype == 2:  # OFFER
                    trusted_servers = self.config.get('trusted_dhcp_servers', [])
                    if mac not in trusted_servers:
                        alert = {
                            'ts': ts,
                            'type': 'rogue_dhcp',
                            'desc': f"Rogue DHCP OFFER from MAC {mac}"
                        }
                        if self._recently_alerted(f"rogue_{mac}", 300) is False:
                            self.db.add_anomaly(alert)
                            self.last_alerts[f"rogue_{mac}"] = ts
                            return alert

        return None

    def _recently_alerted(self, key, interval):
        now = int(time.time())
        if key in self.last_alerts:
            if now - self.last_alerts[key] < interval:
                return True
        return False