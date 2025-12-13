import threading
import logging
import scapy.all as scapy
from .devices import DeviceManager
from .anomalies import AnomalyEngine
from .utils import get_local_ip
import time

class SnifferThread(threading.Thread):
    def __init__(self, iface, db, socketio=None, config=None):
        super().__init__()
        self.iface = iface
        self.db = db
        self.socketio = socketio
        self.devices = DeviceManager(db, config)
        self.anomalies = AnomalyEngine(db, self.devices, config)
        self.running = threading.Event()
        self.running.set()
        self.config = config

    def packet_callback(self, pkt):
        # Device learning + Anomaly check
        try:
            self.devices.learn_from_packet(pkt)
            anomaly = self.anomalies.check_packet(pkt)
            if anomaly and self.socketio:
                self.socketio.emit('alert', anomaly, namespace='/alerts')
            if self.socketio:
                # broadcast new device/packet event for UI
                self.socketio.emit('network_event', {'type': 'pkt','devs': self.devices.active_devices()}, namespace='/devices')
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            # Continue processing other packets

    def run(self):
        logging.info("[*] Packet sniffer started on %s", self.iface)
        try:
            while self.running.is_set():
                scapy.sniff(
                    iface=self.iface,
                    prn=self.packet_callback,
                    store=False,
                    timeout=5
                )
        except Exception as e:
            logging.exception("Error in SnifferThread: %s", e)

    def stop(self):
        self.running.clear()