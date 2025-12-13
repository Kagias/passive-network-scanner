import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    first_seen INT,
    last_seen INT,
    os_guess TEXT
);
CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INT,
    type TEXT,
    desc TEXT
);
"""

class SQLiteDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def add_or_update_device(self, dev):
        with self.lock:
            conn = self._conn()
            try:
                conn.execute("""
                INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, os_guess)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                  ip=excluded.ip,
                  hostname=excluded.hostname,
                  vendor=excluded.vendor,
                  last_seen=excluded.last_seen,
                  os_guess=excluded.os_guess
                """, (
                    dev['mac'], dev['ip'], dev.get('hostname', ""), dev.get('vendor', ""), dev['first_seen'], dev['last_seen'], dev.get('os_guess', "")
                ))
                conn.commit()
            finally:
                conn.close()

    def devices(self):
        with self.lock:
            conn = self._conn()
            try:
                cursor = conn.execute("SELECT * FROM devices")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def add_anomaly(self, alert):
        with self.lock:
            conn = self._conn()
            try:
                conn.execute("""
                INSERT INTO anomalies (ts, type, desc)
                VALUES (?, ?, ?)
                """, (alert['ts'], alert['type'], alert['desc']))
                conn.commit()
            finally:
                conn.close()

    def anomalies(self):
        with self.lock:
            conn = self._conn()
            try:
                cursor = conn.execute("SELECT * FROM anomalies ORDER BY ts DESC LIMIT 100")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()