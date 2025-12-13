import eventlet
eventlet.monkey_patch()  # Must be first!

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import yaml
import os
import sys
import secrets
from scanner.database import SQLiteDB
from scanner.sniffer import SnifferThread
from scanner.utils import validate_interface
import threading
import logging

def load_config():
    with open('config.yaml') as f:
        return yaml.safe_load(f)

def create_app():
    config = load_config()
    app = Flask(__name__, static_folder="static")
    
    # Generate secure SECRET_KEY
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        secret_key = secrets.token_hex(32)
        logging.warning("No SECRET_KEY set in environment. Generated random key for this session.")
        logging.warning("For production, set SECRET_KEY environment variable!")
    app.config['SECRET_KEY'] = secret_key
    
    db = SQLiteDB(config.get('db_path', 'scanner.db'))
    socketio = SocketIO(app, async_mode='eventlet')

    # Validate interface before starting sniffer
    iface = config.get('interface')
    if not iface:
        logging.error("No interface specified in config.yaml")
        sys.exit(1)
    try:
        validate_interface(iface)
    except ValueError as e:
        logging.error(f"Interface validation failed: {e}")
        sys.exit(1)
    
    # Background sniffer thread
    sniffer = SnifferThread(iface, db, socketio, config)
    sniffer.daemon = True
    sniffer.start()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/devices")
    def devices():
        return render_template("devices.html", devices=db.devices())

    @app.route("/alerts")
    def alerts():
        return render_template("alerts.html", alerts=db.anomalies())

    @app.route("/api/devices")
    def api_devices():
        return jsonify(db.devices())

    @app.route("/api/anomalies")
    def api_anomalies():
        return jsonify(db.anomalies())

    @app.route("/api/export")
    def api_export():
        fmt = request.args.get("format", "json")
        data = db.devices()
        if fmt == "csv":
            import io, csv
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
            return output.getvalue(), 200, {'Content-Type': 'text/csv'}
        return jsonify(data)

    @app.route("/api/security_score")
    def api_secscore():
        # Simple score: 100 - (#recent anomalies * 10)
        anomalies = db.anomalies()
        score = max(100 - len([a for a in anomalies if a['ts'] >  (eventlet.green.time.time() - 600)]) * 10, 0)
        return jsonify({'score': score})

    return app, socketio, sniffer, db

if __name__ == "__main__":
    app, socketio, sniffer, _ = create_app()
    conf = load_config()
    socketio.run(app, host=conf['web']['host'], port=conf['web']['port'], debug=conf['web']['debug'])