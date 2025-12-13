import yaml
import os
import sys
import argparse
from scanner.database import SQLiteDB
from scanner.sniffer import SnifferThread
from scanner.utils import validate_interface

def cli_main(cmd, args):
    # Load config
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    db = SQLiteDB(config.get('db_path', 'scanner.db'))

    if cmd == "web":
        # Launch Flask web server/app
        from web.app import create_app
        app, socketio, sniffer, _ = create_app()
        conf = config['web']
        socketio.run(app, host=conf['host'], port=conf['port'], debug=conf['debug'])
        return

    if cmd == "scan":
        # Check if interface specified as argument
        iface = args[0] if args else config.get('interface')
        if not iface:
            print("Error: No interface specified. Use: python run.py scan <interface>")
            print("   Or set 'interface' in config.yaml")
            sys.exit(1)
        try:
            validate_interface(iface)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        sniffer = SnifferThread(iface, db, None, config)
        sniffer.daemon = True
        sniffer.start()
        print(f"[*] Passive monitoring started on {iface}. Press Ctrl+C to stop.")
        try:
            while True:
                import time
                time.sleep(2)
        except KeyboardInterrupt:
            sniffer.stop()
            print("Stopped scan.")
        return

    if cmd == "show":
        if len(args) < 1:
            print("Usage: run.py show devices|alerts")
            return
        if args[0] == "devices":
            for d in db.devices():
                print(f"{d['mac']:17}  {d['ip']:15}  {d['vendor'][:16]:16}  {d['hostname'] or '-'}  {d['os_guess'] or '-'}  last:{d['last_seen']}")
        elif args[0] == "alerts":
            for a in db.anomalies():
                print(f"[{a['ts']}] {a['type']} - {a['desc']}")
        else:
            print("Unknown subcommand for show.")

    elif cmd == "export":
        fmt = "json"
        if "--format" in args:
            idx = args.index("--format")
            fmt = args[idx+1]
        data = db.devices()
        if not data:
            print("No devices found in database.")
            return
        if fmt == "csv":
            import csv
            w = csv.DictWriter(sys.stdout, fieldnames=data[0].keys())
            w.writeheader()
            w.writerows(data)
        else:
            import json
            print(json.dumps(data, indent=2))
    elif cmd in ["--help", "-h", "help"]:
        print("""Passive Network Scanner - Usage:
        
Commands:
  web                          Start web interface
  scan [interface]             Start passive scan (e.g., scan wlo1)
  show devices                 Display discovered devices
  show alerts                  Display security alerts
  export [--format csv|json]   Export device data
  
Examples:
  python run.py web
  python run.py scan wlo1
  python run.py show devices
  python run.py export --format csv
        """)
    else:
        print(f"Unknown command: {cmd}")
        print("Use 'python run.py --help' for usage information.")