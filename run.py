import sys
from cli.main import cli_main

def main():
    # Entrypoint supports: web, scan, show devices, show alerts, export
    if len(sys.argv) < 2 or sys.argv[1] in ['--help', '-h', 'help']:
        print("""Passive Network Scanner - Usage:
        
Commands:
  web                          Start web interface
  scan [interface]             Start passive scan (e.g., scan wlo1)
  show devices                 Display discovered devices
  show alerts                  Display security alerts
  export [--format csv|json]   Export device data
  help, --help, -h             Show this help message
  
Examples:
  python run.py web
  python run.py scan wlo1
  python run.py show devices
  python run.py export --format csv
  
Note: Packet scanning requires root/sudo privileges.
      Use 'ip link' or 'ifconfig' to see available network interfaces.
        """)
        sys.exit(0)
    cmd = sys.argv[1]
    cli_main(cmd, sys.argv[2:])

if __name__ == '__main__':
    main()