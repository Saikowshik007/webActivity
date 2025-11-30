#!/usr/bin/env python3
"""
Device Filter Management Tool
Manage which devices to monitor on your network
"""

import json
import os
import argparse
import sqlite3
from tabulate import tabulate

CONFIG_FILE = 'device_filter.json'
DB_PATH = 'network_activity.db'

def load_config():
    """Load device filter configuration"""
    if not os.path.exists(CONFIG_FILE):
        return {
            "monitor_all_devices": True,
            "interested_devices": [],
            "description": "Add MAC addresses of devices you want to monitor."
        }

    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_config(config):
    """Save device filter configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"[✓] Configuration saved to {CONFIG_FILE}")

def list_all_devices():
    """List all devices detected on network"""
    if not os.path.exists(DB_PATH):
        print("[!] No database found. Run network_monitor.py first to detect devices.")
        return []

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            d.mac_address,
            d.ip_address,
            d.hostname,
            d.last_seen,
            COUNT(DISTINCT dq.id) as query_count
        FROM devices d
        LEFT JOIN dns_queries dq ON d.id = dq.device_id
        GROUP BY d.id
        ORDER BY d.last_seen DESC
    ''')

    devices = cursor.fetchall()
    conn.close()
    return devices

def show_status():
    """Show current filter status"""
    config = load_config()

    print("\n" + "="*80)
    print("DEVICE FILTER STATUS")
    print("="*80)

    if config['monitor_all_devices']:
        print("\n[*] Mode: MONITOR ALL DEVICES (No filtering)")
        print("[*] To enable filtering, run: python manage_devices.py --enable-filter")
    else:
        print("\n[*] Mode: MONITOR ONLY INTERESTED DEVICES")

        if not config['interested_devices']:
            print("\n[!] No interested devices configured!")
            print("[!] Add devices with: python manage_devices.py --add <MAC_ADDRESS>")
        else:
            print(f"\n[*] Monitoring {len(config['interested_devices'])} device(s):")
            for i, mac in enumerate(config['interested_devices'], 1):
                print(f"    {i}. {mac}")

    # Show all detected devices
    devices = list_all_devices()
    if devices:
        print("\n" + "-"*80)
        print("DETECTED DEVICES ON NETWORK")
        print("-"*80)

        table_data = []
        for dev in devices:
            # Check if device is in interested list
            status = "✓ MONITORED" if dev['mac_address'] in config['interested_devices'] else ""
            if config['monitor_all_devices']:
                status = "✓ MONITORED (ALL)"

            table_data.append([
                dev['mac_address'],
                dev['ip_address'] or 'N/A',
                dev['query_count'],
                dev['last_seen'],
                status
            ])

        print(tabulate(table_data,
                      headers=['MAC Address', 'IP Address', 'Queries', 'Last Seen', 'Status'],
                      tablefmt='grid'))

    print()

def add_device(mac_address):
    """Add device to interested list"""
    config = load_config()

    # Normalize MAC address
    mac_address = mac_address.upper().strip()

    if mac_address in config['interested_devices']:
        print(f"[!] Device {mac_address} is already in the interested devices list")
        return

    config['interested_devices'].append(mac_address)
    save_config(config)
    print(f"[✓] Added {mac_address} to interested devices")

    if config['monitor_all_devices']:
        print("\n[!] Note: Filtering is currently disabled (monitoring all devices)")
        print("    Run 'python manage_devices.py --enable-filter' to enable filtering")

def remove_device(mac_address):
    """Remove device from interested list"""
    config = load_config()

    # Normalize MAC address
    mac_address = mac_address.upper().strip()

    if mac_address not in config['interested_devices']:
        print(f"[!] Device {mac_address} is not in the interested devices list")
        return

    config['interested_devices'].remove(mac_address)
    save_config(config)
    print(f"[✓] Removed {mac_address} from interested devices")

def enable_filter():
    """Enable device filtering"""
    config = load_config()

    if not config['interested_devices']:
        print("[!] Cannot enable filtering: No interested devices configured")
        print("[!] Add devices first with: python manage_devices.py --add <MAC_ADDRESS>")
        return

    config['monitor_all_devices'] = False
    save_config(config)
    print(f"[✓] Device filtering ENABLED")
    print(f"[*] Now monitoring only {len(config['interested_devices'])} device(s)")

def disable_filter():
    """Disable device filtering (monitor all devices)"""
    config = load_config()
    config['monitor_all_devices'] = True
    save_config(config)
    print("[✓] Device filtering DISABLED")
    print("[*] Now monitoring ALL devices on network")

def add_device_interactive():
    """Interactive mode to add devices"""
    devices = list_all_devices()

    if not devices:
        print("\n[!] No devices detected yet")
        print("[!] Run network_monitor.py first to detect devices on your network")
        return

    print("\n" + "="*80)
    print("DETECTED DEVICES - Select devices to monitor")
    print("="*80)

    config = load_config()

    table_data = []
    for i, dev in enumerate(devices, 1):
        status = "Already monitored" if dev['mac_address'] in config['interested_devices'] else ""
        table_data.append([
            i,
            dev['mac_address'],
            dev['ip_address'] or 'N/A',
            dev['query_count'],
            status
        ])

    print(tabulate(table_data,
                  headers=['#', 'MAC Address', 'IP Address', 'Queries', 'Status'],
                  tablefmt='grid'))

    print("\nEnter device number(s) to add (comma-separated), or 'q' to quit:")
    choice = input("> ").strip()

    if choice.lower() == 'q':
        return

    try:
        indices = [int(x.strip()) for x in choice.split(',')]
        for idx in indices:
            if 1 <= idx <= len(devices):
                mac = devices[idx-1]['mac_address']
                if mac not in config['interested_devices']:
                    config['interested_devices'].append(mac)
                    print(f"[✓] Added {mac}")
            else:
                print(f"[!] Invalid number: {idx}")

        save_config(config)

        if config['monitor_all_devices']:
            print("\n[?] Enable filtering now? (y/n)")
            if input("> ").strip().lower() == 'y':
                enable_filter()

    except ValueError:
        print("[!] Invalid input. Please enter numbers separated by commas.")

def main():
    parser = argparse.ArgumentParser(
        description='Manage device filtering for network monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Show current filter status and detected devices
  python manage_devices.py --status

  # Add device to monitoring list
  python manage_devices.py --add AA:BB:CC:DD:EE:FF

  # Remove device from monitoring list
  python manage_devices.py --remove AA:BB:CC:DD:EE:FF

  # Interactive mode - select from detected devices
  python manage_devices.py --interactive

  # Enable filtering (monitor only interested devices)
  python manage_devices.py --enable-filter

  # Disable filtering (monitor all devices)
  python manage_devices.py --disable-filter

  # Clear all interested devices
  python manage_devices.py --clear
        '''
    )

    parser.add_argument('-s', '--status', action='store_true',
                       help='Show filter status and detected devices')
    parser.add_argument('-a', '--add', type=str,
                       help='Add device MAC address to interested list')
    parser.add_argument('-r', '--remove', type=str,
                       help='Remove device MAC address from interested list')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Interactive mode to select devices')
    parser.add_argument('--enable-filter', action='store_true',
                       help='Enable device filtering')
    parser.add_argument('--disable-filter', action='store_true',
                       help='Disable device filtering (monitor all)')
    parser.add_argument('--clear', action='store_true',
                       help='Clear all interested devices')

    args = parser.parse_args()

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         Device Filter Management                          ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    if args.add:
        add_device(args.add)
    elif args.remove:
        remove_device(args.remove)
    elif args.interactive:
        add_device_interactive()
    elif args.enable_filter:
        enable_filter()
    elif args.disable_filter:
        disable_filter()
    elif args.clear:
        config = load_config()
        config['interested_devices'] = []
        save_config(config)
        print("[✓] Cleared all interested devices")
    elif args.status:
        show_status()
    else:
        # Default: show status
        show_status()

if __name__ == '__main__':
    main()
