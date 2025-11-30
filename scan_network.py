#!/usr/bin/env python3
"""
Network Scanner - Discovers all devices on your local network
Uses ARP scanning to find devices even if they're not actively communicating
"""

import sqlite3
from scapy.all import ARP, Ether, srp, conf
import ipaddress
import socket
import argparse
from datetime import datetime
from tabulate import tabulate

DB_PATH = 'network_activity.db'

def get_local_network():
    """Detect local network range"""
    try:
        # Get local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Convert to network (assume /24)
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network), local_ip
    except Exception as e:
        print(f"[!] Could not detect local network: {e}")
        return "192.168.1.0/24", None

def get_hostname(ip):
    """Try to get hostname for IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return None

def scan_network(network_range, timeout=2):
    """Scan network for active devices using ARP"""
    print(f"\n[*] Scanning network: {network_range}")
    print(f"[*] This may take a moment...\n")

    # Create ARP request
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and get responses
    try:
        result = srp(packet, timeout=timeout, verbose=False)[0]
    except PermissionError:
        print("[!] ERROR: Permission denied!")
        print("[!] Please run this script with administrator/root privileges:")
        print("    Windows: Run as Administrator")
        print("    Linux/Mac: sudo python scan_network.py")
        return []

    devices = []
    for sent, received in result:
        # Try to get hostname
        hostname = get_hostname(received.psrc)

        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc.upper(),
            'hostname': hostname
        })

    return devices

def save_to_database(devices):
    """Save discovered devices to database"""
    if not devices:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    updated_count = 0
    new_count = 0

    for device in devices:
        # Check if device exists
        cursor.execute('SELECT id FROM devices WHERE mac_address = ?', (device['mac'],))
        result = cursor.fetchone()

        if result:
            # Update existing device
            cursor.execute('''
                UPDATE devices
                SET ip_address = ?, hostname = ?, last_seen = CURRENT_TIMESTAMP
                WHERE mac_address = ?
            ''', (device['ip'], device['hostname'], device['mac']))
            updated_count += 1
        else:
            # Insert new device
            cursor.execute('''
                INSERT INTO devices (mac_address, ip_address, hostname)
                VALUES (?, ?, ?)
            ''', (device['mac'], device['ip'], device['hostname']))
            new_count += 1

    conn.commit()
    conn.close()

    print(f"[✓] Database updated:")
    print(f"    New devices: {new_count}")
    print(f"    Updated devices: {updated_count}")

def display_devices(devices, local_ip):
    """Display discovered devices in a table"""
    if not devices:
        print("\n[!] No devices found on the network")
        return

    print(f"\n{'='*80}")
    print(f"DISCOVERED DEVICES ({len(devices)} found)")
    print(f"{'='*80}\n")

    table_data = []
    for device in devices:
        status = ""
        if device['ip'] == local_ip:
            status = "THIS DEVICE"

        table_data.append([
            device['ip'],
            device['mac'],
            device['hostname'] or 'Unknown',
            status
        ])

    # Sort by IP
    table_data.sort(key=lambda x: ipaddress.IPv4Address(x[0]))

    print(tabulate(table_data,
                  headers=['IP Address', 'MAC Address', 'Hostname', 'Notes'],
                  tablefmt='grid'))
    print()

def compare_with_database(scanned_devices):
    """Compare scanned devices with database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT mac_address, ip_address, hostname FROM devices')
        db_devices = cursor.fetchall()
        conn.close()

        scanned_macs = {d['mac'] for d in scanned_devices}
        db_macs = {d['mac_address'] for d in db_devices}

        # Devices in DB but not in scan (offline/inactive)
        offline_macs = db_macs - scanned_macs

        if offline_macs:
            print(f"\n{'='*80}")
            print(f"OFFLINE DEVICES (in database but not detected in scan)")
            print(f"{'='*80}\n")

            offline_data = []
            for device in db_devices:
                if device['mac_address'] in offline_macs:
                    offline_data.append([
                        device['mac_address'],
                        device['ip_address'] or 'N/A',
                        device['hostname'] or 'Unknown'
                    ])

            print(tabulate(offline_data,
                          headers=['MAC Address', 'Last Known IP', 'Hostname'],
                          tablefmt='grid'))
            print()

    except sqlite3.Error:
        # Database doesn't exist yet
        pass

def main():
    parser = argparse.ArgumentParser(
        description='Scan network to discover all connected devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Auto-detect and scan your local network
  python scan_network.py

  # Scan specific network range
  python scan_network.py --network 192.168.1.0/24

  # Scan and save to database
  python scan_network.py --save

  # Just scan without saving
  python scan_network.py --no-save
        '''
    )

    parser.add_argument('-n', '--network', type=str,
                       help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--timeout', type=int, default=2,
                       help='Timeout in seconds (default: 2)')
    parser.add_argument('--save', action='store_true',
                       help='Save results to database')
    parser.add_argument('--no-save', action='store_true',
                       help='Do not save to database')

    args = parser.parse_args()

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         Network Device Scanner                            ║
    ║         Discover all devices on your network              ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Determine network to scan
    if args.network:
        network_range = args.network
        local_ip = None
    else:
        network_range, local_ip = get_local_network()
        print(f"[*] Detected local IP: {local_ip}")

    # Scan the network
    devices = scan_network(network_range, args.timeout)

    if not devices:
        print("\n[!] No devices found. This could mean:")
        print("    1. You need to run as Administrator/root")
        print("    2. The network range is incorrect")
        print("    3. Devices are blocking ARP requests")
        return

    # Display results
    display_devices(devices, local_ip)

    # Save to database (default behavior unless --no-save)
    if not args.no_save:
        save_to_database(devices)

        # Show comparison with database
        compare_with_database(devices)

        print(f"[*] Tip: Use 'python manage_devices.py --status' to see device filter status")

if __name__ == '__main__':
    main()
