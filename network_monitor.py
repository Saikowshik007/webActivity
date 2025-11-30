#!/usr/bin/env python3
"""
Network Activity Monitor
Captures DNS queries and network activity from devices on your local network.
"""

import sqlite3
import datetime
from scapy.all import sniff, DNS, DNSQR, IP, Ether
from scapy.layers.inet import TCP, UDP
import threading
import signal
import sys
import json
import os
from collections import defaultdict

class NetworkMonitor:
    def __init__(self, db_path='network_activity.db', config_path='device_filter.json'):
        self.db_path = db_path
        self.config_path = config_path
        self.running = True
        self.device_cache = {}
        self.filter_config = self.load_filter_config()
        self.init_database()

    def load_filter_config(self):
        """Load device filter configuration"""
        if not os.path.exists(self.config_path):
            # Create default config
            default_config = {
                "monitor_all_devices": True,
                "interested_devices": [],
                "description": "Add MAC addresses of devices you want to monitor. Set monitor_all_devices to false to enable filtering."
            }
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            return default_config

        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            return {"monitor_all_devices": True, "interested_devices": []}

    def is_device_allowed(self, mac_address):
        """Check if device should be monitored based on filter config"""
        # If monitoring all devices, allow everything
        if self.filter_config.get('monitor_all_devices', True):
            return True

        # Normalize MAC address for comparison
        mac_normalized = mac_address.upper().strip()

        # Check if device is in interested list
        interested_devices = [mac.upper().strip() for mac in self.filter_config.get('interested_devices', [])]
        return mac_normalized in interested_devices

    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                hostname TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # DNS queries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                source_ip TEXT NOT NULL,
                query_name TEXT NOT NULL,
                query_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # HTTP/HTTPS connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                source_ip TEXT NOT NULL,
                dest_ip TEXT NOT NULL,
                dest_port INTEGER,
                protocol TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_device ON dns_queries(device_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connections(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_device ON connections(device_id)')

        conn.commit()
        conn.close()
        print(f"[✓] Database initialized: {self.db_path}")

    def get_or_create_device(self, mac_address, ip_address):
        """Get existing device or create new one"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM devices WHERE mac_address = ?', (mac_address,))
        result = cursor.fetchone()

        if result:
            device_id = result[0]
            # Update last seen and IP if changed
            cursor.execute('''
                UPDATE devices
                SET last_seen = CURRENT_TIMESTAMP, ip_address = ?
                WHERE id = ?
            ''', (ip_address, device_id))
        else:
            cursor.execute('''
                INSERT INTO devices (mac_address, ip_address)
                VALUES (?, ?)
            ''', (mac_address, ip_address))
            device_id = cursor.lastrowid
            print(f"[+] New device detected: {mac_address} ({ip_address})")

        conn.commit()
        conn.close()
        return device_id

    def log_dns_query(self, packet):
        """Log DNS query to database"""
        try:
            if packet.haslayer(DNSQR):
                dns_query = packet[DNSQR]
                query_name = dns_query.qname.decode('utf-8', errors='ignore').rstrip('.')

                # Get source IP and MAC
                source_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
                mac_address = packet[Ether].src if packet.haslayer(Ether) else 'Unknown'

                # Check if device is allowed
                if not self.is_device_allowed(mac_address):
                    return

                # Get or create device
                device_id = self.get_or_create_device(mac_address, source_ip)

                # Get query type
                qtype_map = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT'}
                query_type = qtype_map.get(dns_query.qtype, str(dns_query.qtype))

                # Insert DNS query
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO dns_queries (device_id, source_ip, query_name, query_type)
                    VALUES (?, ?, ?, ?)
                ''', (device_id, source_ip, query_name, query_type))
                conn.commit()
                conn.close()

                print(f"[DNS] {source_ip} ({mac_address[:17]}) -> {query_name}")

        except Exception as e:
            print(f"[!] Error logging DNS query: {e}")

    def log_connection(self, packet):
        """Log HTTP/HTTPS connection attempts"""
        try:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst

                # Get MAC address
                mac_address = packet[Ether].src if packet.haslayer(Ether) else 'Unknown'

                # Check if device is allowed
                if not self.is_device_allowed(mac_address):
                    return

                # Only log outbound connections (from local network)
                if not source_ip.startswith(('192.168.', '10.', '172.16.')):
                    return

                # Get port and protocol
                if packet.haslayer(TCP):
                    dest_port = packet[TCP].dport
                    protocol = 'TCP'
                    # Only log common web ports
                    if dest_port not in [80, 443, 8080, 8443]:
                        return
                else:
                    dest_port = packet[UDP].dport
                    protocol = 'UDP'
                    # Skip DNS (already logged separately)
                    if dest_port == 53:
                        return

                device_id = self.get_or_create_device(mac_address, source_ip)

                # Insert connection
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO connections (device_id, source_ip, dest_ip, dest_port, protocol)
                    VALUES (?, ?, ?, ?, ?)
                ''', (device_id, source_ip, dest_ip, dest_port, protocol))
                conn.commit()
                conn.close()

                print(f"[{protocol}] {source_ip} -> {dest_ip}:{dest_port}")

        except Exception as e:
            print(f"[!] Error logging connection: {e}")

    def packet_handler(self, packet):
        """Main packet handler"""
        try:
            # Log DNS queries
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                self.log_dns_query(packet)
            # Log web connections
            elif packet.haslayer(IP):
                self.log_connection(packet)
        except Exception as e:
            print(f"[!] Error handling packet: {e}")

    def start_monitoring(self, interface=None):
        """Start packet capture"""
        print(f"\n{'='*60}")
        print("Network Activity Monitor Started")
        print(f"{'='*60}")
        print(f"[*] Database: {self.db_path}")
        if interface:
            print(f"[*] Interface: {interface}")

        # Show filter status
        if self.filter_config.get('monitor_all_devices', True):
            print("[*] Filter Mode: MONITORING ALL DEVICES")
        else:
            interested_count = len(self.filter_config.get('interested_devices', []))
            print(f"[*] Filter Mode: MONITORING {interested_count} INTERESTED DEVICE(S)")
            for mac in self.filter_config.get('interested_devices', []):
                print(f"    - {mac}")

        print("[*] Monitoring DNS queries and web connections...")
        print("[*] Press Ctrl+C to stop\n")

        try:
            # Capture DNS (UDP port 53) and web traffic (TCP ports 80, 443)
            # Enable promiscuous mode to capture all packets on the network
            sniff(
                filter="udp port 53 or tcp port 80 or tcp port 443",
                prn=self.packet_handler,
                iface=interface,
                store=False,
                promisc=True  # Enable promiscuous mode
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping monitor...")
            self.running = False
        except PermissionError:
            print("\n[!] ERROR: Permission denied!")
            print("[!] Please run this script with administrator/root privileges:")
            print("    Windows: Run as Administrator")
            print("    Linux/Mac: sudo python network_monitor.py")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] Error: {e}")
            sys.exit(1)

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         Network Activity Monitor v1.0                     ║
    ║         Device-Level WiFi Activity Tracking               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    print("[*] TIP: Not seeing all devices? Run 'python scan_network.py' to discover all devices on your network\n")

    monitor = NetworkMonitor()

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n[*] Shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start monitoring
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
