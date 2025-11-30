#!/usr/bin/env python3
"""
Command-line tool to query network activity history
"""

import sqlite3
import argparse
from datetime import datetime, timedelta
from tabulate import tabulate

DB_PATH = 'network_activity.db'

def get_db_connection():
    """Get database connection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
        exit(1)

def list_devices():
    """List all devices"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            d.id,
            d.mac_address,
            d.ip_address,
            d.first_seen,
            d.last_seen,
            COUNT(DISTINCT dq.id) as query_count
        FROM devices d
        LEFT JOIN dns_queries dq ON d.id = dq.device_id
        GROUP BY d.id
        ORDER BY d.last_seen DESC
    ''')

    rows = cursor.fetchall()
    if not rows:
        print("\n[*] No devices found")
        conn.close()
        return

    table_data = []
    for row in rows:
        table_data.append([
            row['id'],
            row['mac_address'],
            row['ip_address'] or 'N/A',
            row['query_count'],
            row['last_seen']
        ])

    print("\n" + "="*80)
    print("DEVICES ON NETWORK")
    print("="*80)
    print(tabulate(table_data,
                   headers=['ID', 'MAC Address', 'IP Address', 'Queries', 'Last Seen'],
                   tablefmt='grid'))
    print()

    conn.close()

def show_device_activity(device_id, hours=24, limit=50):
    """Show activity for a specific device"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get device info
    cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
    device = cursor.fetchone()

    if not device:
        print(f"\n[!] Device ID {device_id} not found")
        conn.close()
        return

    print("\n" + "="*80)
    print(f"DEVICE ACTIVITY: {device['mac_address']} ({device['ip_address'] or 'N/A'})")
    print("="*80)

    # Get DNS queries
    cursor.execute('''
        SELECT query_name, query_type, timestamp
        FROM dns_queries
        WHERE device_id = ?
        AND timestamp >= datetime('now', '-' || ? || ' hours')
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (device_id, hours, limit))

    queries = cursor.fetchall()

    if queries:
        print(f"\nDNS Queries (last {hours} hours):")
        print("-" * 80)
        table_data = []
        for q in queries:
            table_data.append([
                q['query_name'],
                q['query_type'],
                q['timestamp']
            ])
        print(tabulate(table_data,
                      headers=['Domain', 'Type', 'Timestamp'],
                      tablefmt='grid'))
    else:
        print(f"\n[*] No DNS queries in the last {hours} hours")

    # Get connections
    cursor.execute('''
        SELECT dest_ip, dest_port, protocol, timestamp
        FROM connections
        WHERE device_id = ?
        AND timestamp >= datetime('now', '-' || ? || ' hours')
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (device_id, hours, limit))

    connections = cursor.fetchall()

    if connections:
        print(f"\n\nConnections (last {hours} hours):")
        print("-" * 80)
        table_data = []
        for c in connections:
            table_data.append([
                c['dest_ip'],
                c['dest_port'],
                c['protocol'],
                c['timestamp']
            ])
        print(tabulate(table_data,
                      headers=['Destination IP', 'Port', 'Protocol', 'Timestamp'],
                      tablefmt='grid'))
    else:
        print(f"\n[*] No connections in the last {hours} hours")

    print()
    conn.close()

def search_queries(search_term, limit=50):
    """Search DNS queries"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            d.mac_address,
            d.ip_address,
            dq.query_name,
            dq.timestamp
        FROM dns_queries dq
        JOIN devices d ON dq.device_id = d.id
        WHERE dq.query_name LIKE ?
        ORDER BY dq.timestamp DESC
        LIMIT ?
    ''', (f'%{search_term}%', limit))

    results = cursor.fetchall()

    if not results:
        print(f"\n[*] No results found for '{search_term}'")
        conn.close()
        return

    print("\n" + "="*80)
    print(f"SEARCH RESULTS: '{search_term}'")
    print("="*80)

    table_data = []
    for r in results:
        table_data.append([
            r['mac_address'],
            r['ip_address'] or 'N/A',
            r['query_name'],
            r['timestamp']
        ])

    print(tabulate(table_data,
                  headers=['MAC Address', 'IP Address', 'Domain', 'Timestamp'],
                  tablefmt='grid'))
    print()

    conn.close()

def show_top_domains(hours=24, limit=20):
    """Show most frequently queried domains"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT query_name, COUNT(*) as count
        FROM dns_queries
        WHERE timestamp >= datetime('now', '-' || ? || ' hours')
        GROUP BY query_name
        ORDER BY count DESC
        LIMIT ?
    ''', (hours, limit))

    results = cursor.fetchall()

    if not results:
        print(f"\n[*] No queries in the last {hours} hours")
        conn.close()
        return

    print("\n" + "="*80)
    print(f"TOP DOMAINS (last {hours} hours)")
    print("="*80)

    table_data = []
    for r in results:
        table_data.append([
            r['query_name'],
            r['count']
        ])

    print(tabulate(table_data,
                  headers=['Domain', 'Query Count'],
                  tablefmt='grid'))
    print()

    conn.close()

def main():
    parser = argparse.ArgumentParser(
        description='Query network activity history',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # List all devices
  python query_history.py --list

  # Show activity for device ID 1 (last 24 hours)
  python query_history.py --device 1

  # Show activity for device ID 2 (last 48 hours)
  python query_history.py --device 2 --hours 48

  # Search for queries containing "google"
  python query_history.py --search google

  # Show top 20 most queried domains (last 24 hours)
  python query_history.py --top

  # Show top domains for last week
  python query_history.py --top --hours 168
        '''
    )

    parser.add_argument('-l', '--list', action='store_true',
                       help='List all devices')
    parser.add_argument('-d', '--device', type=int,
                       help='Show activity for device ID')
    parser.add_argument('-s', '--search', type=str,
                       help='Search DNS queries')
    parser.add_argument('-t', '--top', action='store_true',
                       help='Show top queried domains')
    parser.add_argument('--hours', type=int, default=24,
                       help='Time range in hours (default: 24)')
    parser.add_argument('--limit', type=int, default=50,
                       help='Limit number of results (default: 50)')

    args = parser.parse_args()

    # Check if database exists
    import os
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("[!] Please run network_monitor.py first to create the database")
        exit(1)

    # Execute commands
    if args.list:
        list_devices()
    elif args.device:
        show_device_activity(args.device, args.hours, args.limit)
    elif args.search:
        search_queries(args.search, args.limit)
    elif args.top:
        show_top_domains(args.hours, args.limit)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
