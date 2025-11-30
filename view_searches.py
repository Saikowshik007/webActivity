#!/usr/bin/env python3
"""
View captured search queries and browsing history
Display Google searches, URLs visited, and user behavior
"""

import sqlite3
import argparse
from tabulate import tabulate
from datetime import datetime, timedelta
import urllib.parse

DB_PATH = 'network_activity.db'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def view_search_history(device_id=None, hours=24, search_engine=None, limit=100):
    """View search query history"""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = '''
        SELECT
            sq.search_engine,
            sq.query,
            sq.timestamp,
            sq.source_ip,
            d.mac_address,
            d.hostname
        FROM search_queries sq
        LEFT JOIN devices d ON sq.device_id = d.id
        WHERE sq.timestamp >= datetime('now', '-' || ? || ' hours')
    '''

    params = [hours]

    if device_id:
        query += ' AND sq.device_id = ?'
        params.append(device_id)

    if search_engine:
        query += ' AND sq.search_engine = ?'
        params.append(search_engine)

    query += ' ORDER BY sq.timestamp DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()

    if not results:
        print(f"\n[*] No search queries found in the last {hours} hours")
        return

    print(f"\n{'='*100}")
    print(f"SEARCH QUERY HISTORY (Last {hours} hours)")
    print(f"{'='*100}\n")

    table_data = []
    for row in results:
        table_data.append([
            row['timestamp'],
            row['hostname'] or row['mac_address'][:17],
            row['source_ip'],
            row['search_engine'].upper(),
            row['query']
        ])

    print(tabulate(table_data,
                  headers=['Time', 'Device', 'IP', 'Engine', 'Search Query'],
                  tablefmt='grid',
                  maxcolwidths=[None, 20, 15, 10, 60]))
    print()

def view_browsing_history(device_id=None, hours=24, limit=100):
    """View browsing history (URLs visited)"""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = '''
        SELECT
            uv.url,
            uv.full_url,
            uv.method,
            uv.status_code,
            uv.timestamp,
            uv.source_ip,
            d.mac_address,
            d.hostname
        FROM urls_visited uv
        LEFT JOIN devices d ON uv.device_id = d.id
        WHERE uv.timestamp >= datetime('now', '-' || ? || ' hours')
    '''

    params = [hours]

    if device_id:
        query += ' AND uv.device_id = ?'
        params.append(device_id)

    query += ' ORDER BY uv.timestamp DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()

    if not results:
        print(f"\n[*] No browsing history found in the last {hours} hours")
        return

    print(f"\n{'='*120}")
    print(f"BROWSING HISTORY (Last {hours} hours)")
    print(f"{'='*120}\n")

    table_data = []
    for row in results:
        # Truncate URL if too long
        url_display = row['url'][:50] + '...' if len(row['url']) > 50 else row['url']

        table_data.append([
            row['timestamp'],
            row['hostname'] or row['mac_address'][:17],
            row['method'],
            row['status_code'] or 'N/A',
            url_display
        ])

    print(tabulate(table_data,
                  headers=['Time', 'Device', 'Method', 'Status', 'URL'],
                  tablefmt='grid',
                  maxcolwidths=[None, 20, 8, 8, 70]))
    print()

def view_form_submissions(device_id=None, hours=24, limit=50):
    """View form submissions"""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = '''
        SELECT
            fs.url,
            fs.form_data,
            fs.timestamp,
            fs.source_ip,
            d.mac_address,
            d.hostname
        FROM form_submissions fs
        LEFT JOIN devices d ON fs.device_id = d.id
        WHERE fs.timestamp >= datetime('now', '-' || ? || ' hours')
    '''

    params = [hours]

    if device_id:
        query += ' AND fs.device_id = ?'
        params.append(device_id)

    query += ' ORDER BY fs.timestamp DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()

    if not results:
        print(f"\n[*] No form submissions found in the last {hours} hours")
        return

    print(f"\n{'='*100}")
    print(f"FORM SUBMISSIONS (Last {hours} hours)")
    print(f"{'='*100}\n")

    for row in results:
        print(f"Time: {row['timestamp']}")
        print(f"Device: {row['hostname'] or row['mac_address'][:17]} ({row['source_ip']})")
        print(f"URL: {row['url']}")
        print(f"Data: {row['form_data']}")
        print("-" * 100)
        print()

def view_top_sites(device_id=None, hours=24, limit=20):
    """View most visited sites"""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = '''
        SELECT
            url,
            COUNT(*) as visit_count
        FROM urls_visited
        WHERE timestamp >= datetime('now', '-' || ? || ' hours')
    '''

    params = [hours]

    if device_id:
        query += ' AND device_id = ?'
        params.append(device_id)

    query += '''
        GROUP BY url
        ORDER BY visit_count DESC
        LIMIT ?
    '''
    params.append(limit)

    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()

    if not results:
        print(f"\n[*] No browsing data found")
        return

    print(f"\n{'='*80}")
    print(f"TOP VISITED SITES (Last {hours} hours)")
    print(f"{'='*80}\n")

    table_data = []
    for row in results:
        table_data.append([
            row['url'],
            row['visit_count']
        ])

    print(tabulate(table_data,
                  headers=['Website', 'Visits'],
                  tablefmt='grid',
                  maxcolwidths=[60, None]))
    print()

def view_device_summary(device_id):
    """View comprehensive summary for a device"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get device info
    cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
    device = cursor.fetchone()

    if not device:
        print(f"[!] Device ID {device_id} not found")
        return

    print(f"\n{'='*80}")
    print(f"DEVICE ACTIVITY SUMMARY")
    print(f"{'='*80}")
    print(f"MAC Address: {device['mac_address']}")
    print(f"IP Address: {device['ip_address']}")
    print(f"Hostname: {device['hostname'] or 'Unknown'}")
    print(f"First Seen: {device['first_seen']}")
    print(f"Last Seen: {device['last_seen']}")
    print(f"{'='*80}\n")

    # Count statistics
    cursor.execute('SELECT COUNT(*) FROM search_queries WHERE device_id = ?', (device_id,))
    search_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM urls_visited WHERE device_id = ?', (device_id,))
    url_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM dns_queries WHERE device_id = ?', (device_id,))
    dns_count = cursor.fetchone()[0]

    print(f"Total Search Queries: {search_count}")
    print(f"Total URLs Visited: {url_count}")
    print(f"Total DNS Queries: {dns_count}")
    print()

    conn.close()

    # Show recent activity
    view_search_history(device_id, hours=24, limit=10)
    view_browsing_history(device_id, hours=24, limit=20)
    view_top_sites(device_id, hours=24, limit=10)

def main():
    parser = argparse.ArgumentParser(
        description='View captured search queries and browsing history',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # View all search queries (last 24 hours)
  python view_searches.py --searches

  # View browsing history
  python view_searches.py --history

  # View searches for specific device
  python view_searches.py --searches --device 1

  # View last 48 hours
  python view_searches.py --searches --hours 48

  # View only Google searches
  python view_searches.py --searches --engine google

  # View comprehensive device summary
  python view_searches.py --summary --device 1

  # View top visited sites
  python view_searches.py --top-sites

  # View form submissions
  python view_searches.py --forms
        '''
    )

    parser.add_argument('-s', '--searches', action='store_true',
                       help='View search query history')
    parser.add_argument('-H', '--history', action='store_true',
                       help='View browsing history (URLs)')
    parser.add_argument('-f', '--forms', action='store_true',
                       help='View form submissions')
    parser.add_argument('-t', '--top-sites', action='store_true',
                       help='View top visited sites')
    parser.add_argument('--summary', action='store_true',
                       help='View comprehensive device summary')
    parser.add_argument('-d', '--device', type=int,
                       help='Filter by device ID')
    parser.add_argument('--hours', type=int, default=24,
                       help='Time range in hours (default: 24)')
    parser.add_argument('-e', '--engine', type=str,
                       help='Filter by search engine (google, bing, yahoo, etc.)')
    parser.add_argument('--limit', type=int, default=100,
                       help='Limit number of results')

    args = parser.parse_args()

    if args.summary:
        if not args.device:
            print("[!] --summary requires --device ID")
            return
        view_device_summary(args.device)
    elif args.searches:
        view_search_history(args.device, args.hours, args.engine, args.limit)
    elif args.history:
        view_browsing_history(args.device, args.hours, args.limit)
    elif args.forms:
        view_form_submissions(args.device, args.hours, args.limit)
    elif args.top_sites:
        view_top_sites(args.device, args.hours, args.limit)
    else:
        # Default: show everything
        view_search_history(hours=args.hours, limit=20)
        view_browsing_history(hours=args.hours, limit=30)
        view_top_sites(hours=args.hours, limit=10)


if __name__ == '__main__':
    main()
