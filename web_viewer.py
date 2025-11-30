#!/usr/bin/env python3
"""
Web Interface for Network Activity Monitor
View device history and DNS queries through a web browser
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta
import os

app = Flask(__name__)
DB_PATH = 'network_activity.db'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    """Get all devices"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            d.id,
            d.mac_address,
            d.ip_address,
            d.hostname,
            d.first_seen,
            d.last_seen,
            COUNT(DISTINCT dq.id) as query_count,
            COUNT(DISTINCT c.id) as connection_count
        FROM devices d
        LEFT JOIN dns_queries dq ON d.id = dq.device_id
        LEFT JOIN connections c ON d.id = c.device_id
        GROUP BY d.id
        ORDER BY d.last_seen DESC
    ''')

    devices = []
    for row in cursor.fetchall():
        devices.append({
            'id': row['id'],
            'mac_address': row['mac_address'],
            'ip_address': row['ip_address'],
            'hostname': row['hostname'] or 'Unknown',
            'first_seen': row['first_seen'],
            'last_seen': row['last_seen'],
            'query_count': row['query_count'],
            'connection_count': row['connection_count']
        })

    conn.close()
    return jsonify(devices)

@app.route('/api/device/<int:device_id>/queries')
def get_device_queries(device_id):
    """Get DNS queries for a specific device"""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 100, type=int)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            query_name,
            query_type,
            timestamp,
            source_ip
        FROM dns_queries
        WHERE device_id = ?
        AND timestamp >= datetime('now', '-' || ? || ' hours')
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (device_id, hours, limit))

    queries = []
    for row in cursor.fetchall():
        queries.append({
            'query_name': row['query_name'],
            'query_type': row['query_type'],
            'timestamp': row['timestamp'],
            'source_ip': row['source_ip']
        })

    conn.close()
    return jsonify(queries)

@app.route('/api/device/<int:device_id>/connections')
def get_device_connections(device_id):
    """Get connections for a specific device"""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 100, type=int)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            dest_ip,
            dest_port,
            protocol,
            timestamp,
            source_ip
        FROM connections
        WHERE device_id = ?
        AND timestamp >= datetime('now', '-' || ? || ' hours')
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (device_id, hours, limit))

    connections = []
    for row in cursor.fetchall():
        connections.append({
            'dest_ip': row['dest_ip'],
            'dest_port': row['dest_port'],
            'protocol': row['protocol'],
            'timestamp': row['timestamp'],
            'source_ip': row['source_ip']
        })

    conn.close()
    return jsonify(connections)

@app.route('/api/recent_activity')
def get_recent_activity():
    """Get recent network activity across all devices"""
    limit = request.args.get('limit', 50, type=int)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            d.mac_address,
            d.ip_address,
            dq.query_name as activity,
            'DNS' as type,
            dq.timestamp
        FROM dns_queries dq
        JOIN devices d ON dq.device_id = d.id
        ORDER BY dq.timestamp DESC
        LIMIT ?
    ''', (limit,))

    activities = []
    for row in cursor.fetchall():
        activities.append({
            'mac_address': row['mac_address'],
            'ip_address': row['ip_address'],
            'activity': row['activity'],
            'type': row['type'],
            'timestamp': row['timestamp']
        })

    conn.close()
    return jsonify(activities)

@app.route('/api/top_queries')
def get_top_queries():
    """Get most frequently queried domains"""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 20, type=int)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            query_name,
            COUNT(*) as count
        FROM dns_queries
        WHERE timestamp >= datetime('now', '-' || ? || ' hours')
        GROUP BY query_name
        ORDER BY count DESC
        LIMIT ?
    ''', (hours, limit))

    queries = []
    for row in cursor.fetchall():
        queries.append({
            'domain': row['query_name'],
            'count': row['count']
        })

    conn.close()
    return jsonify(queries)

@app.route('/api/search')
def search():
    """Search DNS queries and connections"""
    query = request.args.get('q', '')

    if not query:
        return jsonify([])

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT DISTINCT
            d.mac_address,
            d.ip_address,
            dq.query_name,
            dq.timestamp
        FROM dns_queries dq
        JOIN devices d ON dq.device_id = d.id
        WHERE dq.query_name LIKE ?
        ORDER BY dq.timestamp DESC
        LIMIT 50
    ''', (f'%{query}%',))

    results = []
    for row in cursor.fetchall():
        results.append({
            'mac_address': row['mac_address'],
            'ip_address': row['ip_address'],
            'query_name': row['query_name'],
            'timestamp': row['timestamp']
        })

    conn.close()
    return jsonify(results)

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("[!] Please run network_monitor.py first to create the database")
        exit(1)

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         Network Activity Web Viewer                       ║
    ╚═══════════════════════════════════════════════════════════╝

    [*] Starting web server...
    [*] Open your browser to: http://localhost:5000
    [*] Press Ctrl+C to stop
    """)

    app.run(debug=True, host='0.0.0.0', port=5000)
