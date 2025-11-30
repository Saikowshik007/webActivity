#!/usr/bin/env python3
"""
HTTPS Traffic Interceptor
Captures and decrypts HTTPS traffic including Google searches, URLs, and browsing history

IMPORTANT: This uses SSL/TLS interception which requires:
1. Running this script as a proxy
2. Installing a root certificate on monitored devices
3. Proper authorization - only use on networks you own
4. Legal compliance with local laws

This is designed for parental controls and legitimate network monitoring.
"""

import sqlite3
from mitmproxy import http, ctx
from mitmproxy.tools.main import mitmdump
import urllib.parse
import re
from datetime import datetime
import json
import sys

DB_PATH = 'network_activity.db'

class HTTPSInterceptor:
    def __init__(self):
        self.init_database()

    def init_database(self):
        """Add tables for HTTPS traffic interception"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # URLs visited table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS urls_visited (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                source_ip TEXT NOT NULL,
                url TEXT NOT NULL,
                full_url TEXT,
                method TEXT,
                status_code INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # Search queries table (Google, Bing, Yahoo, etc.)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS search_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                source_ip TEXT NOT NULL,
                search_engine TEXT NOT NULL,
                query TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # POST data table (form submissions)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS form_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                source_ip TEXT NOT NULL,
                url TEXT NOT NULL,
                form_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_urls_timestamp ON urls_visited(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_urls_device ON urls_visited(device_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_search_timestamp ON search_queries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_search_device ON search_queries(device_id)')

        conn.commit()
        conn.close()
        ctx.log.info("[✓] HTTPS Interceptor database initialized")

    def get_device_id(self, ip_address):
        """Get device ID from IP address"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (ip_address,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def extract_search_query(self, url, host):
        """Extract search queries from URLs"""
        search_engines = {
            'google': r'[?&]q=([^&]+)',
            'bing': r'[?&]q=([^&]+)',
            'yahoo': r'[?&]p=([^&]+)',
            'duckduckgo': r'[?&]q=([^&]+)',
            'yandex': r'[?&]text=([^&]+)',
            'baidu': r'[?&]wd=([^&]+)',
        }

        for engine, pattern in search_engines.items():
            if engine in host.lower():
                match = re.search(pattern, url)
                if match:
                    query = urllib.parse.unquote_plus(match.group(1))
                    return engine, query

        return None, None

    def log_url(self, flow: http.HTTPFlow):
        """Log visited URL"""
        try:
            source_ip = flow.client_conn.peername[0]
            url = flow.request.pretty_url
            host = flow.request.pretty_host
            method = flow.request.method
            status_code = flow.response.status_code if flow.response else None

            # Get device ID
            device_id = self.get_device_id(source_ip)

            # Check for search query
            search_engine, query = self.extract_search_query(url, host)

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Log the URL
            cursor.execute('''
                INSERT INTO urls_visited (device_id, source_ip, url, full_url, method, status_code)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (device_id, source_ip, host, url, method, status_code))

            # If it's a search query, log it separately
            if query:
                cursor.execute('''
                    INSERT INTO search_queries (device_id, source_ip, search_engine, query)
                    VALUES (?, ?, ?, ?)
                ''', (device_id, source_ip, search_engine, query))

                ctx.log.info(f"[SEARCH] {source_ip} -> {search_engine}: {query}")
            else:
                ctx.log.info(f"[URL] {source_ip} -> {method} {host}")

            conn.commit()
            conn.close()

        except Exception as e:
            ctx.log.error(f"Error logging URL: {e}")

    def log_post_data(self, flow: http.HTTPFlow):
        """Log POST data (form submissions)"""
        try:
            if flow.request.method == "POST":
                source_ip = flow.client_conn.peername[0]
                url = flow.request.pretty_url

                # Try to get form data
                content = flow.request.content
                if content:
                    try:
                        # Try to decode as form data
                        form_data = flow.request.urlencoded_form
                        if form_data:
                            # Filter out sensitive data (passwords, etc.)
                            filtered_data = {}
                            sensitive_fields = ['password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'key']

                            for key, value in form_data.items():
                                if any(sensitive in key.lower() for sensitive in sensitive_fields):
                                    filtered_data[key] = "[REDACTED]"
                                else:
                                    filtered_data[key] = value

                            device_id = self.get_device_id(source_ip)

                            conn = sqlite3.connect(DB_PATH)
                            cursor = conn.cursor()
                            cursor.execute('''
                                INSERT INTO form_submissions (device_id, source_ip, url, form_data)
                                VALUES (?, ?, ?, ?)
                            ''', (device_id, source_ip, url, json.dumps(filtered_data)))
                            conn.commit()
                            conn.close()

                            ctx.log.info(f"[FORM] {source_ip} -> POST to {url}")
                    except:
                        pass  # Not form data or couldn't decode

        except Exception as e:
            ctx.log.error(f"Error logging POST data: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP request"""
        # Log POST data on request
        if flow.request.method == "POST":
            self.log_post_data(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP response"""
        # Log URL after response (so we have status code)
        if flow.response:
            self.log_url(flow)


# Addon for mitmproxy
addons = [HTTPSInterceptor()]


def main():
    """Main entry point for standalone execution"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         HTTPS Traffic Interceptor                         ║
    ║         Captures encrypted web traffic                    ║
    ╚═══════════════════════════════════════════════════════════╝

    IMPORTANT SETUP REQUIRED:
    1. Install mitmproxy certificate on monitored devices
    2. Configure devices to use this computer as proxy
    3. Or use ARP spoofing (see setup_mitm.py)

    Starting proxy server...
    Certificate will be available at: http://mitm.it
    """)

    # Initialize database
    interceptor = HTTPSInterceptor()

    print("[*] Run mitmproxy with:")
    print("    mitmproxy -s https_interceptor.py")
    print("    OR")
    print("    mitmdump -s https_interceptor.py")
    print("\n[*] For transparent proxy mode:")
    print("    mitmdump --mode transparent -s https_interceptor.py")


if __name__ == '__main__':
    main()
