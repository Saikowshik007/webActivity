
# Network Activity Monitor

A Python-based network monitoring tool that captures and logs device-level WiFi activity on your local network. Track DNS queries, web connections, and view comprehensive device history through a web interface or CLI.

## Features

- **Real-time Network Monitoring**: Captures DNS queries and HTTP/HTTPS connection attempts
- **Device Tracking**: Automatically identifies and tracks devices by MAC and IP address
- **Historical Data**: Stores all activity in SQLite database for historical analysis
- **Web Dashboard**: Beautiful, responsive web interface to view network activity
- **CLI Tools**: Command-line interface for querying network history
- **Search Functionality**: Search for specific domains or devices
- **Top Domains**: See most frequently accessed domains
- **Device-Level Insights**: View detailed activity for each device on your network

## What Data is Captured?

### DNS Queries
- Domain names being looked up
- Query types (A, AAAA, CNAME, etc.)
- Source device (MAC + IP)
- Timestamps

### Web Connections
- HTTP (port 80) and HTTPS (port 443) connections
- Destination IPs and ports
- Connection protocols

### Device Information
- MAC addresses
- IP addresses
- First seen / Last seen timestamps
- Activity statistics

## Important Limitations

Due to modern web security:
- **HTTPS traffic is encrypted** - You can see which domains are accessed (via DNS) but not the specific pages or content
- **DNS over HTTPS (DoH)** - Some devices may bypass local DNS monitoring
- **VPN traffic** - Devices using VPNs will show connections to VPN servers only

This tool is designed for monitoring your own network for legitimate purposes like parental controls, bandwidth analysis, or network debugging.

## Requirements

- **Windows/Linux/macOS** with Python 3.7+
- **Administrator/Root privileges** (required for packet capture)
- **Network access** to WiFi router or ability to run on a device that can see all network traffic

## Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

On Windows, you may also need to install:
- **Npcap** (for packet capture): https://npcap.com/#download

On Linux, install `tcpdump`:
```bash
sudo apt-get install tcpdump
```

### 2. Verify Installation

```bash
python network_monitor.py --help
```

## Usage

### 1. Start Network Monitoring

**Windows (Run as Administrator):**
```bash
# Right-click Command Prompt -> "Run as Administrator"
python network_monitor.py
```

**Linux/Mac:**
```bash
sudo python network_monitor.py
```

The monitor will start capturing network activity and storing it in `network_activity.db`.

Leave this running in the background to collect data.

### 2. View Data via Web Interface

In a separate terminal:

```bash
python web_viewer.py
```

Then open your browser to: **http://localhost:5000**

The web interface provides:
- Real-time device list
- DNS query history per device
- Top queried domains
- Activity timeline
- Device statistics

### 3. Query Data via Command Line

```bash
# List all devices
python query_history.py --list

# Show activity for device ID 1 (last 24 hours)
python query_history.py --device 1

# Show activity for last 48 hours
python query_history.py --device 1 --hours 48

# Search for specific domains
python query_history.py --search facebook
python query_history.py --search google

# Show top 20 most queried domains
python query_history.py --top

# Show top domains for last week
python query_history.py --top --hours 168
```

## Example Output

### Web Interface
The web dashboard shows:
- Total devices on network
- Active devices (last 24h)
- DNS query counts
- Real-time activity feed
- Device-specific history

### CLI Output
```
================================================================================
DEVICES ON NETWORK
================================================================================
╒══════╤═══════════════════╤══════════════╤══════════╤═══════════════════════╕
│   ID │ MAC Address       │ IP Address   │  Queries │ Last Seen             │
╞══════╪═══════════════════╪══════════════╪══════════╪═══════════════════════╡
│    1 │ AA:BB:CC:DD:EE:FF │ 192.168.1.10 │      234 │ 2025-11-30 14:23:45   │
│    2 │ 11:22:33:44:55:66 │ 192.168.1.15 │      156 │ 2025-11-30 14:20:12   │
╘══════╧═══════════════════╧══════════════╧══════════╧═══════════════════════╛
```

## Project Structure

```
webActivity/
├── network_monitor.py      # Main monitoring script (run with admin/root)
├── web_viewer.py           # Web interface server
├── query_history.py        # CLI query tool
├── requirements.txt        # Python dependencies
├── network_activity.db     # SQLite database (created on first run)
├── templates/
│   └── index.html         # Web interface HTML
└── README.md              # This file
```

## How It Works

1. **Packet Capture**: Uses Scapy to capture network packets on your WiFi interface
2. **DNS Monitoring**: Intercepts DNS queries (UDP port 53) to see what domains devices are looking up
3. **Connection Tracking**: Monitors TCP connections to ports 80 (HTTP) and 443 (HTTPS)
4. **Device Identification**: Extracts MAC and IP addresses to identify unique devices
5. **Data Storage**: Logs all activity to SQLite database for historical analysis
6. **Visualization**: Provides web and CLI interfaces to explore the data

## Security & Privacy Notes

- This tool is designed for monitoring **your own network** only
- Requires physical access and administrator privileges
- Cannot decrypt HTTPS traffic (you only see DNS lookups and connection metadata)
- Use responsibly and in compliance with local laws
- Inform users on your network that monitoring is taking place

## Troubleshooting

### "Permission denied" error
- **Windows**: Run Command Prompt as Administrator
- **Linux/Mac**: Use `sudo` before the command

### "No module named 'scapy'"
```bash
pip install -r requirements.txt
```

### Not capturing any packets
- Check that you're running with admin/root privileges
- Verify network interface is active
- On Windows, ensure Npcap is installed
- Try specifying network interface: Check available interfaces first

### Database locked errors
- Only run one instance of `network_monitor.py` at a time
- Close `web_viewer.py` before running database-intensive queries

## Advanced Usage

### Monitor Specific Network Interface

Find available interfaces:
```python
from scapy.all import get_if_list
print(get_if_list())
```

Then modify `network_monitor.py` line with `start_monitoring()` to specify interface:
```python
monitor.start_monitoring(interface="eth0")  # or "Wi-Fi", "wlan0", etc.
```

### Export Data

The SQLite database can be queried directly:
```bash
sqlite3 network_activity.db
```

Example queries:
```sql
-- All DNS queries today
SELECT * FROM dns_queries
WHERE date(timestamp) = date('now');

-- Device activity summary
SELECT d.mac_address, COUNT(*) as queries
FROM devices d
JOIN dns_queries dq ON d.id = dq.device_id
GROUP BY d.id;
```

## License

This tool is provided for educational and personal network monitoring purposes only. Use responsibly and ethically.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before monitoring network traffic.
