# Quick Start Guide

## 3-Step Setup

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

**Windows users**: Also download and install [Npcap](https://npcap.com/#download)

### Step 2: Start Monitoring (Run as Administrator!)

**Windows:**
1. Right-click `start_monitor.bat` → "Run as Administrator"

**Or via command line:**
```bash
# Windows: Open Command Prompt as Administrator
python network_monitor.py

# Linux/Mac
sudo python network_monitor.py
```

You should see:
```
Network Activity Monitor Started
[*] Monitoring DNS queries and web connections...
[DNS] 192.168.1.10 -> google.com
```

### Step 3: View Your Data

**Option A: Web Interface (Recommended)**

Open a new terminal and run:
```bash
python web_viewer.py
```

Open browser to: http://localhost:5000

**Option B: Command Line**

```bash
# List devices
python query_history.py --list

# View device activity
python query_history.py --device 1

# Search for domains
python query_history.py --search youtube
```

## What You'll See

The network monitor will show you:
- ✅ Every device connected to your WiFi
- ✅ What websites they're visiting (DNS lookups)
- ✅ When they accessed them
- ✅ How frequently they visit certain sites
- ❌ Specific page content (HTTPS is encrypted)
- ❌ Actual search terms (HTTPS is encrypted)

## Understanding the Data

### DNS Queries
When a device visits `www.youtube.com`, you'll see:
- Device MAC: `AA:BB:CC:DD:EE:FF`
- IP Address: `192.168.1.10`
- Domain: `youtube.com`
- Timestamp: `2025-11-30 14:23:45`

### What You Can Learn
- Which apps/services devices are using
- Time of day usage patterns
- Most frequently visited sites
- New devices joining your network

### Privacy Limitations
Due to HTTPS encryption:
- ✅ You can see: `facebook.com` was accessed
- ❌ You cannot see: Which posts were viewed
- ✅ You can see: `google.com` was queried
- ❌ You cannot see: The actual search terms

## Monitor Only Specific Devices (Optional)

By default, the monitor tracks ALL devices. You can filter to monitor only specific devices (e.g., your kids' devices).

### Quick Filter Setup

```bash
# 1. First, run monitor to discover devices
python network_monitor.py
# Let it run for a minute, then press Ctrl+C

# 2. See all detected devices
python manage_devices.py --status

# 3. Add devices you want to monitor
python manage_devices.py --add AA:BB:CC:DD:EE:FF
python manage_devices.py --add 11:22:33:44:55:66

# 4. Enable filtering
python manage_devices.py --enable-filter

# 5. Restart monitor (now only tracks those devices)
python network_monitor.py
```

### Interactive Mode (Easier!)

```bash
# Run this to select devices from a menu
python manage_devices.py --interactive
```

### Filter Management Commands

```bash
# View filter status
python manage_devices.py --status

# Add device to monitor list
python manage_devices.py --add <MAC_ADDRESS>

# Remove device from list
python manage_devices.py --remove <MAC_ADDRESS>

# Enable filtering (monitor only interested devices)
python manage_devices.py --enable-filter

# Disable filtering (monitor all devices)
python manage_devices.py --disable-filter
```

## Common Issues

### "Permission denied"
→ You must run as Administrator (Windows) or with sudo (Linux/Mac)

### "No packets captured"
→ Check that:
1. You're running with admin/root privileges
2. Npcap is installed (Windows)
3. Your WiFi is active

### "Database locked"
→ Only run ONE instance of `network_monitor.py`

## Tips for Best Results

1. **Run on main router** (if possible) - Sees all network traffic
2. **Run on desktop PC** connected to WiFi - Sees traffic from that network
3. **Leave running 24/7** - Builds comprehensive history
4. **Check web interface** - Much easier than CLI for browsing

## Example Usage Scenarios

### Parental Controls
```bash
# See what your kids' devices are accessing
python query_history.py --device 3 --hours 24
```

### Bandwidth Investigation
```bash
# Find which device is using streaming services
python query_history.py --search netflix
python query_history.py --search youtube
```

### Network Security
```bash
# See all devices on your network
python query_history.py --list

# Investigate suspicious device
python query_history.py --device 5
```

## Next Steps

- Read the full [README.md](README.md) for advanced usage
- Explore the SQLite database directly for custom queries
- Set up the monitor to run as a background service

## Need Help?

Check the [README.md](README.md) for:
- Detailed troubleshooting
- Advanced configuration
- Database export options
- Security considerations
