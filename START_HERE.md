# 🚀 START HERE - Simple Setup

## What This Does

**See EVERYTHING users do on your WiFi in ONE web dashboard:**
- ✅ Google searches (exact search terms)
- ✅ URLs visited (complete browsing history)
- ✅ YouTube videos watched
- ✅ All devices on network
- ✅ Top visited sites
- ✅ DNS queries

**Just open a browser - no command line bullshit!**

## Quick Setup (3 Steps)

### 1. Install

```bash
pip install -r requirements.txt
```

Windows: Also install [Npcap](https://npcap.com/#download)

### 2. Discover Devices

```bash
# Run as Administrator (Windows) or sudo (Linux/Mac)
python scan_network.py
```

This finds ALL devices on your network.

### 3. Start Everything

**Open 2 terminals:**

**Terminal 1 - Web Dashboard:**
```bash
python web_viewer.py
```

Then open browser: **http://localhost:5000**

That's it for basic monitoring (DNS only).

---

## To See HTTPS Traffic (Google Searches, Exact URLs)

You need 2 more terminals:

**Terminal 2 - HTTPS Interceptor:**
```bash
mitmdump --mode transparent -s https_interceptor.py
```

**Terminal 3 - Traffic Redirector:**
```bash
# Replace 192.168.1.15 with target device IP
sudo python setup_mitm.py --target 192.168.1.15
```

**Terminal 4 - Install Certificate on Target Device:**

From the device you're monitoring:
1. Open browser
2. Go to: **http://mitm.it**
3. Install certificate for your device type
4. Trust it as root certificate

Now browse from that device and refresh the dashboard - you'll see everything!

---

## The Dashboard Shows:

### 🔍 Search Queries Tab
- Every Google/Bing/Yahoo search
- Exact search terms typed
- Which device searched what
- Time of each search

### 🌐 Browsing History Tab
- Every URL visited (not just domains!)
- Full YouTube links
- Instagram posts
- Complete browsing history

### 📱 Devices Tab
- All devices on network
- MAC addresses
- IP addresses
- Hostnames
- Activity stats

### ⭐ Top Sites Tab
- Most visited websites
- Visit counts
- Ranked by popularity

### 📡 DNS Queries Tab
- All DNS lookups
- Domain queries
- Frequency

---

## That's It!

**No more fucking command line tools.**

Just open **http://localhost:5000** and see everything in the web dashboard.

The dashboard auto-refreshes every 30 seconds.

---

## Troubleshooting

**Not seeing Google searches/URLs?**
- HTTPS interceptor running? (Terminal 2)
- ARP spoofing running? (Terminal 3)
- Certificate installed on target device?
- Visit http://mitm.it from target device to install cert

**Not seeing all devices?**
- Run `python scan_network.py` as admin/root
- Wait a minute for scan to complete

**Dashboard shows no data?**
- Make sure you ran `scan_network.py` first
- Check that `network_activity.db` exists
- Restart `web_viewer.py`

---

## Legal Notice

Only use on networks YOU OWN. For parental controls and authorized monitoring only.
