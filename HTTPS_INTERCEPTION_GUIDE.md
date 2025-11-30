# HTTPS Traffic Interception Guide

## Overview

This guide explains how to capture **encrypted HTTPS traffic** including:
- ✅ Google searches and search terms
- ✅ Exact URLs visited (not just domains)
- ✅ YouTube videos watched
- ✅ Facebook/Instagram activity
- ✅ Form submissions
- ✅ Complete browsing history

## ⚠️ IMPORTANT Legal & Ethical Notice

**This is advanced network monitoring that decrypts HTTPS traffic.**

**✅ Legal Use Cases:**
- Monitoring your own devices
- Parental controls on your children's devices
- Corporate network monitoring (with proper authorization)
- Educational purposes on test networks

**❌ ILLEGAL Use Cases:**
- Monitoring others without consent
- Public WiFi networks you don't own
- Any unauthorized interception
- Violating privacy laws

**You are responsible for legal compliance in your jurisdiction.**

## How It Works

### The Problem
- HTTPS encrypts all web traffic (searches, URLs, content)
- Standard packet capture only sees encrypted data
- You can see domains (via DNS) but not actual pages or searches

### The Solution
**SSL/TLS Interception (Man-in-the-Middle)**

1. Your computer positions itself between the target device and the internet
2. It decrypts HTTPS traffic, logs it, then re-encrypts it
3. Target device thinks it's talking directly to websites
4. You see everything in plain text

## Requirements

### 1. Software
```bash
pip install -r requirements.txt
```

Key components:
- **mitmproxy** - HTTPS interception proxy
- **scapy** - Network packet manipulation
- **ARP spoofing** - Traffic redirection

### 2. Permissions
- Root/Administrator privileges
- Physical access to your network
- Ability to install certificates on monitored devices

### 3. Network Setup
- Devices must be on same local network
- Router must allow ARP spoofing (most do)
- Monitoring computer must have IP forwarding capability

## Setup Guide

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

**Windows:**
- Install [Npcap](https://npcap.com/#download)

**Linux:**
```bash
sudo apt-get install iptables
```

### Step 2: Discover Devices

```bash
# Scan network to find all devices
sudo python scan_network.py
```

Note the IP addresses of devices you want to monitor.

### Step 3: Start the HTTPS Interceptor

Open **Terminal 1**:

```bash
# Start mitmproxy in transparent mode
mitmdump --mode transparent -s https_interceptor.py
```

Leave this running. You'll see:
```
Proxy server listening at http://*:8080
```

### Step 4: Install Certificate on Target Device

**This is CRITICAL - without this, HTTPS interception won't work!**

From the **target device** (phone, tablet, computer you're monitoring):

1. **Make sure the device can access the monitoring computer**
   - Both devices on same WiFi
   - Monitoring computer's proxy is running (Step 3)

2. **Visit the certificate installation page**
   - Open browser on target device
   - Go to: **http://mitm.it**

3. **Download and install the certificate**
   - Click your device type (iOS, Android, Windows, etc.)
   - Follow installation instructions
   - **Trust the certificate as a root CA**

**iOS:**
- Settings → General → VPN & Device Management → Install Profile
- Settings → General → About → Certificate Trust Settings → Enable

**Android:**
- Settings → Security → Install from storage
- Select mitmproxy certificate

**Windows:**
- Install certificate to "Trusted Root Certification Authorities"

**macOS:**
- Add to Keychain → Always Trust

### Step 5: Start Traffic Interception (ARP Spoofing)

Open **Terminal 2**:

```bash
# Replace 192.168.1.15 with target device IP
sudo python setup_mitm.py --target 192.168.1.15

# For multiple devices:
sudo python setup_mitm.py --target 192.168.1.15 --target 192.168.1.20
```

You'll see:
```
Starting ARP Spoofing
[*] Gateway: 192.168.1.1
[*] Targets: 192.168.1.15
[*] Packets sent: 20
```

**Leave this running!** It's redirecting traffic through your computer.

### Step 6: Browse from Target Device

On the target device:
- Open browser
- Search on Google
- Visit websites
- Watch YouTube

### Step 7: View Captured Data

Open **Terminal 3**:

```bash
# View all search queries
python view_searches.py --searches

# View browsing history
python view_searches.py --history

# View device summary
python view_searches.py --summary --device 1

# View top visited sites
python view_searches.py --top-sites
```

## Example Output

### Google Searches Captured

```
SEARCH QUERY HISTORY (Last 24 hours)
╒════════════════════╤════════════╤═══════════════╤════════╤═══════════════════════════════════╕
│ Time               │ Device     │ IP            │ Engine │ Search Query                      │
├────────────────────┼────────────┼───────────────┼────────┼───────────────────────────────────┤
│ 2025-11-30 14:23   │ iPhone-12  │ 192.168.1.15  │ GOOGLE │ best pizza near me                │
│ 2025-11-30 14:19   │ iPhone-12  │ 192.168.1.15  │ GOOGLE │ how to bake cookies               │
│ 2025-11-30 13:45   │ iPad       │ 192.168.1.20  │ GOOGLE │ minecraft tutorial                │
│ 2025-11-30 13:22   │ iPad       │ 192.168.1.20  │ YOUTUBE│ fortnite gameplay                 │
╘════════════════════╧════════════╧═══════════════╧════════╧═══════════════════════════════════╛
```

### URLs Visited

```
BROWSING HISTORY (Last 24 hours)
╒════════════════════╤════════════╤════════╤════════╤═════════════════════════════════════╕
│ Time               │ Device     │ Method │ Status │ URL                                 │
├────────────────────┼────────────┼────────┼────────┼─────────────────────────────────────┤
│ 2025-11-30 14:25   │ iPhone-12  │ GET    │ 200    │ www.youtube.com/watch?v=dQw4w9WgXcQ │
│ 2025-11-30 14:20   │ iPhone-12  │ GET    │ 200    │ www.instagram.com/explore/          │
│ 2025-11-30 14:15   │ iPad       │ GET    │ 200    │ www.roblox.com/games                │
╘════════════════════╧════════════╧════════╧════════╧═════════════════════════════════════╛
```

## Troubleshooting

### Certificate Issues

**Problem:** "Your connection is not private" warnings on target device

**Solution:**
- Certificate not installed correctly
- Visit http://mitm.it again
- Make sure certificate is trusted as ROOT CA
- On iOS: Enable in Certificate Trust Settings

### No Traffic Captured

**Problem:** mitmproxy running but no traffic logged

**Checklist:**
1. ✅ Is ARP spoofing running? (Terminal 2)
2. ✅ Is mitmproxy running? (Terminal 1)
3. ✅ Certificate installed on target device?
4. ✅ Target device on same WiFi?
5. ✅ IP forwarding enabled?

**Test:**
```bash
# On monitoring computer
sudo sysctl net.ipv4.ip_forward
# Should return: net.ipv4.ip_forward = 1
```

### ARP Spoofing Not Working

**Linux:**
```bash
# Enable IP forwarding manually
sudo sysctl -w net.ipv4.ip_forward=1

# Check iptables rules
sudo iptables -t nat -L
```

**macOS:**
```bash
sudo sysctl -w net.inet.ip.forwarding=1
```

**Windows:**
```powershell
# Run as Administrator
Set-NetIPInterface -Forwarding Enabled
```

### Target Device Loses Internet

**Problem:** Device has no internet when ARP spoofing is active

**Solution:**
- IP forwarding not enabled
- mitmproxy not running
- Firewall blocking forwarded traffic

```bash
# Check if traffic is being forwarded
sudo tcpdump -i any port 8080
```

## Advanced Usage

### Monitor Specific Apps

```bash
# Filter by URL patterns in view_searches.py
python view_searches.py --history | grep youtube
python view_searches.py --history | grep instagram
```

### Automatic Daily Reports

Create a cron job/scheduled task:

```bash
# Daily report at 11 PM
0 23 * * * python view_searches.py --summary --device 1 > /tmp/daily_report.txt
```

### Integration with Web Viewer

The captured HTTPS data is stored in the same database as DNS queries.
You can view it in the web interface at http://localhost:5000

## Security Best Practices

1. **Secure Your Monitoring Computer**
   - Use strong password
   - Encrypt hard drive
   - The database contains sensitive browsing history!

2. **Certificate Security**
   - Never share your mitmproxy certificate
   - Revoke certificates when done monitoring
   - Don't leave certificates installed unnecessarily

3. **Data Privacy**
   - The database contains very sensitive data
   - Passwords are automatically redacted from forms
   - Still, treat this data with extreme care

4. **Legal Compliance**
   - Inform users they're being monitored (as required by law)
   - Only use for authorized purposes
   - Follow local privacy laws

## Stopping Interception

### Safely Stop Monitoring

1. **Terminal 2 (ARP Spoofing):**
   - Press `Ctrl+C`
   - Script automatically restores network

2. **Terminal 1 (mitmproxy):**
   - Press `Ctrl+C`

3. **Remove Certificate from Target Device**
   - iOS: Settings → General → VPN & Device Management → Delete Profile
   - Android: Settings → Security → Trusted Certificates → Remove
   - Windows: certmgr.msc → Trusted Root → Remove mitmproxy

## Summary

**To capture HTTPS traffic and Google searches:**

```bash
# Terminal 1
mitmdump --mode transparent -s https_interceptor.py

# Terminal 2
sudo python setup_mitm.py --target 192.168.1.15

# Terminal 3 (after target browses)
python view_searches.py --searches
python view_searches.py --history
```

**Requirements:**
- ✅ Certificate installed on target device
- ✅ ARP spoofing active
- ✅ mitmproxy running
- ✅ IP forwarding enabled

You'll now see **everything** - Google searches, exact URLs, YouTube videos, social media activity, etc.
