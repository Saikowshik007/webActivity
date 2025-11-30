# Device Filtering Guide

## Overview

The network monitor can be configured to capture activity from **only specific devices** instead of all devices on your network. This is useful for:

- **Parental Controls**: Monitor only your children's devices
- **IoT Monitoring**: Track only smart home devices
- **Specific User Tracking**: Focus on particular devices of interest
- **Reducing Noise**: Filter out irrelevant network traffic

## How It Works

The device filter uses MAC addresses to identify which devices to monitor. When filtering is enabled:

1. All network packets are captured
2. Each packet's source MAC address is checked
3. Only packets from "interested devices" are logged to the database
4. Other traffic is ignored

## Configuration File

Device filter settings are stored in `device_filter.json`:

```json
{
  "monitor_all_devices": true,
  "interested_devices": [
    "AA:BB:CC:DD:EE:FF",
    "11:22:33:44:55:66"
  ],
  "description": "Add MAC addresses of devices you want to monitor."
}
```

- `monitor_all_devices`: `true` = capture all devices, `false` = filter enabled
- `interested_devices`: List of MAC addresses to monitor

## Using the Device Manager

### View Status

```bash
python manage_devices.py --status
```

Shows:
- Current filter mode (all devices vs. filtered)
- List of interested devices (if any)
- All detected devices on your network
- Which devices are currently being monitored

### Interactive Mode (Recommended)

```bash
python manage_devices.py --interactive
```

This launches an interactive menu where you can:
1. See all detected devices with their MAC addresses and IPs
2. Select devices by number (comma-separated)
3. Automatically enable filtering

### Manual Device Management

```bash
# Add a device
python manage_devices.py --add AA:BB:CC:DD:EE:FF

# Remove a device
python manage_devices.py --remove AA:BB:CC:DD:EE:FF

# Clear all devices
python manage_devices.py --clear
```

### Enable/Disable Filtering

```bash
# Enable filtering (monitor only interested devices)
python manage_devices.py --enable-filter

# Disable filtering (monitor all devices)
python manage_devices.py --disable-filter
```

## Complete Workflow Example

### Scenario: Monitor Your Kids' Devices

**Step 1: Discover Devices**
```bash
# Run monitor to detect all devices
python network_monitor.py
# Let it run for a few minutes to detect devices
# Press Ctrl+C to stop
```

**Step 2: View Detected Devices**
```bash
python manage_devices.py --status
```

Output:
```
DETECTED DEVICES ON NETWORK
╒════╤═══════════════════╤══════════════╤══════════╕
│  # │ MAC Address       │ IP Address   │  Queries │
├────┼───────────────────┼──────────────┼──────────┤
│  1 │ AA:BB:CC:DD:EE:FF │ 192.168.1.10 │      234 │ (Your laptop)
│  2 │ 11:22:33:44:55:66 │ 192.168.1.15 │      156 │ (Kid's phone)
│  3 │ 77:88:99:AA:BB:CC │ 192.168.1.20 │       89 │ (Kid's tablet)
│  4 │ DD:EE:FF:00:11:22 │ 192.168.1.25 │       45 │ (Smart TV)
╘════╧═══════════════════╧══════════════╧══════════╛
```

**Step 3: Add Devices to Monitor**
```bash
# Add kid's phone
python manage_devices.py --add 11:22:33:44:55:66

# Add kid's tablet
python manage_devices.py --add 77:88:99:AA:BB:CC
```

Or use interactive mode:
```bash
python manage_devices.py --interactive
# Enter: 2,3
```

**Step 4: Enable Filtering**
```bash
python manage_devices.py --enable-filter
```

Output:
```
[✓] Device filtering ENABLED
[*] Now monitoring only 2 device(s)
```

**Step 5: Start Monitoring**
```bash
python network_monitor.py
```

Output:
```
============================================================
Network Activity Monitor Started
============================================================
[*] Database: network_activity.db
[*] Filter Mode: MONITORING 2 INTERESTED DEVICE(S)
    - 11:22:33:44:55:66
    - 77:88:99:AA:BB:CC
[*] Monitoring DNS queries and web connections...
```

Now only the two specified devices will be logged!

## Switching Back to Monitor All Devices

```bash
python manage_devices.py --disable-filter
python network_monitor.py
```

Output:
```
[*] Filter Mode: MONITORING ALL DEVICES
```

## Finding MAC Addresses

### From the Monitor
The easiest way is to run the monitor briefly and check the database:
```bash
python query_history.py --list
```

### From Windows Command Prompt
```bash
arp -a
```

### From Linux/Mac Terminal
```bash
arp -a
# or
ip neigh
```

### From Your Router
Most routers have a "Connected Devices" page showing MAC addresses.

## Tips

1. **Run Unfiltered First**: Always run the monitor without filtering first to discover all devices
2. **MAC Address Format**: Can be entered with or without colons (AA:BB:CC:DD:EE:FF or AABBCCDDEEFF)
3. **Case Insensitive**: MAC addresses are automatically normalized to uppercase
4. **Dynamic IPs**: Filtering uses MAC addresses (not IPs) because IPs can change
5. **Config Editable**: You can manually edit `device_filter.json` if needed

## Troubleshooting

### "No devices to monitor" but I added devices
- Make sure you ran `--enable-filter` after adding devices
- Check `device_filter.json` to verify devices are listed
- Restart the monitor after enabling filtering

### Not capturing anything after enabling filter
- Verify the MAC addresses are correct
- Check that the devices are actually active on the network
- Run `--status` to confirm filter configuration

### Want to start over
```bash
# Clear everything and start fresh
python manage_devices.py --clear
python manage_devices.py --disable-filter
```

## Advanced: Manual Config Editing

You can directly edit `device_filter.json`:

```json
{
  "monitor_all_devices": false,
  "interested_devices": [
    "AA:BB:CC:DD:EE:FF",
    "11:22:33:44:55:66",
    "77:88:99:AA:BB:CC"
  ],
  "description": "Monitoring kids' devices"
}
```

After editing, restart the monitor to apply changes.
