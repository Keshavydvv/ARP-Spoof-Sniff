#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for sent, received in answered_list:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})
    return clients

def print_result(clients):
    print("IP Address\t\tMAC Address")
    print("-" * 50)
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

def main():
    parser = argparse.ArgumentParser(description="ARP Network Scanner")
    parser.add_argument(
        "-r", "--range",
        dest="ip_range",
        required=True,
        help="IP range to scan (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "-i", "--iface",
        dest="iface",
        default=None,
        help="Network interface to use (e.g., eth0)"
    )
    args = parser.parse_args()

    if args.iface:
        scapy.conf.iface = args.iface

    print(f"[*] Scanning network range: {args.ip_range}")
    if args.iface:
        print(f"[*] Using interface: {args.iface}")
    print()

    results = scan(args.ip_range)
    print_result(results)

if __name__ == "__main__":
    main()
