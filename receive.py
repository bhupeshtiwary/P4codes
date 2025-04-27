#!/usr/bin/env python3
import os
import sys
from scapy.all import get_if_list, sniff, Ether, IP

def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface



def parse_int(pkt):
    if Ether not in pkt:
        return
    
    raw = bytes(pkt)
    eth_offset = 14  # Ethernet header length
    ether_type = int.from_bytes(raw[12:14], byteorder='big')  # Ethernet type at offset 12-13

    # Only process INT packets
    if ether_type != 0x1212:
        return

    int_offset = eth_offset
    while True:
        # Check if we have enough bytes for an INT header
        if int_offset + 10 > len(raw):
            break
            
        # Extract INT header fields (10 bytes)
        hop_count = raw[int_offset]
        switch_id = raw[int_offset + 1]
        ingress_ts = int.from_bytes(raw[int_offset + 2:int_offset + 8], "big")
        next_proto = int.from_bytes(raw[int_offset + 8:int_offset + 10], "big")

        print(f"INT -> hop_count={hop_count}, switch_id={switch_id}, ts={ingress_ts}")
        
        # Move to next header
        int_offset += 10
        
        # Check next protocol type
        if next_proto == 0x1212:  # Another INT header
            continue
        elif next_proto == 0x0800:  # IPv4 follows
            # Parse IPv4 header if needed
            if int_offset + 20 > len(raw):
                break
            src_ip = raw[int_offset + 12 : int_offset + 16]
            dst_ip = raw[int_offset + 16 : int_offset + 20]
            print(f"IP: {socket.inet_ntoa(src_ip)} -> {socket.inet_ntoa(dst_ip)}")
            break
        else:  # Unknown protocol
            break


def main():
    iface = get_if()
    print("sniffing on %s" % iface)
    sniff(iface=iface, prn=parse_int)

if __name__ == '__main__':
    main()
