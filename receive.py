#!/usr/bin/env python3
import sys
from scapy.all import get_if_list, Ether, IP, sniff

def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0")
    sys.exit(1)

def parse_int(pkt):
    raw = bytes(pkt)
    # Ethernet (14B) + IPv4 header (ihl*4)
    eth_len = 14
    ihl = (raw[14] & 0x0F) * 4
    off = eth_len + ihl

    # While there are at least 6 bytes remaining, treat them as INT entries
    while off + 6 <= len(raw):
        hop = raw[off]
        sw  = raw[off + 1]
        ts  = int.from_bytes(raw[off + 2:off + 6], "big")
        print(f"INT -> hop_count={hop}, switch_id={sw}, ts={ts}")
        off += 6

def main():
    iface = get_if()
    print(f"sniffing on {iface}")
    sniff(iface=iface, prn=parse_int)

if __name__ == '__main__':
    main
