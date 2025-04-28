#!/usr/bin/env python3
import sys
from scapy.all import sniff, get_if_list

def get_if():
    # In h2's namespace the interface is literally "h2-eth0"
    return "h2-eth0"

def parse_int(pkt):
    raw = bytes(pkt)
    # Ethernet header = 14 bytes
    eth_len = 14
    # IHL (in 4-byte words) × 4 = full IPv4 header length
    ihl = (raw[14] & 0x0F) * 4
    off = eth_len + ihl

    # Each INT entry is 8 bytes: hop_count(1), switch_id(1), ts(6)
    while off + 8 <= len(raw):
        hop = raw[off]
        # stop if we hit an unused slot
        if hop == 0:
            break
        sw = raw[off + 1]
        ts = int.from_bytes(raw[off + 2 : off + 8], "big")
        print(f"INT -> hop_count={hop}, switch_id={sw}, ts={ts}")
        off += 8

def main():
    print("Available interfaces:", get_if_list())
    iface = get_if()
    print(f"Sniffing on {iface} (h2 namespace!)")
    # no filter so we see all packets; change count or timeout as you like
    sniff(iface=iface, prn=parse_int)

if __name__ == "__main__":
    main()
