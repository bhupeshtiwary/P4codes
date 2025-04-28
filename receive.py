#!/usr/bin/env python3
from scapy.all import sniff, IP

PROTO_INT = 0x9A  # same as in your P4 program

def parse_int(pkt):
    # Only IPv4 INT packets
    if not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    if ip.proto != PROTO_INT:
        return

    raw = bytes(ip.payload)
    off = 0

    # Parse at most 4 INT entries, then stop
    for _ in range(4):
        if off + 8 > len(raw):
            break
        hop = raw[off]
        if hop == 0:
            break
        sw = raw[off + 1]
        ts = int.from_bytes(raw[off + 2 : off + 8], "big")
        print(f"INT -> hop_count={hop}, switch_id={sw}, ts={ts}")
        off += 8

if __name__ == "__main__":
    # Only capture our INT packets, exit after a while (optional)
    sniff(filter="ip proto 154", prn=parse_int)
