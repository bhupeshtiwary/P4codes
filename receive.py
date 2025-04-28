#!/usr/bin/env python3
from scapy.all import sniff

def parse_int(pkt):
    raw = bytes(pkt)
    eth_len = 14
    ihl     = (raw[14] & 0x0F) * 4
    off     = eth_len + 20

    # Each INT entry is 8 bytes: hop(1) + switch_id(1) + ts(6)
    while off + 8 <= len(raw):
        hop = raw[off]
        if hop == 0:        # stop on unused slot
            break
        sw = raw[off + 1]
        ts = int.from_bytes(raw[off + 2 : off + 8], "big")
        print(f"INT -> hop_count={hop}, switch_id={sw}, ts={ts}")
        off += 8

if __name__ == "__main__":
    # Listen on all interfaces—inside h2 this will pick up h2-eth0
    sniff(prn=parse_int)
