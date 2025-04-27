#!/usr/bin/env python3
import sys
from scapy.all import Ether, IP, sniff

def get_if():
    from scapy.all import get_if_list
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    sys.exit(1)


def parse_int(pkt):
    if Ether not in pkt or IP not in pkt:
        return
    raw = bytes(pkt)
    eth_len = 14
    ihl = (raw[14] & 0x0F) * 4
    int_off = eth_len + ihl
    if len(raw) < int_off + 6:
        return
    int_hdr = raw[int_off:int_off+6]
    hop_count = int_hdr[0]
    switch_id = int_hdr[1]
    ts = int.from_bytes(int_hdr[2:], 'big')
    print(f"INT -> hop_count={hop_count}, switch_id={switch_id}, ts={ts}")


def main():
    iface = get_if()
    print(f"Sniffing on {iface}")
    sniff(iface=iface, prn=parse_int)

if __name__ == '__main__':
    main()
