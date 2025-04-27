#!/usr/bin/env python3
import os
import sys

from scapy.all import get_if_list, TCP,IP,sniff,  Ether



def get_if():
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def parse_int(pkt):
    if Ether not in pkt or IP not in pkt:
        return
    raw=bytes(pkt)
    eth_len=14
    ihl=(raw[14]&0x0F)*4
    int_off=eth_len+ihl

    if len(raw)<int_off+6:
        return
    int_hdr=raw[int_off:int_off+8]
    hop_count=int_hdr[0]
    switch_id=int_hdr[1]
    ts= int.from_bytes(int_hdr[2:],"big")
    print(f"INT -> hop_count={hop_count}, switch_id={switch_id}, ts={ts}")
    


def main():
    iface=get_if()
    
    print("sniffing on %s" % iface)

    sniff(iface = iface,prn = parse_int)

if __name__ == '__main__':
    main()
