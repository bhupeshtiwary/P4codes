#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP,Raw, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination> <message>')
        exit(1)
    dst_ip=sys.argv[1]
    count=int(sys.argv[2]) if len(sys.argv) > 2 else 1
    iface = get_if()
    src_mac=get_if_hwaddr(iface)
    
    pkt=(
          Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff')/
        IP(dst=dst_ip)/
        TCP(dport=1234,sport=1234)/
        Raw(load=b"HELLO_INT")
        )
    print(f"sending {count} pkts to {dst_ip} on {iface}" )
    pkt.show2()
    sendp(pkt,iface=iface,count=count,inter=0.5,verbose=False)
   


if __name__ == '__main__':
    main()
