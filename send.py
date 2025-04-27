#!/usr/bin/env python3
import sys
from scapy.all import Ether, IP, TCP, Raw, get_if_hwaddr, get_if_list, sendp

def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Usage: send.py <destination> <count>")
        sys.exit(1)
    dst_ip = sys.argv[1]
    count = int(sys.argv[2])
    iface = get_if()
    src_mac = get_if_hwaddr(iface)

    pkt = (
        Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') /
        IP(dst=dst_ip) /
        TCP(dport=1234, sport=1234) /
        Raw(load=b"HELLO_INT")
    )
    print(f"Sending {count} pkts to {dst_ip} on {iface}")
    pkt.show2()
    sendp(pkt, iface=iface, count=count, inter=0.5, verbose=False)

if __name__ == '__main__':
    main()
