#!/usr/bin/env python3
from scapy.all import sniff, IP

# Must match your P4’s PROTO_INT
PROTO_INT = 0x9A

def parse_int(pkt):
    # 1) Only IPv4, non-fragment INT packets
    if not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    # drop fragments (we need the full payload)
    if ip.flags.MF or ip.frag != 0:
        return
    if ip.proto != PROTO_INT:
        return

    data = bytes(ip.payload)
    off = 0

    # 2) Parse exactly 4 slots, stop on hop_count==0
    for _ in range(4):
        if off + 8 > len(data):
            break
        hop = data[off]
        if hop == 0:
            break
        sw = data[off + 1]
        ts = int.from_bytes(data[off+2:off+8], 'big')
        print(f"INT -> hop_count={hop}, switch_id={sw}, ts={ts}")
        off += 8

if __name__ == "__main__":
    # BPF filter so kernel only gives us INT‐protocol IPv4
    bpf = "ip proto 154"
    # sniff forever, calling parse_int() per packet
    sniff(filter=bpf, prn=parse_int, store=0)
