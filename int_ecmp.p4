#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_INT  = 0x9A;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
// Standard IPv4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// INT telemetry header (8 bytes per hop)
header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

// Packet headers including up to 4 INT slots
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    int_t      inst1;
    int_t      inst2;
    int_t      inst3;
    int_t      inst4;
}

// ECMP + INT metadata
struct metadata {
    bit<8> group_id;
    bit<1> hash;
    bit<1> do_int;
    bit<8> switch_id;
    bit<8> next_idx;
    bit<8> old_hop1; bit<8> old_hop2; bit<8> old_hop3; bit<8> old_hop4;
    bit<8> old_sw1;   bit<8> old_sw2;   bit<8> old_sw3;   bit<8> old_sw4;
    bit<48> old_ts1;  bit<48> old_ts2;  bit<48> old_ts3;  bit<48> old_ts4;
}

// Parser: Ethernet -> IPv4 -> conditional INT slots
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start { transition parse_ethernet; }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:    accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_INT: parse_inst1;
            default:    accept;
        }
    }
    state parse_inst1 {
        packet.extract(hdr.inst1);
        transition select(hdr.inst1.hop_count) {
            0: accept;
            default: parse_inst2;
        }
    }
    state parse_inst2 {
        packet.extract(hdr.inst2);
        transition select(hdr.inst2.hop_count) {
            0: accept;
            default: parse_inst3;
        }
    }
    state parse_inst3 {
        packet.extract(hdr.inst3);
        transition select(hdr.inst3.hop_count) {
            0: accept;
            default: parse_inst4;
        }
    }
    state parse_inst4 {
        packet.extract(hdr.inst4);
        transition accept;
    }
}

// No-op verify checksum
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// Ingress: ECMP, INT enable, preserve/clear/restore/stamp workflow
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action set_group(bit<8> gid) {
        meta.group_id = gid;
    }
    action compute_hash() {
        meta.hash = (bit<1>)((hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr) & 1);
    }
    action set_port_and_rewrite(bit<9> port, macAddr_t dst, macAddr_t src) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dst;
        hdr.ethernet.srcAddr = src;
    }
    action enable_int(bit<8> id) {
        meta.do_int = 1;
        meta.switch_id = id;
        hdr.ipv4.protocol = PROTO_INT;
    }

    table ecmp_group_table {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { set_group; }
        size = 1024;
    }
    table ecmp_select_table {
        key = { meta.group_id: exact; meta.hash: exact; }
        actions = { set_port_and_rewrite; }
        size = 1024;
    }
    table int_table {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { enable_int; }
        size = 1024;
    }

    apply {
        if (!hdr.ipv4.isValid()) return;

        // If first-hop (not yet marked INT), zero everything
        if (hdr.ipv4.protocol != PROTO_INT) {
            hdr.inst1 = 0; hdr.inst2 = 0; hdr.inst3 = 0; hdr.inst4 = 0;
            meta.old_hop1 = 0; meta.old_hop2 = 0; meta.old_hop3 = 0; meta.old_hop4 = 0;
            meta.do_int = 0;
            meta.next_idx = 0;
        }

        // 1) Preserve any existing INT slots
        meta.old_hop1 = hdr.inst1.hop_count;  meta.old_sw1 = hdr.inst1.switch_id;  meta.old_ts1 = hdr.inst1.ingress_timestamp;
        meta.old_hop2 = hdr.inst2.hop_count;  meta.old_sw2 = hdr.inst2.switch_id;  meta.old_ts2 = hdr.inst2.ingress_timestamp;
        meta.old_hop3 = hdr.inst3.hop_count;  meta.old_sw3 = hdr.inst3.switch_id;  meta.old_ts3 = hdr.inst3.ingress_timestamp;
        meta.old_hop4 = hdr.inst4.hop_count;  meta.old_sw4 = hdr.inst4.switch_id;  meta.old_ts4 = hdr.inst4.ingress_timestamp;

        // 2) Clear all INT headers so we can rebuild from scratch
        hdr.inst1 = 0; hdr.inst2 = 0; hdr.inst3 = 0; hdr.inst4 = 0;
        meta.next_idx = 0;

        // 3) Restore preserved slots & set next_idx
        if (meta.old_hop1 != 0) {
            hdr.inst1.setValid();
            hdr.inst1.hop_count       = meta.old_hop1;
            hdr.inst1.switch_id       = meta.old_sw1;
            hdr.inst1.ingress_timestamp = meta.old_ts1;
            meta.next_idx = 1;
        }
        if (meta.old_hop2 != 0) {
            hdr.inst2.setValid();
            hdr.inst2.hop_count       = meta.old_hop2;
            hdr.inst2.switch_id       = meta.old_sw2;
            hdr.inst2.ingress_timestamp = meta.old_ts2;
            meta.next_idx = 2;
        }
        if (meta.old_hop3 != 0) {
            hdr.inst3.setValid();
            hdr.inst3.hop_count       = meta.old_hop3;
            hdr.inst3.switch_id       = meta.old_sw3;
            hdr.inst3.ingress_timestamp = meta.old_ts3;
            meta.next_idx = 3;
        }
        if (meta.old_hop4 != 0) {
            hdr.inst4.setValid();
            hdr.inst4.hop_count       = meta.old_hop4;
            hdr.inst4.switch_id       = meta.old_sw4;
            hdr.inst4.ingress_timestamp = meta.old_ts4;
            meta.next_idx = 4;
        }

        // 4) ECMP forward + MAC rewrite
        ecmp_group_table.apply();
        compute_hash();
        ecmp_select_table.apply();

        // 5) Enable INT on this hop
        int_table.apply();

        // 6) Stamp the new INT slot, if room
        if (meta.do_int == 1 && meta.next_idx < 4) {
            bit<8> hop = meta.next_idx + 1;
            if (meta.next_idx == 0) {
                hdr.inst1.setValid();
                hdr.inst1.hop_count       = hop;
                hdr.inst1.switch_id       = meta.switch_id;
                hdr.inst1.ingress_timestamp = standard_metadata.ingress_global_timestamp;
            } else if (meta.next_idx == 1) {
                hdr.inst2.setValid();
                hdr.inst2.hop_count       = hop;
                hdr.inst2.switch_id       = meta.switch_id;
                hdr.inst2.ingress_timestamp = standard_metadata.ingress_global_timestamp;
            } else if (meta.next_idx == 2) {
                hdr.inst3.setValid();
                hdr.inst3.hop_count       = hop;
                hdr.inst3.switch_id       = meta.switch_id;
                hdr.inst3.ingress_timestamp = standard_metadata.ingress_global_timestamp;
            } else {
                hdr.inst4.setValid();
                hdr.inst4.hop_count       = hop;
                hdr.inst4.switch_id       = meta.switch_id;
                hdr.inst4.ingress_timestamp = standard_metadata.ingress_global_timestamp;
            }
        }
    }
}

// No-op egress
control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// Recompute IPv4 checksum
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen, hdr.ipv4.identification,
                hdr.ipv4.flags,   hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,     hdr.ipv4.protocol,
                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

// Deparser: emit all slots in order
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.inst1);
        packet.emit(hdr.inst2);
        packet.emit(hdr.inst3);
        packet.emit(hdr.inst4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
