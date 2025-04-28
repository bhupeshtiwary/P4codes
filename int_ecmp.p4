/* Updated P4_16 program for multi-hop INT stamping */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_TCP = 0x06;
const bit<8>  PROTO_INT = 0x9A;

// Ethernet header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4 header
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
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

// INT header instance
header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

// All headers: four INT slots
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    int_t      inst1;
    int_t      inst2;
    int_t      inst3;
    int_t      inst4;
}

// Metadata for INT logic
struct metadata {
    bit<8>  group_id;
    bit<1>  hash;
    bit<1>  do_int;
    bit<8>  switch_id;
    bit<8>  hop_count;
}

// Parser: extract ethernet, IPv4, then up to 4 INT headers when protocol==PROTO_INT
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t sm) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_INT: parse_int1;
            default: accept;
        }
    }
    state parse_int1 {
        packet.extract(hdr.inst1);
        transition parse_int2;
    }
    state parse_int2 {
        packet.extract(hdr.inst2);
        transition parse_int3;
    }
    state parse_int3 {
        packet.extract(hdr.inst3);
        transition parse_int4;
    }
    state parse_int4 {
        packet.extract(hdr.inst4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    action set_group(bit<8> gid) { meta.group_id = gid; }
    action compute_hash() { meta.hash = (bit<1>)(hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr) & 1; }
    action set_port(bit<9> port) { sm.egress_spec = port; }
    action enable_int(bit<8> id) { meta.do_int = 1; meta.switch_id = id; }
    action rewrite_mac(bit<48> dst, bit<48> src) {
        hdr.ethernet.dstAddr = dst;
        hdr.ethernet.srcAddr = src;
    }

    table ecmp_group_table {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { set_group; }
        size = 1024;
    }
    table ecmp_select_table {
        key = { meta.group_id: exact; meta.hash: exact; }
        actions = { set_port; }
        size = 1024;
    }
    table int_table {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { enable_int; }
        size = 1024;
    }
    table mac_rewrite {
        key = { sm.egress_spec: exact; }
        actions = { rewrite_mac; }
        size = 16;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // ECMP & MAC
            ecmp_group_table.apply();
            compute_hash();
            ecmp_select_table.apply();
            mac_rewrite.apply();
            int_table.apply();

            // On first INT hop, switch protocol and adjust lengths
            if (meta.do_int == 1) {
                // Stamp new INT header in next available slot
                bit<8> idx = meta.hop_count;
                if (idx == 0) hdr.inst1.setValid();
                else if (idx == 1) hdr.inst2.setValid();
                else if (idx == 2) hdr.inst3.setValid();
                else if (idx == 3) hdr.inst4.setValid();

                // Fill fields
                if (idx == 0) {
                    hdr.ipv4.protocol = PROTO_INT;
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 6;
                    hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
                    hdr.inst1.hop_count = 1;
                    hdr.inst1.switch_id = meta.switch_id;
                    hdr.inst1.ingress_timestamp = sm.ingress_global_timestamp;
                } else if (idx == 1) {
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 6;
                    hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
                    hdr.inst2.hop_count = 2;
                    hdr.inst2.switch_id = meta.switch_id;
                    hdr.inst2.ingress_timestamp = sm.ingress_global_timestamp;
                } else if (idx == 2) {
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 6;
                    hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
                    hdr.inst3.hop_count = 3;
                    hdr.inst3.switch_id = meta.switch_id;
                    hdr.inst3.ingress_timestamp = sm.ingress_global_timestamp;
                } else if (idx == 3) {
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 6;
                    hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
                    hdr.inst4.hop_count = 4;
                    hdr.inst4.switch_id = meta.switch_id;
                    hdr.inst4.ingress_timestamp = sm.ingress_global_timestamp;
                }
                meta.hop_count = meta.hop_count + 1;
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) { apply { } }

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset,
              hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        if (hdr.inst1.isValid()) packet.emit(hdr.inst1);
        if (hdr.inst2.isValid()) packet.emit(hdr.inst2);
        if (hdr.inst3.isValid()) packet.emit(hdr.inst3);
        if (hdr.inst4.isValid()) packet.emit(hdr.inst4);
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
