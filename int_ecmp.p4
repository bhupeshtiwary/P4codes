// Updated int_ecmp.p4 — supports up to 4 INT hops and merges MAC-rewrite into ECMP select

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_INT  = 0x9A;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Standard headers
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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

// INT telemetry header (6 bytes per hop)
header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

// Header stack of up to 4 INT entries
header_stack<int_t, 4> insts_t;

// All packet headers
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    insts_t    insts;
}

// Per-packet metadata
struct metadata {
    bit<8>  group_id;
    bit<1>  hash;
    bit<1>  do_int;
    bit<8>  switch_id;
    bit<8>  next_idx;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
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
            PROTO_INT: parse_int_loop;
            default:   accept;
        }
    }
    // Repeatedly extract INT headers if present
    state parse_int_loop {
        packet.extract(hdr.insts.next);
        transition select(hdr.ipv4.protocol) {
            PROTO_INT: parse_int_loop;
            default:   accept;
        }
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Actions
    action set_group(bit<8> gid) {
        meta.group_id = gid;
    }
    action compute_hash() {
        // simple XOR-based hash → 1 bit
        meta.hash = (bit<1>)((hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr) & 1);
    }
    action set_port_and_rewrite(bit<9> port,
                                macAddr_t dst,
                                macAddr_t src) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr          = dst;
        hdr.ethernet.srcAddr          = src;
    }
    action enable_int(bit<8> id) {
        meta.do_int     = 1;
        meta.switch_id  = id;
        hdr.ipv4.protocol = PROTO_INT;
    }

    // Tables
    table ecmp_group_table {
        key     = { hdr.ipv4.dstAddr: lpm; }
        actions = { set_group; }
        size    = 1024;
    }
    table ecmp_select_table {
        key     = { meta.group_id: exact; meta.hash: exact; }
        actions = { set_port_and_rewrite; }
        size    = 1024;
    }
    table int_table {
        key     = { hdr.ipv4.dstAddr: lpm; }
        actions = { enable_int; }
        size    = 1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // initialize per-packet INT index
            meta.next_idx = 0;
            // ECMP decision + MAC rewrite in one shot
            ecmp_group_table.apply();
            compute_hash();
            ecmp_select_table.apply();
            // determine if we should insert INT header
            int_table.apply();

            if (meta.do_int == 1 && meta.next_idx < 4) {
                // stamp the next INT slot
                hdr.insts[meta.next_idx].setValid();
                hdr.insts[meta.next_idx].hop_count        = meta.next_idx + 1;
                hdr.insts[meta.next_idx].switch_id        = meta.switch_id;
                hdr.insts[meta.next_idx].ingress_timestamp = standard_metadata.ingress_global_timestamp;
                meta.next_idx = meta.next_idx + 1;
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

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
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        // Emit up to all 4 INT headers; only valid ones serialize
        packet.emit(hdr.insts);
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
