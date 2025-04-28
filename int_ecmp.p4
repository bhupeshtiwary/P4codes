/* Updated P4_16 program with conditional INT parsing and unconditional deparser emit */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_INT = 0x9A;  // Custom IPv4 protocol number for INT header

// Header definitions
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

// INT telemetry header (6 bytes)
header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    int_t      inst;
}

struct metadata {
    bit<8> group_id;
    bit<1> hash;
    bit<1> do_int;
    bit<8> switch_id;
}

// Register storing this switch's ID
register<bit<8>>(1) switch_id_reg;

// Parser: Ethernet → IPv4 → optionally INT
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
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_INT: parse_int;
            default: accept;
        }
    }
    state parse_int {
        packet.extract(hdr.inst);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // Load static switch ID
    action load_switch_id() {
        switch_id_reg.read(meta.switch_id, 0);
    }
    
    // ECMP group select
    action set_group(bit<8> gid)    { meta.group_id = gid; }
    action compute_hash()           { meta.hash = (bit<1>)((hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr) & 1); }
    action set_port(bit<9> port)    { standard_metadata.egress_spec = port; }
    
    // Enable INT: set flag and overwrite protocol
    action enable_int() {
        meta.do_int = 1;
        hdr.ipv4.protocol = PROTO_INT;
    }
    
    // MAC rewrite for forwarding
    action rewrite_mac(macAddr_t dst, macAddr_t src) {
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
        key = { standard_metadata.egress_spec: exact; }
        actions = { rewrite_mac; }
        size = 16;
    }
    
    apply {
        load_switch_id();
        if (hdr.ipv4.isValid()) {
            ecmp_group_table.apply();
            compute_hash();
            ecmp_select_table.apply();
            mac_rewrite.apply();
            int_table.apply();
            
            if (meta.do_int == 1) {
                hdr.inst.setValid();
                hdr.inst.hop_count = hdr.inst.hop_count + 1;
                hdr.inst.switch_id = meta.switch_id;
                hdr.inst.ingress_timestamp = standard_metadata.ingress_global_timestamp;
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

// Deparser now emits INT header unconditionally (BMv2 supports emitting invalid headers as zeros)
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.inst);
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
