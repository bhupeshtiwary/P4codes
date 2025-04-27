#include <core.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

struct metadata {
    bit<1>   do_int;
    bit<8>   hop_count;
    bit<8>   switch_id;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    int_t      inst;
}

register<bit<8>>(1) switch_id_reg;

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
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x7D: parse_int;
            default: accept;
        }
    }
    state parse_int {
        packet.extract(hdr.inst);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action load_switch_id() {
        switch_id_reg.read(meta.switch_id, 0);
    }
    action mark_int_proto() {
        hdr.ipv4.protocol = 0x7D;
    }
    table int_table {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { mark_int_proto; _nop; }
        size = 1024;
    }
    apply {
        // pull existing INT header into metadata
        if (hdr.inst.isValid()) {
            meta.do_int    = 1;
            meta.hop_count = hdr.inst.hop_count;
        }
        // first-hop enable
        int_table.apply();

        if (meta.do_int == 1) {
            if (!hdr.inst.isValid()) {
                hdr.inst.setValid();
                meta.hop_count = 0;
            }
            meta.hop_count = meta.hop_count + 1;
            load_switch_id();
            hdr.inst.hop_count         = meta.hop_count;
            hdr.inst.switch_id         = meta.switch_id;
            hdr.inst.ingress_timestamp = standard_metadata.ingress_global_timestamp;
            mark_int_proto();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyDeparser(packet_out packet, in headers hdr) {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ipv4);
    if (hdr.inst.isValid()) {
        packet.emit(hdr.inst);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
