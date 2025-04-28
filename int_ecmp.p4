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
// Use a header stack for INT slots
header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    header_stack<int_t, 4> inst; // stack of up to 4 INT headers
}

struct metadata {
    bit<8> group_id;
    bit<1> hash;
    bit<1> do_int;
    bit<8> switch_id;
    bit<8> next_idx;
}

// Parser: Ethernet -> IPv4 -> INT stack if PROTO_INT
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
            PROTO_INT: parse_int_stack;
            default:    accept;
        }
    }
    state parse_int_stack {
        // extract up to 4 INT headers; header_stack sets valid=true
        packet.extract(hdr.inst);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action set_group(bit<8> gid) {
        meta.group_id = gid;
    }
    action compute_hash() {
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
        meta.do_int       = 1;
        meta.switch_id    = id;
        hdr.ipv4.protocol = PROTO_INT;
        hdr.ipv4.ihl      = hdr.ipv4.ihl + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    }

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
        if (!hdr.ipv4.isValid()) return;
        // Determine number of existing INT headers
        if (hdr.ipv4.protocol == PROTO_INT) {
            // header_stack provides API to count valid headers? Instead, scan manually
            meta.next_idx = 0;
            for (var i = 0; i < 4; i = i + 1) {
                if (hdr.inst[i].isValid()) meta.next_idx = meta.next_idx + 1;
            }
        } else {
            meta.next_idx = 0;
        }
        // ECMP + MAC
        ecmp_group_table.apply();
        compute_hash();
        ecmp_select_table.apply();
        // Enable INT
        int_table.apply();
        // Stamp into stack slot
        if (meta.do_int == 1 && meta.next_idx < 4) {
            hdr.inst[meta.next_idx].setValid();
            hdr.inst[meta.next_idx].hop_count = (bit<8>)(meta.next_idx + 1);
            hdr.inst[meta.next_idx].switch_id = meta.switch_id;
            hdr.inst[meta.next_idx].ingress_timestamp = standard_metadata.ingress_global_timestamp;
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { apply { } }

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
        // header_stack.emit only valid headers in order
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
