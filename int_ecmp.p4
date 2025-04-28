/* Integrated MAC rewrite into ECMP selector and removed separate mac_rewrite table */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_INT = 0x9A;

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

// INT header
header int_t {
    bit<8>  hop_count;
    bit<8>  switch_id;
    bit<48> ingress_timestamp;
}

// All headers
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    int_t      inst1;
    int_t      inst2;
    int_t      inst3;
    int_t      inst4;
}

// Metadata
struct metadata {
    bit<8>  group_id;
    bit<1>  hash;
    bit<1>  do_int;
    bit<8>  switch_id;
    bit<8>  hop_count;
}

// Parser: only extract Ethernet and IPv4
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    state start { transition parse_ethernet; }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

// Ingress: ECMP with integrated MAC rewrite
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    action set_group(bit<8> gid) { meta.group_id = gid; }
    action compute_hash() { meta.hash = (bit<1>)(hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr) & 1; }
    // Now includes MAC rewrite parameters
    action set_port_and_rewrite(bit<9> port, bit<48> dst, bit<48> src) {
        sm.egress_spec = port;
        hdr.ethernet.dstAddr = dst;
        hdr.ethernet.srcAddr = src;
    }
    action enable_int(bit<8> id) { meta.do_int = 1; meta.switch_id = id; }

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
        if (hdr.ipv4.isValid()) {
            ecmp_group_table.apply();
            compute_hash();
            ecmp_select_table.apply(); // sets port and rewrites MAC
            int_table.apply();

            if (meta.do_int == 1) {
                bit<8> idx = meta.hop_count;
                // mark next INT slot valid
                if (idx == 0) hdr.inst1.setValid();
                else if (idx == 1) hdr.inst2.setValid();
                else if (idx == 2) hdr.inst3.setValid();
                else if (idx == 3) hdr.inst4.setValid();

                // adjust IPv4 header for new INT (6 bytes)
                if (idx == 0) hdr.ipv4.protocol = PROTO_INT;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 6;
                hdr.ipv4.ihl = hdr.ipv4.ihl + 2;

                // fill telemetry
                if (idx == 0) {
                    hdr.inst1.hop_count = 1;
                    hdr.inst1.switch_id = meta.switch_id;
                    hdr.inst1.ingress_timestamp = sm.ingress_global_timestamp;
                } else if (idx == 1) {
                    hdr.inst2.hop_count = 2;
                    hdr.inst2.switch_id = meta.switch_id;
                    hdr.inst2.ingress_timestamp = sm.ingress_global_timestamp;
                } else if (idx == 2) {
                    hdr.inst3.hop_count = 3;
                    hdr.inst3.switch_id = meta.switch_id;
                    hdr.inst3.ingress_timestamp = sm.ingress_global_timestamp;
                } else if (idx == 3) {
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
        update_checksum(hdr.ipv4.isValid(),
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
        packet.emit(hdr.inst1);
        packet.emit(hdr.inst2);
        packet.emit(hdr.inst3);
        packet.emit(hdr.inst4);
    }
}

V1Switch(
    MyParser(), MyVerifyChecksum(), MyIngress(),
    MyEgress(), MyComputeChecksum(), MyDeparser()
) main;

/* NEXT: Update your s*_runtime.json files so that each ecmp_select_table entry uses the new action parameters:
   e.g. {
     "table": "MyIngress.ecmp_select_table",
     "match": { "meta.group_id": 1, "meta.hash": 0 },
     "action_name": "MyIngress.set_port_and_rewrite",
     "action_params": {
       "port": 2,
       "dst": "aa:bb:cc:00:02:01",
       "src": "aa:bb:cc:00:01:02"
     }
   }
*/
