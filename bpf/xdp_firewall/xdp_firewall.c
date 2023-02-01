// +build ignore
#include "bpf_endian.h"
#include "common.h"

const __u8 IPPROTO_TCP = 6;		/* Transmission Control Protocol	*/

struct pair {
    __u32 ip;
    __u16 port;
    __u16 padding;
};
/* Define an LRU hash map for storing packet count by source IPv4 address */
struct bpf_map_def SEC("maps") whitelist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct pair),
    .value_size = sizeof(__u32),
    .max_entries = 100,
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 ns : 1,
        reserved : 3,
        doff : 4,
        fin : 1,
        syn : 1,
        rst : 1,
        psh : 1,
        ack : 1,
        urg : 1,
        ece : 1,
        cwr : 1;
};



SEC("xdp")
int tcp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct pair key;
//    struct pair key2;

    u32 *value;

    if (data + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    data += sizeof(*eth);

    struct iphdr *iph = data;
     if (data + sizeof(*iph) > data_end) {
       return XDP_ABORTED;
     }

    if (iph->version != 4) {
        return XDP_DROP;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

     data += iph->ihl * 4;
     struct tcphdr *tcph = data;
     if (data + sizeof(*tcph) > data_end) {
       return XDP_ABORTED;
     }

    key.ip = iph->saddr;
    key.port = tcph->source;
    key.padding = 0;

    if ((tcph->syn)) {
       u32 v1 = 11;
       bpf_map_update_elem(&whitelist, &key, &v1,BPF_ANY);
       return XDP_DROP;
    }
    return XDP_PASS;

    if (tcph->dest == 5051) {
            u32 v1 = 10;
            bpf_map_update_elem(&whitelist, &key, &v1,BPF_ANY);
       return XDP_PASS;
    }

//    key2.ip = iph->daddr;
//    key2.port = tcph->dest;
//    key2.padding = 0;

    value = bpf_map_lookup_elem(&whitelist, &key);
    if (value) {
        return XDP_PASS;
    }


//
//    u32 v2 = 20;
//    bpf_map_update_elem(&whitelist, &key2, &v2,BPF_ANY);

    return XDP_DROP;
}
char _license[] SEC("license") = "GPL";
