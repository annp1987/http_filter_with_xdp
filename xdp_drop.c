#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define IP_TCP 	6
#define ETH_HLEN 14

BPF_TABLE("percpu_array", uint32_t, long, action_map, 256);

static inline int parse_ipv4(struct xdp_md *ctx, u64 nh_off) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct iphdr *iph = data + nh_off;

    if (iph + 1 > data_end)
        return XDP_DROP;

    //filter tcp packets (ip next protocol = 0x06)
    if (iph->protocol == IPPROTO_TCP)
    {
        u32 tcp_header_length = 0;
        u32 ip_header_length = 0;
        u32 payload_offset = 0;
        u32 payload_length = 0;
        u32 ip_total_length = iph->tot_len;


        // calculate ip header length
        // e.g iph->ihl = 5; Ip header length= 5x4 =20
        ip_header_length = iph->ihl << 2;

        // check ip header length
        if (ip_header_length < sizeof(*iph)){
            return XDP_DROP;
        }

        struct tcphdr *tcph = data + nh_off + sizeof(*iph);
        // calculate tcp header length
        // e.g tcph->doff = 5; tcp header length = 5x4 =20
        tcp_header_length = tcph->doff << 2;
        payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
        payload_length = ip_total_length - ip_header_length - tcp_header_length;

        //http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
        //minimum length of http request is always geater than 7 bytes
        //avoid invalid access memory
        //include empty payload
        if (payload_length < 7)
            return XDP_DROP;
    
        //load first 7 byte of payload into p (payload_array)
        //direct access to skb not allowed
        unsigned long p[7];
        int i = 0;
        int j = 0;
        const int last_index = payload_offset + 7;
        //return XDP_PASS;
        for (i = payload_offset ; i < last_index ; i++) {
            p[j] = load_byte(data, i);
            j++;
        }

        //bpf_trace_printk("xdp %d", p[0]);
        //find a match with an HTTP message
        //HTTP
        if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
            return XDP_PASS;
        }
        //GET
        if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
            return XDP_PASS;
        }

        //POST
        if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
            return XDP_PASS;
        }
        //PUT
        if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
            return XDP_PASS;
        }
        //DELETE
        if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
            return XDP_PASS;
        }
        //HEAD
        if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
            return XDP_PASS;
        }

    }
    else
        return XDP_PASS;

}

int xdp_prog1(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    int rc = XDP_PASS;
    u16 h_proto;
    u64 nh_off = 0;
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return rc;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    // filter ip packets (ethernet type = 0x0800)
    if (h_proto == htons(ETH_P_IP))
        return parse_ipv4(ctx, nh_off)
    else
        return rc;

}
