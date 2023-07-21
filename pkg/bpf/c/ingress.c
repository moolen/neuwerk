#include "headers/common.h"

#define ETH_HLEN 14
#define ETH_ALEN 6
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define L4_PORT_OFF                                                            \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_CSUM_OFF                                                           \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define TCP_CSUM_OFF                                                           \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

#define MAP_MAX_NETWORKS 255
#define MAP_MAX_POLICIES 65535
#define MAP_MAX_PKT_TRACK 16777216


// store network device index to which we redirect the packets
static volatile const __u32 net_redir_device = 0;
static volatile const __u32 ingress_addr = 0;
static volatile const __u16 dns_listen_port = 0;

struct policy_key {
  __u32 upstream_addr;
  __u16 upstream_port;
  __u16 __unused;
};

const struct policy_key *unused0 __attribute__((unused));

struct network_policy {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAP_MAX_POLICIES);
  __type(key, sizeof(struct policy_key));
  __type(value, __u32);
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAP_MAX_PKT_TRACK);
  __type(key, __u32); // addr
  __type(value, __u64); // clock_gettime(CLOCK_TAI)
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_track SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, MAP_MAX_NETWORKS);
  __type(key, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct network_policy);
} network_policies SEC(".maps");

struct network_cidr {
  __u32 addr;
  __u32 mask;
};

const struct network_cidr *unused1 __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAP_MAX_NETWORKS);
  __type(key, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __type(value, sizeof(struct network_cidr));
} network_cidrs SEC(".maps");

SEC("classifier/cls")
int ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *ip = (data + sizeof(struct ethhdr));
  struct tcphdr *tcp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct tcphdr) >
      data_end) {
    return TC_ACT_OK;
  }

  bpf_printk("pkt arrived: proto=%lu daddr=%lu dport=%lu", ip->protocol, ip->daddr, tcp->dest);
  // TODO: implement CONNTRACK
  // either use bpf_skb_ct_lookup (Kernel 5.19+)
  // https://elixir.bootlin.com/linux/v5.19.17/source/net/netfilter/nf_conntrack_bpf.c
  // or copy cilium CT
  // https://github.com/cilium/cilium/blob/master/bpf/lib/conntrack.h
  if (ip->protocol != 6) {
    bpf_printk("skip non-tcp");
    return TC_ACT_OK;
  }

  if (ip->daddr == ingress_addr && tcp->dest == dns_listen_port) {
    bpf_printk("pass tcp DNS traffic");
    return TC_ACT_OK;
  }

  // check if source ip is in a given network cidr
  // if it is: apply configured policies
  for (__u8 i = 0; i < MAP_MAX_NETWORKS; i++) {
    bpf_printk("checking network [%d]", i);;
    __u32 ii = i;
    struct network_cidr *cidr = bpf_map_lookup_elem(&network_cidrs, &ii);
    if (cidr == NULL) {
      bpf_printk("no cidr found");
      break;
    }

    bpf_printk("cidr=%lu mask=%lu saddr=%lu", cidr->addr, cidr->mask, ip->saddr);
    // if no match: try next network
    if ((cidr->addr & cidr->mask) != (ip->saddr & cidr->mask)) {
      bpf_printk("cidr: no match");
      continue;
    }

    // get policies for given network
    __u32 *policies = bpf_map_lookup_elem(&network_policies, &ii);
    if (policies == NULL) {
      bpf_printk("no cidr found");
      break;
    }

    // lookup destination tuple.
    // if there is a match: apply verdict, otherwise try next and apply
    // default policy.
    struct policy_key pk = {0};
    pk.upstream_addr = ip->daddr;
    pk.upstream_port = tcp->dest;
    __u8 *verdict = bpf_map_lookup_elem(policies, &pk);
    if (verdict == NULL) {
      bpf_printk("verdict is NULL daddr=%lu sport=%d dport=%d", ip->daddr, tcp->source, tcp->dest);
      break;
    }
    bpf_printk("verdict=%d daddr=%lu", *verdict, ip->daddr);

    // track last seen packet
    __u64 now = bpf_ktime_get_tai_ns();
    long ok = bpf_map_update_elem(&pkt_track, &ip->daddr, &now, 0);
    if (ok < 0) {
      bpf_printk("failed to update ktime %llu", now);
    }


    long redir = bpf_redirect_neigh(net_redir_device, NULL, 0, 0);
    bpf_printk("redirect=%d", redir);
    return redir;
  }

  bpf_printk("dropping packet");
  return TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
