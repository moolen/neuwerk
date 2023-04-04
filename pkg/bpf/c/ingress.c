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

  // TODO: implement CONNTRACK
  // either use bpf_skb_ct_lookup (Kernel 5.19+)
  // https://elixir.bootlin.com/linux/v5.19.17/source/net/netfilter/nf_conntrack_bpf.c
  // or copy cilium CT
  // https://github.com/cilium/cilium/blob/master/bpf/lib/conntrack.h

  // TODO: for now we only support TCP
  if (ip->protocol != 6) {
    return TC_ACT_OK;
  }

  // check if source ip is in a given network cidr
  // if it is: apply configured policies
  for (__u8 i = 0; i < MAP_MAX_NETWORKS; i++) {
    bpf_printk("checking network [%d]", i);
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

    // TODO: pass net device idx from map
    long redir = bpf_redirect_neigh(3, NULL, 0, 0);
    bpf_printk("redirect=%d", redir);
    return redir;
  }

  // TODO: implement default
  return TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
