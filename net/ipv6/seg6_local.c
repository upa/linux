/*
 *  SR-IPv6 implementation
 *
 *  Authors:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *  eBPF support: Mathieu Xhonneux <m.xhonneux@gmail.com>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *        modify it under the terms of the GNU General Public License
 *        as published by the Free Software Foundation; either version
 *        2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/lwtunnel.h>
#include <net/netevent.h>
#include <net/netns/generic.h>
#include <net/ip6_fib.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/seg6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/icmpv6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/dst_cache.h>
#ifdef CONFIG_IPV6_SEG6_HMAC
#include <net/seg6_hmac.h>
#endif
#include <net/seg6_local.h>
#include <linux/etherdevice.h>
#include <linux/bpf.h>

struct seg6_local_lwt;

struct seg6_action_desc {
	int action;
	unsigned long attrs;
	int (*input)(struct sk_buff *skb, struct seg6_local_lwt *slwt);
	int static_headroom;
};

struct bpf_lwt_prog {
	struct bpf_prog *prog;
	char *name;
};

struct seg6_local_lwt {
	struct lwtunnel_state *lwt;	/* parent */
	int action;
	struct ipv6_sr_hdr *srh;
	int table;
	struct in_addr nh4;
	struct in6_addr nh6;
	struct in6_addr argmask;
	int iif;
	int oif;
	u8 mac[ETH_ALEN];
	u8 endflavor;
	struct bpf_lwt_prog bpf;

	int headroom;
	struct seg6_action_desc *desc;
};


static unsigned int  seg6_net_id;

#define SEG6_HASH_BITS 8
#define SEG6_HASH_SIZE (1 << SEG6_HASH_BITS)

struct seg6_net {
	struct net *net;	/* parent */
	struct net_device *lo;	/* loopback on this netns */
	/* XXX: netdev for lo in this netns: ip_route_input_slow()
	 * uses skb->dev for flowi4.flowi4_iif. This causes uninteded
	 * fib rule match in End.Dx functions.
	 */

	struct hlist_head flow4_table[SEG6_HASH_SIZE];
	struct timer_list flow4_timer;	/* aging flow4 table */
};

struct net_device *seg6_net_get_lo(struct seg6_net *snet)
{
	/* only at first time, get lo */
	if (unlikely(!snet->lo)) {
		preempt_disable();
		snet->lo = dev_get_by_name(snet->net, "lo");
		if (unlikely(!snet->lo)) {
			net_err_ratelimited("%s: failed to get lo\n",
					    __func__);
		}
		preempt_enable();
	}

	return snet->lo;
}

struct seg6_flow4 {
	struct hlist_node hlist; /* seg6_net->flow4_table[] */
	struct rcu_head rcu;
	unsigned long updated;

	int ifindex;
	__u8 protocol;
	__be32 saddr, daddr;
	u16 sport, dport;

	/* stored header information */
	struct ipv6hdr ip6h;
#define SEG6_FLOW4_MAX_NSEGS 16
	struct ipv6_sr_hdr srh;
	struct in6_addr segments[SEG6_FLOW4_MAX_NSEGS];
	/* XXX: should consider alignment */
};
#define SEG6_FLOW4_LIFETIME		(10 * HZ)
#define SEG6_FLOW4_AGING_INTERVAL	(1 * HZ)



static void seg6_flow4_dump(struct seg6_flow4 *f)
{
	pr_debug("%s\n", __func__);
	if (!f) {
		pr_debug("%s: f is null!\n", __func__);
		return;
	}

	pr_debug("    ifindex %d\n", f->ifindex);
	pr_debug("    saddr   %pI4\n", &f->saddr);
	pr_debug("    daddr   %pI4\n", &f->daddr);
	pr_debug("    proto   %u\n", f->protocol);;
	pr_debug("    sport   %u\n", ntohs(f->sport));
	pr_debug("    dport   %u\n", ntohs(f->dport));
	pr_debug("    ip6 saddr %pI6\n", &f->ip6h.saddr);
	pr_debug("    ip6 daddr %pI6\n", &f->ip6h.daddr);
	pr_debug("    segmengs[0] %pI6\n", &f->srh.segments[0]);
}

#define seg6_flow4_dump_msg(f, fmt, ...)			\
	do {							\
		pr_debug("%s: " fmt, __func__, ##__VA_ARGS__);	\
		seg6_flow4_dump((f));				\
	} while(0)


static inline unsigned int seg6_flow4_hash(struct seg6_flow4 *f)
{
	return hash_64(f->ifindex + f->protocol + f->saddr + f->daddr +
		       f->sport + ((__be32)(f->dport) << 16), SEG6_HASH_BITS);
}

static inline struct hlist_head *seg6_flow4_head(struct seg6_net *snet,
					  struct seg6_flow4 *f)
{
	return &snet->flow4_table[seg6_flow4_hash(f)];
}

static inline void seg6_flow4_update(struct seg6_flow4 *f,
				     struct ipv6hdr *ip6h,
				     struct ipv6_sr_hdr *srh)
{
	if (ip6h)
		memcpy(&f->ip6h, ip6h, sizeof(struct ipv6hdr));
	if (srh)
		memcpy(&f->srh, srh, (srh->hdrlen + 1) << 3);
	f->updated = jiffies;
}

static struct seg6_flow4 *seg6_flow4_alloc(void)
{
	struct seg6_flow4 *f;

	f = kmalloc(sizeof(struct seg6_flow4), GFP_ATOMIC);
	if (!f) {
		net_err_ratelimited("%s: failed to malloc" , __func__);
		return NULL;
	}
	memset(f, 0, sizeof(struct seg6_flow4));

	f->updated = jiffies;

	return f;
}

static int seg6_flow4_make(struct seg6_flow4 *f, struct sk_buff *skb,
			   int iif)
{
	/* fill f from skb */
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *udp;

	iph = ip_hdr(skb);
	if (iph->version != 4) {
		pr_err("%s: ip version is not 4, %u\n",
		       __func__, iph->version);
		return -1;
	}

	f->ifindex = iif;
	f->protocol = iph->protocol;
	f->saddr = iph->saddr;
	f->daddr = iph->daddr;
	f->sport = 0;
	f->dport = 0;

	switch(iph->protocol) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(((char *)iph) + (iph->ihl << 2));
		f->sport = tcp->source;
		f->dport = tcp->dest;
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)(((char *)iph) + (iph->ihl << 2));
		f->sport = udp->source;
		f->dport = udp->dest;
		break;
	}

	return 0;
}

static struct seg6_flow4 *seg6_flow4_find(struct seg6_net *snet,
					  struct seg6_flow4 *f)
{
	struct hlist_head *head = seg6_flow4_head(snet, f);
	struct seg6_flow4 *tmp;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp, head, hlist) {
		if (tmp->ifindex == f->ifindex &&
		    tmp->protocol == f->protocol &&
		    tmp->saddr == f->saddr && tmp->daddr == f->daddr &&
		    tmp->sport == f->sport && tmp->dport == f->dport) {
			rcu_read_unlock();
			return tmp;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static void seg6_flow4_add(struct seg6_net *snet, struct seg6_flow4 *f)
{
	hlist_add_head_rcu(&f->hlist, seg6_flow4_head(snet, f));
}

static void seg6_flow4_free(struct rcu_head *head)
{
	struct seg6_flow4 *f = container_of(head, struct seg6_flow4, rcu);
	kfree(f);
}

static void seg6_flow4_del(struct seg6_flow4 *f)
{
	hlist_del_rcu(&f->hlist);
	call_rcu(&f->rcu, seg6_flow4_free);
}


static void seg6_flow4_cleanup(struct timer_list *t)
{
	struct seg6_net *snet = from_timer(snet, t, flow4_timer);
	struct seg6_flow4 *f;
	struct hlist_node *p, *n;
	unsigned long timeout;
	unsigned long next_timer = jiffies + SEG6_FLOW4_AGING_INTERVAL;
	int h;

	for (h = 0; h < SEG6_HASH_SIZE; h++) {
		hlist_for_each_safe(p, n, &snet->flow4_table[h]) {
			f = container_of(p, struct seg6_flow4, hlist);
			timeout = f->updated + SEG6_FLOW4_LIFETIME;

			if (time_before_eq(timeout, jiffies)) {
				seg6_flow4_dump_msg(f, "flow4 timeout\n");
				seg6_flow4_del(f);
			}
		}
	}

	mod_timer(&snet->flow4_timer, next_timer);
}

static void seg6_flow4_destroy(struct seg6_net *snet)
{
	struct hlist_node *p, *n;
	struct seg6_flow4 *f;
	int h;

	for (h = 0; h < SEG6_HASH_SIZE; h++) {
		hlist_for_each_safe(p, n, &snet->flow4_table[h]) {
			f = container_of(p, struct seg6_flow4, hlist);
			seg6_flow4_del(f);
		}
	}
}

static __net_init int seg6_init_net(struct net *net)
{
	struct seg6_net *snet = net_generic(net, seg6_net_id);

	__hash_init(snet->flow4_table, SEG6_HASH_SIZE);

	snet->net = net;
	snet->lo = NULL;

	timer_setup(&snet->flow4_timer, seg6_flow4_cleanup, TIMER_DEFERRABLE);
	mod_timer(&snet->flow4_timer, jiffies + SEG6_FLOW4_AGING_INTERVAL);

	return 0;
}

static __net_exit void seg6_exit_net(struct net *net)
{
	struct seg6_net *snet = net_generic(net, seg6_net_id);

	del_timer_sync(&snet->flow4_timer);

	if (snet->lo)
		dev_put(snet->lo);

	seg6_flow4_destroy(snet);
}

static struct pernet_operations seg6_net_ops = {
	.init	= seg6_init_net,
	.exit	= seg6_exit_net,
	.id	= &seg6_net_id,
	.size	= sizeof(struct seg6_net),
};


struct seg6_cache {
	struct hlist_node hlist;	/* seg6_cache_table[] */
	struct rcu_head rcu;

	unsigned long updated;

	int ifindex;		/* ifindex of the IN IFACE */
	__be32 arg;

	/* cached header informations */
	__be16 prot;		/* ethert type of inner hdr (skb->protocol) */
#define SEG6_CACHE_MAX_SEGS 16
	struct ipv6hdr hdr;	/* outer ipv6 hdr */
	struct ipv6_sr_hdr srh;	/* outer sr hdr */
	struct in6_addr segments[SEG6_CACHE_MAX_SEGS];
	__u8 tos;		/* inner ipv4 tos */
	__be32 flowlabel;	/* inner ipv6 flowlabel */
};
DEFINE_HASHTABLE(seg6_cache_table, SEG6_HASH_BITS);


static void seg6_cache_dump(struct seg6_cache *c)
{
	if (!c)
		pr_debug("%s: c is null!\n", __func__);
	if (c->ifindex == 0)
		pr_debug("%s: unused cache\n", __func__);

	pr_debug("    ifindex       %d\n", c->ifindex);
	pr_debug("    argument      0x%x\n", ntohl(c->arg));
	pr_debug("    protocol      0x%04x\n", ntohs(c->prot));
	pr_debug("    daddr         %pI6", &c->hdr.daddr);
	pr_debug("    saddr         %pI6", &c->hdr.saddr);
	pr_debug("    segleft       %u\n", c->srh.segments_left);
	pr_debug("    segs[segleft] %pI6\n",
		 &c->srh.segments[c->srh.segments_left]);
}
#define seg6_cache_dump_msg(c, fmt, ...)                        \
	do {							\
		pr_debug("%s: " fmt, __func__, ##__VA_ARGS__);	\
		seg6_cache_dump((c));				\
	} while(0)

static inline unsigned int seg6_cache_hash(__be32 arg, int ifindex,
					   __be16 prot)
{
	__be64 a;

	a = arg;
	a <<= 16;
	a |= prot;
	a <<= 16;
	a += ifindex;

	return hash_64(a, SEG6_HASH_BITS);
}

static inline struct hlist_head *seg6_cache_head(__be32 arg, int ifindex,
						__be16 prot)
{
	return &seg6_cache_table[seg6_cache_hash(arg, ifindex, prot)];
}

static struct seg6_cache *seg6_cache_alloc(__be32 arg, int ifindex,
					   __be16 prot)
{
	struct seg6_cache *c;

	c = kmalloc(sizeof(struct seg6_cache), GFP_ATOMIC);
	if (!c) {
		net_err_ratelimited("%s: failed to malloc\n", __func__);
		return NULL;
	}

	memset(c, 0, sizeof(struct seg6_cache));
	c->updated = jiffies;
	c->ifindex = ifindex;
	c->arg = arg;
	c->prot = prot;

	return c;
}

static struct seg6_cache *seg6_cache_find(__be32 arg, int ifindex,
					  __be16 prot)
{
	struct hlist_head *head = seg6_cache_head(arg, ifindex, prot);
	struct seg6_cache *found;

	rcu_read_lock();
	hlist_for_each_entry_rcu(found, head, hlist) {
		if (found->arg == arg && found->ifindex == ifindex &&
		    found->prot == prot) {
			rcu_read_unlock();
			return found;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static void seg6_cache_add(struct seg6_cache *c)
{
	hlist_add_head_rcu(&c->hlist, seg6_cache_head(c->arg, c->ifindex,
						      c->prot));
}

static void seg6_cache_remove(int ifindex)
{
	struct hlist_node *p, *n;
	struct seg6_cache *c;
	int h;

	/* XXX: Remove cache entries associating the ingress
	 * interface. If everything properly works, a single End.AC.E
	 * route uses a single incoming interface that is not used by
	 * other End.AC.E routes. However, it can accidentally happen
	 * that multiple End.AC.E routes share a single incoming
	 * interface. In this case, if an End.AC.E route is deleted,
	 * associating caches are removed even other End.AC.E routes
	 * use the caches. Thus, we use RCU to protect cache entries
	 * from unintended free by multiple routes.
	 */
	for (h = 0; h < SEG6_HASH_SIZE; h++) {
		hlist_for_each_safe(p, n, &seg6_cache_table[h]) {
			c = container_of(p, struct seg6_cache, hlist);
			hlist_del_rcu(&c->hlist);
			kfree_rcu(c, rcu);
		}
	}
}

static inline int extract_shift_bits(struct in6_addr mask)
{
	int n, i, len = 0;

	for (n = 15; n >= 0; n--) {
		for (i = 0; i < 8; i++) {
			if (!(mask.s6_addr[n] & (0x01 << i))) {
				len++;
			} else
				return len;
		}
	}

	/* mask is all 0 */
	return 0;
}

static __be32 seg6_extract_arg(struct in6_addr addr, struct in6_addr mask)
{
	struct in6_addr buf;
	__u32 ret;
	int n, m, skip, len = extract_shift_bits(mask);

	for (n = 0; n < 4; n++)
		buf.s6_addr32[n] = addr.s6_addr32[n] & mask.s6_addr32[n];

	skip = len >> 3; /* we can skip "skip" bytes */
	for (n = 0; n < len - (skip << 3); n++) {
		__u8 a = 0, b = 0;

		for (m = 0; m < 16 - skip; m++) {
			a = buf.s6_addr[m] & 0x01;
			buf.s6_addr[m] >>= 1;
			if (b)
				buf.s6_addr[m] |= (b << 7);
			b = a;
		}
	}

	/* host byte order */
	ret = 0;
	ret |= buf.s6_addr[16 - skip - 4] << 24;
	ret |= buf.s6_addr[16 - skip - 3] << 16;
	ret |= buf.s6_addr[16 - skip - 2] << 8;
	ret |= buf.s6_addr[16 - skip - 1];

	return htonl(ret);
}

static int seg6_end_ac_get_arg(struct sk_buff *skb, __be32 *arg)
{
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;
	__be32 a = 0;
	int ret = 0;

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		ip4h = ip_hdr(skb);
		a = ntohl((__u32)ip4h->tos);
		break;
	case ETH_P_IPV6:
		ip6h = ipv6_hdr(skb);
		a = ip6_flowlabel(ip6h);
		break;
	default:
		net_warn_ratelimited("%s: unsupported ptorocol 0x%04x\n",
				     __func__, ntohs(skb->protocol));
		ret = -1;
	}

	*arg = a;
	return ret;
}



static struct seg6_local_lwt *seg6_local_lwtunnel(struct lwtunnel_state *lwt)
{
	return (struct seg6_local_lwt *)lwt->data;
}

static struct ipv6_sr_hdr *get_srh(struct sk_buff *skb)
{
	struct ipv6_sr_hdr *srh;
	int len, srhoff = 0;

	if (ipv6_find_hdr(skb, &srhoff, IPPROTO_ROUTING, NULL, NULL) < 0)
		return NULL;

	if (!pskb_may_pull(skb, srhoff + sizeof(*srh)))
		return NULL;

	srh = (struct ipv6_sr_hdr *)(skb->data + srhoff);

	len = (srh->hdrlen + 1) << 3;

	if (!pskb_may_pull(skb, srhoff + len))
		return NULL;

	if (!seg6_validate_srh(srh, len))
		return NULL;

	return srh;
}

static struct ipv6_sr_hdr *get_and_validate_srh(struct sk_buff *skb)
{
	struct ipv6_sr_hdr *srh;

	srh = get_srh(skb);
	if (!srh)
		return NULL;

	if (srh->segments_left == 0)
		return NULL;

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (!seg6_hmac_validate_skb(skb))
		return NULL;
#endif

	return srh;
}

static bool decap_and_validate(struct sk_buff *skb, int proto, bool validate)
{
	struct ipv6_sr_hdr *srh;
	unsigned int off = 0;

	srh = get_srh(skb);
	if (srh && validate && srh->segments_left > 0)
		return false;

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (srh && !seg6_hmac_validate_skb(skb))
		return false;
#endif

	if (ipv6_find_hdr(skb, &off, proto, NULL, NULL) < 0)
		return false;

	if (!pskb_pull(skb, off))
		return false;

	skb_postpull_rcsum(skb, skb_network_header(skb), off);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->encapsulation = 0;

	return true;
}

static void advance_nextseg(struct ipv6_sr_hdr *srh, struct in6_addr *daddr)
{
	struct in6_addr *addr;

	srh->segments_left--;
	addr = srh->segments + srh->segments_left;
	*daddr = *addr;
}

int seg6_lookup_nexthop(struct sk_buff *skb, struct in6_addr *nhaddr,
			u32 tbl_id)
{
	struct net *net = dev_net(skb->dev);
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	int flags = RT6_LOOKUP_F_HAS_SADDR;
	struct dst_entry *dst = NULL;
	struct rt6_info *rt;
	struct flowi6 fl6;

	fl6.flowi6_iif = skb->dev->ifindex;
	fl6.daddr = nhaddr ? *nhaddr : hdr->daddr;
	fl6.saddr = hdr->saddr;
	fl6.flowlabel = ip6_flowinfo(hdr);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = hdr->nexthdr;

	if (nhaddr)
		fl6.flowi6_flags = FLOWI_FLAG_KNOWN_NH;

	if (!tbl_id) {
		dst = ip6_route_input_lookup(net, skb->dev, &fl6, skb, flags);
	} else {
		struct fib6_table *table;

		table = fib6_get_table(net, tbl_id);
		if (!table)
			goto out;

		rt = ip6_pol_route(net, table, 0, &fl6, skb, flags);
		dst = &rt->dst;
	}

	if (dst && dst->dev->flags & IFF_LOOPBACK && !dst->error) {
		dst_release(dst);
		dst = NULL;
	}

out:
	if (!dst) {
		rt = net->ipv6.ip6_blk_hole_entry;
		dst = &rt->dst;
		dst_hold(dst);
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);
	return dst->error;
}

static int seg6_local_endflavor(struct sk_buff *skb, struct ipv6_sr_hdr *srh,
				u8 flavor)
{
	int ret = 0;
	u8 srhlen;
	u16 plen;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);

	/* pop srh in accordance with end flavor */
	switch (flavor) {
	case SEG6_LOCAL_ENDFLAVOR_PSP:
		srhlen = (srh->hdrlen + 1) << 3;
		plen = ntohs(ip6h->payload_len);
		ip6h->nexthdr = srh->nexthdr;
		ip6h->payload_len = htons(plen - srhlen);
		memcpy(srh, ((char *)srh) + srhlen, plen - srhlen);
		skb_reset_transport_header(skb);
		break;

	case SEG6_LOCAL_ENDFLAVOR_NONE:
		ret = 0;
		break;

	case SEG6_LOCAL_ENDFLAVOR_USP:
	case SEG6_LOCAL_ENDFLAVOR_USD:
	default:
		net_warn_ratelimited("%s: unsupported end flavor %u\n",
				     __func__, flavor);
		ret = -ENOTSUPP;
	}

	return ret;
}

/* regular endpoint function */
static int input_action_end(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	if (srh->segments_left == 0)
		if (seg6_local_endflavor(skb, srh, slwt->endflavor) < 0)
			goto drop;

	seg6_lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* regular endpoint, and forward to specified nexthop */
static int input_action_end_x(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	if (srh->segments_left == 0)
		if (seg6_local_endflavor(skb, srh, slwt->endflavor) < 0)
			goto drop;

	seg6_lookup_nexthop(skb, &slwt->nh6, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_t(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	if (srh->segments_left == 0)
		if (seg6_local_endflavor(skb, srh, slwt->endflavor) < 0)
			goto drop;

	seg6_lookup_nexthop(skb, NULL, slwt->table);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* decapsulate and forward inner L2 frame on specified interface */
static int input_action_end_dx2(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct net_device *odev;
	struct ethhdr *eth;

	if (!decap_and_validate(skb, NEXTHDR_NONE, true))
		goto drop;

	if (!pskb_may_pull(skb, ETH_HLEN))
		goto drop;

	skb_reset_mac_header(skb);
	eth = (struct ethhdr *)skb->data;

	/* To determine the frame's protocol, we assume it is 802.3. This avoids
	 * a call to eth_type_trans(), which is not really relevant for our
	 * use case.
	 */
	if (!eth_proto_is_802_3(eth->h_proto))
		goto drop;

	odev = dev_get_by_index_rcu(net, slwt->oif);
	if (!odev)
		goto drop;

	/* As we accept Ethernet frames, make sure the egress device is of
	 * the correct type.
	 */
	if (odev->type != ARPHRD_ETHER)
		goto drop;

	if (!(odev->flags & IFF_UP) || !netif_carrier_ok(odev))
		goto drop;

	skb_orphan(skb);

	if (skb_warn_if_lro(skb))
		goto drop;

	skb_forward_csum(skb);

	if (skb->len - ETH_HLEN > odev->mtu)
		goto drop;

	skb->dev = odev;
	skb->protocol = eth->h_proto;

	return dev_queue_xmit(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* decapsulate and forward to specified nexthop */
static int input_action_end_dx6(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct in6_addr *nhaddr = NULL;

	/* this function accepts IPv6 encapsulated packets, with either
	 * an SRH with SL=0, or no SRH.
	 */

	if (!decap_and_validate(skb, IPPROTO_IPV6, true))
		goto drop;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		goto drop;

	/* The inner packet is not associated to any local interface,
	 * so we do not call netif_rx().
	 *
	 * If slwt->nh6 is set to ::, then lookup the nexthop for the
	 * inner packet's DA. Otherwise, use the specified nexthop.
	 */

	if (!ipv6_addr_any(&slwt->nh6))
		nhaddr = &slwt->nh6;

	seg6_lookup_nexthop(skb, nhaddr, 0);

	return dst_input(skb);
drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_dx4(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct iphdr *iph;
	struct seg6_net *snet = net_generic(dev_net(skb->dev), seg6_net_id);
	struct net_device *lo;
	__be32 nhaddr;
	int err;

	if (!decap_and_validate(skb, IPPROTO_IPIP, true))
		goto drop;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto drop;

	skb->protocol = htons(ETH_P_IP);

	iph = ip_hdr(skb);

	nhaddr = slwt->nh4.s_addr ?: iph->daddr;

	skb_dst_drop(skb);

	/* XXX: after decapsulation, remaining the ingress interface
	 * of the skb causes uninteded behavior with ip rule. so, use
	 * loopback as the ingress interface */
	lo = seg6_net_get_lo(snet);
	if (unlikely(!lo))
		goto drop;
	skb->dev = lo;
	skb->skb_iif = snet->lo->ifindex;

	err = ip_route_input(skb, nhaddr, iph->saddr, 0, skb->dev);
	if (err)
		goto drop;

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_dt6(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	if (!decap_and_validate(skb, IPPROTO_IPV6, true))
		goto drop;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		goto drop;

	seg6_lookup_nexthop(skb, NULL, slwt->table);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* push an SRH on top of the current one */
static int input_action_end_b6(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int err = -EINVAL;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	err = seg6_do_srh_inline(skb, slwt->srh);
	if (err)
		goto drop;

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	seg6_lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return err;
}

/* encapsulate within an outer IPv6 header and a specified SRH */
static int input_action_end_b6_encap(struct sk_buff *skb,
				     struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int err = -EINVAL;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	skb_reset_inner_headers(skb);
	skb->encapsulation = 1;

	err = seg6_do_srh_encap(skb, slwt->srh, IPPROTO_IPV6);
	if (err)
		goto drop;

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	seg6_lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return err;
}

DEFINE_PER_CPU(struct seg6_bpf_srh_state, seg6_bpf_srh_states);

bool seg6_bpf_has_valid_srh(struct sk_buff *skb)
{
	struct seg6_bpf_srh_state *srh_state =
		this_cpu_ptr(&seg6_bpf_srh_states);
	struct ipv6_sr_hdr *srh = srh_state->srh;

	if (unlikely(srh == NULL))
		return false;

	if (unlikely(!srh_state->valid)) {
		if ((srh_state->hdrlen & 7) != 0)
			return false;

		srh->hdrlen = (u8)(srh_state->hdrlen >> 3);
		if (!seg6_validate_srh(srh, (srh->hdrlen + 1) << 3))
			return false;

		srh_state->valid = true;
	}

	return true;
}

static int input_action_end_bpf(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct seg6_bpf_srh_state *srh_state =
		this_cpu_ptr(&seg6_bpf_srh_states);
	struct ipv6_sr_hdr *srh;
	int ret;

	srh = get_and_validate_srh(skb);
	if (!srh) {
		kfree_skb(skb);
		return -EINVAL;
	}
	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	/* preempt_disable is needed to protect the per-CPU buffer srh_state,
	 * which is also accessed by the bpf_lwt_seg6_* helpers
	 */
	preempt_disable();
	srh_state->srh = srh;
	srh_state->hdrlen = srh->hdrlen << 3;
	srh_state->valid = true;

	rcu_read_lock();
	bpf_compute_data_pointers(skb);
	ret = bpf_prog_run_save_cb(slwt->bpf.prog, skb);
	rcu_read_unlock();

	switch (ret) {
	case BPF_OK:
	case BPF_REDIRECT:
		break;
	case BPF_DROP:
		goto drop;
	default:
		pr_warn_once("bpf-seg6local: Illegal return value %u\n", ret);
		goto drop;
	}

	if (srh_state->srh && !seg6_bpf_has_valid_srh(skb))
		goto drop;

	preempt_enable();
	if (ret != BPF_REDIRECT)
		seg6_lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	preempt_enable();
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_am_e(struct sk_buff *skb,
				 struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct ipv6_sr_hdr *srh;
	struct net_device *odev;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	srh->segments_left--;

	/* set daddr to segment list[0] */
	ipv6_hdr(skb)->daddr = srh->segments[0];

	/* validate, create mac header, and xmit */
	odev = dev_get_by_index_rcu(net, slwt->oif);
	if (!odev)
		goto drop;

	if (odev->type != ARPHRD_ETHER)
		goto drop;

	if (!(odev->flags & IFF_UP) || !netif_carrier_ok(odev))
		goto drop;

	skb_orphan(skb);

	if (skb_warn_if_lro(skb))
		goto drop;

	skb_forward_csum(skb);

	if (skb->len - ETH_HLEN > odev->mtu)
		goto drop;

	skb->dev = odev;

	dev_hard_header(skb, skb->dev, ETH_P_IPV6, slwt->mac, odev->dev_addr,
			skb->len);
	return dev_queue_xmit(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_am_i_t(struct sk_buff *skb,
				   struct seg6_local_lwt *slwt)
{
	int ret;
	struct ipv6_sr_hdr *srh;
	struct dst_entry *dst = NULL;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	/* set daddr to segment list[segment left] */
	ipv6_hdr(skb)->daddr = srh->segments[srh->segments_left];

	skb_scrub_packet(skb, false);

	ret = seg6_lookup_nexthop(skb, NULL, slwt->table);
	if (ret != 0)
		goto drop;

	/* check loop */
	dst = skb_dst(skb);
	if (dst && dst->lwtstate &&
	    seg6_local_lwtunnel(dst->lwtstate) == slwt) {
		/* this is loop ! */
		net_warn_ratelimited("%s: looping this seg6local route\n",
				     __func__);
		goto drop;
	}


	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_af4_e(struct sk_buff *skb,
				  struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct seg6_net *snet = net_generic(net, seg6_net_id);
	struct ipv6hdr *ip6h;
	struct ipv6_sr_hdr *srh;
	struct seg6_flow4 s, *f;
	struct net_device *odev;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;
	if (srh->first_segment > SEG6_FLOW4_MAX_NSEGS) {
		net_err_ratelimited("%s: this srh has too many segments! %d\n",
				    __func__, srh->first_segment);
		goto drop;
	}

	if (srh->nexthdr != IPPROTO_IPIP)
		goto drop;

	ip6h = ipv6_hdr(skb);

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	/* save latest ipv6hdr and srh */
	ip6h = ipv6_hdr(skb);
	memcpy(&s.ip6h, ip6h, sizeof(struct ipv6hdr));
	memcpy(&s.srh, srh, (srh->hdrlen + 1) << 3);

	/* decap and find flow */
	if (!decap_and_validate(skb, IPPROTO_IPIP, false))
		goto drop;

	if (seg6_flow4_make(&s, skb, slwt->iif) < 0)
		goto drop;

	f = seg6_flow4_find(snet, &s);
	if (!f) {
		/* new ipv4 flow. create and store the flow info */
		f = seg6_flow4_alloc();
		if (!f)
			goto drop;

		memcpy(f, &s, sizeof(s));
		seg6_flow4_add(snet, f);
		seg6_flow4_dump_msg(f, "new flow stored\n");
	} else {
		seg6_flow4_update(f, &s.ip6h, &s.srh);
	}

	/* validate, create mac header, and xmit */
	odev = dev_get_by_index_rcu(net, slwt->oif);
	if (!odev)
		goto drop;

	if (odev->type != ARPHRD_ETHER)
		goto drop;

	if (!(odev->flags & IFF_UP) || !netif_carrier_ok(odev))
		goto drop;

	skb->protocol = htons(ETH_P_IP);
	skb_orphan(skb);

	if (skb_warn_if_lro(skb))
		goto drop;

	skb_forward_csum(skb);

	if (skb->len - ETH_HLEN > odev->mtu)
		goto drop;

	skb->dev = odev;

	dev_hard_header(skb, skb->dev, ETH_P_IP, slwt->mac, odev->dev_addr,
			skb->len);
	return dev_queue_xmit(skb);
drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_af4_i_t(struct sk_buff *skb,
				    struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct seg6_net *snet = net_generic(net, seg6_net_id);
	struct seg6_flow4 s, *f;
	struct ipv6hdr *hdr;
	struct ipv6_sr_hdr *srh;
	struct dst_entry *dst;
	int srhlen, hdrlen, err;

	if (seg6_flow4_make(&s, skb, skb->skb_iif) < 0)
		goto drop;

	seg6_flow4_dump_msg(&s, "finding flow is\n");

	f = seg6_flow4_find(snet, &s);
	if (!f)
		goto drop;

	seg6_flow4_update(f, NULL, NULL);
	seg6_flow4_dump_msg(f, "found flow is\n");

	/* encap the packet within the stored ipv6 and sr headers */
	hdrlen = sizeof(struct ipv6hdr);
	srhlen = (f->srh.hdrlen + 1) << 3;
	err = skb_cow_head(skb, srhlen + hdrlen + skb->mac_len);
	if (unlikely(err)) {
		net_err_ratelimited("%s: skb_cow_head error\n", __func__);
		goto drop;
	}

	skb_push(skb, srhlen + hdrlen);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	hdr = ipv6_hdr(skb);
	srh = (struct ipv6_sr_hdr *)(hdr + 1);

	memcpy(hdr, &f->ip6h, sizeof(struct ipv6hdr));
	memcpy(srh, &f->srh, srhlen);

	skb->protocol = htons(ETH_P_IPV6);
	skb_postpush_rcsum(skb, hdr, hdrlen + srhlen);
	skb_scrub_packet(skb, true);

	/* reroute and xmit the sr packet*/
	err = seg6_lookup_nexthop(skb, NULL, slwt->table);
	if (err != 0)
		goto drop;

	/* check loop */
	dst = skb_dst(skb);
	if (dst && dst->lwtstate &&
	    seg6_local_lwtunnel(dst->lwtstate) == slwt) {
		net_warn_ratelimited("%s: looping this seg6local route\n",
				     __func__);
		goto drop;
	}

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_ac_e(struct sk_buff *skb,
				 struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct iphdr *ip4h;
	struct ipv6hdr *hdr, *ip6h;
	struct ipv6_sr_hdr *srh;
	struct seg6_cache *c;
	struct net_device *odev;
	__be16 ethertype;
	__be32 arg;
	u8 tclass;
	int protocol;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;
	if (srh->first_segment > SEG6_CACHE_MAX_SEGS) {
		net_err_ratelimited("%s: this srh has too many segments! %d\n",
				    __func__, srh->first_segment);
		goto drop;
	}

	/* find cache entry */
	protocol = srh->nexthdr;
	switch (protocol) {
	case IPPROTO_IPIP:
		ethertype = htons(ETH_P_IP);
		break;

	case IPPROTO_IPV6:
		ethertype = htons(ETH_P_IPV6);
		break;
	default:
		net_warn_ratelimited("%s: unsupported nexthdr type %d\n",
				     __func__, srh->nexthdr);
		goto drop;
	}

	hdr = ipv6_hdr(skb);
	arg = seg6_extract_arg(hdr->daddr, slwt->argmask);
	c = seg6_cache_find(arg, slwt->iif, ethertype);
	if (!c) {
		c = seg6_cache_alloc(arg, slwt->iif, ethertype);
		if (!c)
			goto drop;
		seg6_cache_add(c);
		seg6_cache_dump_msg(c, "new cache added\n");
	} else
		seg6_cache_dump_msg(c, "cache found\n");


	/* store headers to cache */
	advance_nextseg(srh, &hdr->daddr);
	memcpy(&c->hdr, hdr, sizeof(struct ipv6hdr));
	memcpy(&c->srh, srh, (srh->hdrlen + 1) << 3);
	c->updated = jiffies;

	/* decap */
	if (!decap_and_validate(skb, protocol, false)) {
		pr_debug("%s: decap failed\n", __func__);
		goto drop;
	}

	/* store arg into tos or flowlabel of inner header */
	switch (protocol) {
	case IPPROTO_IPIP:
		ip4h = ip_hdr(skb);
		c->tos = ip4h->tos;
		ip4h->tos = ntohl(arg) & 0xFF;
		ip4h->check = 0;
		ip4h->check = ip_fast_csum((__u8 *)ip4h, ip4h->ihl);
		break;
	case IPPROTO_IPV6:
		ip6h = ipv6_hdr(skb);
		c->flowlabel = ip6_flowlabel(ip6h);
		tclass = ip6_tclass(ip6_flowinfo(ip6h));
		ip6_flow_hdr(ip6h, tclass, arg & htonl(0xFFFFF));
		break;
	}

	/* validate, create mac header, and xmit */
	odev = dev_get_by_index_rcu(net, slwt->oif);
	if (!odev)
		goto drop;

	if (odev->type != ARPHRD_ETHER)
		goto drop;

	if (!(odev->flags & IFF_UP) || !netif_carrier_ok(odev))
		goto drop;

	skb->protocol = ethertype;
	skb_orphan(skb);

	if (skb_warn_if_lro(skb))
		goto drop;

	skb_forward_csum(skb);

	if (skb->len - ETH_HLEN > odev->mtu)
		goto drop;

	skb->dev = odev;

	dev_hard_header(skb, skb->dev, ntohs(ethertype), slwt->mac,
			odev->dev_addr, skb->len);
	return dev_queue_xmit(skb);
drop:
	kfree_skb(skb);
	return -EINVAL;

}

static int input_action_end_ac_i_t(struct sk_buff *skb,
				   struct seg6_local_lwt *slwt)
{
	struct seg6_cache *c;
	struct iphdr *ip4h;
	struct ipv6hdr *hdr, *ip6h;
	struct ipv6_sr_hdr *srh;
	struct dst_entry *dst;
	int srhlen, hdrlen, pktlen, err;
	__be32 arg;
	__u8 tclass;

	/* find cache entry */
	if (seg6_end_ac_get_arg(skb, &arg) < 0)
		goto drop;

	c = seg6_cache_find(arg, skb->skb_iif, skb->protocol);
	if (!c) {
		net_warn_ratelimited("%s: cache not found for "
				     "arg 0x%x, ifindex %d\n",
				     __func__, ntohl(arg), skb->skb_iif);
		goto drop;
	}
	seg6_cache_dump_msg(c, "cache entry found\n");

	/* decrement ttl, and restore tos or flowlabel */
	switch(ntohs(skb->protocol)) {
	case ETH_P_IP:
		ip4h = ip_hdr(skb);
		if (ip4h->ttl <= 1) {
			icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
			goto drop;
		}
		ip4h->ttl--;
		ip4h->tos = c->tos;
		ip4h->check = 0;
		ip4h->check = ip_fast_csum((__u8 *)ip4h, ip4h->ihl);
		pktlen = ntohs(ip4h->tot_len);
		break;
	case ETH_P_IPV6:
		ip6h = ipv6_hdr(skb);
		if (ip6h->hop_limit <= 1) {
			icmpv6_send(skb, ICMPV6_TIME_EXCEED,
				    ICMPV6_EXC_HOPLIMIT, 0);
			goto drop;
		}
		ip6h->hop_limit--;
		tclass = ip6_tclass(ip6_flowlabel(ip6h));
		ip6_flow_hdr(ip6h, tclass, c->flowlabel);
		pktlen = ntohs(ip6h->payload_len) + 40;
		break;
	default:
		goto drop;
	}

	/* encap the packet within the stored ipv6 and sr headers */
	hdrlen = sizeof(struct ipv6hdr);
	srhlen = (c->srh.hdrlen + 1) << 3;
	err = skb_cow_head(skb, srhlen + hdrlen + skb->mac_len);
	if (unlikely(err)) {
		net_err_ratelimited("%s: skb_cow_head error\n", __func__);
		goto drop;
	}

	skb_push(skb, srhlen + hdrlen);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	hdr = ipv6_hdr(skb);

	srh = (struct ipv6_sr_hdr *)(hdr + 1);

	memcpy(srh, &c->srh, srhlen);
	memcpy(hdr, &c->hdr, sizeof(struct ipv6hdr));
	hdr->payload_len = htons(pktlen + srhlen);

	skb->protocol = htons(ETH_P_IPV6);
	skb_postpush_rcsum(skb, hdr, hdrlen + srhlen);
	skb_scrub_packet(skb, true);

	/* reroute and xmit the sr packet*/
	err = seg6_lookup_nexthop(skb, NULL, slwt->table);
	if (err != 0)
		goto drop;

	/* check loop */
	dst = skb_dst(skb);
	if (dst && dst->lwtstate &&
	    seg6_local_lwtunnel(dst->lwtstate) == slwt) {
		net_warn_ratelimited("%s: looping this seg6local route\n",
				     __func__);
		goto drop;
	}

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static struct seg6_action_desc seg6_action_table[] = {
	{
		.action		= SEG6_LOCAL_ACTION_END,
		.attrs		= (1 << SEG6_LOCAL_ENDFLAVOR),
		.input		= input_action_end,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_X,
		.attrs		= (1 << SEG6_LOCAL_NH6 |
				   1 << SEG6_LOCAL_ENDFLAVOR),
		.input		= input_action_end_x,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_T,
		.attrs		= (1 << SEG6_LOCAL_TABLE |
				   1 << SEG6_LOCAL_ENDFLAVOR),
		.input		= input_action_end_t,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX2,
		.attrs		= (1 << SEG6_LOCAL_OIF),
		.input		= input_action_end_dx2,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX6,
		.attrs		= (1 << SEG6_LOCAL_NH6),
		.input		= input_action_end_dx6,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX4,
		.attrs		= (1 << SEG6_LOCAL_NH4),
		.input		= input_action_end_dx4,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DT6,
		.attrs		= (1 << SEG6_LOCAL_TABLE),
		.input		= input_action_end_dt6,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_B6,
		.attrs		= (1 << SEG6_LOCAL_SRH),
		.input		= input_action_end_b6,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_B6_ENCAP,
		.attrs		= (1 << SEG6_LOCAL_SRH),
		.input		= input_action_end_b6_encap,
		.static_headroom	= sizeof(struct ipv6hdr),
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_BPF,
		.attrs		= (1 << SEG6_LOCAL_BPF),
		.input		= input_action_end_bpf,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_AM_E,
		.attrs		= (1 << SEG6_LOCAL_OIF | 1 << SEG6_LOCAL_MAC),
		.input		= input_action_end_am_e,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_AM_I_T,
		.attrs		= (1 << SEG6_LOCAL_TABLE),
		.input		= input_action_end_am_i_t,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_AF4_E,
		.attrs		= (1 << SEG6_LOCAL_OIF | 1 << SEG6_LOCAL_IIF |
				   1 << SEG6_LOCAL_MAC),
		.input		= input_action_end_af4_e,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_AF4_I_T,
		.attrs		= (1 << SEG6_LOCAL_TABLE),
		.input		= input_action_end_af4_i_t,
		.static_headroom	= (sizeof(struct ipv6hdr) +
					   sizeof(struct ipv6_sr_hdr) +
					   (sizeof(struct ipv6hdr) << 3)),
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_AC_E,
		.attrs		= (1 << SEG6_LOCAL_OIF | 1 << SEG6_LOCAL_IIF |
				   1 << SEG6_LOCAL_MAC |
				   1 << SEG6_LOCAL_ARGMASK),
		.input		= input_action_end_ac_e,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_AC_I_T,
		.attrs		= (1 << SEG6_LOCAL_TABLE),
		.input		= input_action_end_ac_i_t,
		.static_headroom	= (sizeof(struct ipv6hdr) +
					   sizeof(struct ipv6_sr_hdr) +
					   (sizeof(struct ipv6hdr) << 3)),
	},
};

static struct seg6_action_desc *__get_action_desc(int action)
{
	struct seg6_action_desc *desc;
	int i, count;

	count = ARRAY_SIZE(seg6_action_table);
	for (i = 0; i < count; i++) {
		desc = &seg6_action_table[i];
		if (desc->action == action)
			return desc;
	}

	return NULL;
}

static int seg6_local_input(struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct seg6_action_desc *desc;
	struct seg6_local_lwt *slwt;

	slwt = seg6_local_lwtunnel(orig_dst->lwtstate);
	desc = slwt->desc;

	if (skb->protocol != htons(ETH_P_IP) &&
	    skb->protocol != htons(ETH_P_IPV6))
		goto drop;

	if (skb->protocol == htons(ETH_P_IP) &&
	    desc->action != SEG6_LOCAL_ACTION_END_AF4_I_T &&
	    desc->action != SEG6_LOCAL_ACTION_END_AC_I_T)
		goto drop;

	return desc->input(skb, slwt);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static const struct nla_policy seg6_local_policy[SEG6_LOCAL_MAX + 1] = {
	[SEG6_LOCAL_ACTION]	= { .type = NLA_U32 },
	[SEG6_LOCAL_SRH]	= { .type = NLA_BINARY },
	[SEG6_LOCAL_TABLE]	= { .type = NLA_U32 },
	[SEG6_LOCAL_NH4]	= { .type = NLA_BINARY,
				    .len = sizeof(struct in_addr) },
	[SEG6_LOCAL_NH6]	= { .type = NLA_BINARY,
				    .len = sizeof(struct in6_addr) },
	[SEG6_LOCAL_IIF]	= { .type = NLA_U32 },
	[SEG6_LOCAL_OIF]	= { .type = NLA_U32 },
	[SEG6_LOCAL_MAC]	= { .type = NLA_BINARY,
				    .len = ETH_ALEN },
	[SEG6_LOCAL_ENDFLAVOR]	= { .type = NLA_U8 },
	[SEG6_LOCAL_ARGMASK]	= { .type = NLA_BINARY,
				    .len = sizeof(struct in6_addr) },
	[SEG6_LOCAL_BPF]	= { .type = NLA_NESTED },
};

static int parse_nla_srh(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int len;

	srh = nla_data(attrs[SEG6_LOCAL_SRH]);
	len = nla_len(attrs[SEG6_LOCAL_SRH]);

	/* SRH must contain at least one segment */
	if (len < sizeof(*srh) + sizeof(struct in6_addr))
		return -EINVAL;

	if (!seg6_validate_srh(srh, len))
		return -EINVAL;

	slwt->srh = kmemdup(srh, len, GFP_KERNEL);
	if (!slwt->srh)
		return -ENOMEM;

	slwt->headroom += len;

	return 0;
}

static int put_nla_srh(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	struct nlattr *nla;
	int len;

	srh = slwt->srh;
	len = (srh->hdrlen + 1) << 3;

	nla = nla_reserve(skb, SEG6_LOCAL_SRH, len);
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), srh, len);

	return 0;
}

static int cmp_nla_srh(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	int len = (a->srh->hdrlen + 1) << 3;

	if (len != ((b->srh->hdrlen + 1) << 3))
		return 1;

	return memcmp(a->srh, b->srh, len);
}

static int parse_nla_table(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->table = nla_get_u32(attrs[SEG6_LOCAL_TABLE]);

	return 0;
}

static int put_nla_table(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_TABLE, slwt->table))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_table(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->table != b->table)
		return 1;

	return 0;
}

static int parse_nla_nh4(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->nh4, nla_data(attrs[SEG6_LOCAL_NH4]),
	       sizeof(struct in_addr));

	return 0;
}

static int put_nla_nh4(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_NH4, sizeof(struct in_addr));
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), &slwt->nh4, sizeof(struct in_addr));

	return 0;
}

static int cmp_nla_nh4(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->nh4, &b->nh4, sizeof(struct in_addr));
}

static int parse_nla_nh6(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->nh6, nla_data(attrs[SEG6_LOCAL_NH6]),
	       sizeof(struct in6_addr));

	return 0;
}

static int put_nla_nh6(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_NH6, sizeof(struct in6_addr));
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), &slwt->nh6, sizeof(struct in6_addr));

	return 0;
}

static int cmp_nla_nh6(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->nh6, &b->nh6, sizeof(struct in6_addr));
}

static int parse_nla_iif(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->iif = nla_get_u32(attrs[SEG6_LOCAL_IIF]);

	return 0;
}

static int put_nla_iif(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_IIF, slwt->iif))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_iif(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->iif != b->iif)
		return 1;

	return 0;
}

static int parse_nla_oif(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->oif = nla_get_u32(attrs[SEG6_LOCAL_OIF]);

	return 0;
}

static int put_nla_oif(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_OIF, slwt->oif))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_oif(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->oif != b->oif)
		return 1;

	return 0;
}

static int parse_nla_mac(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(slwt->mac, nla_data(attrs[SEG6_LOCAL_MAC]), ETH_ALEN);
	return 0;
}

static int put_nla_mac(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_MAC, ETH_ALEN);
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), &slwt->mac, ETH_ALEN);

	return 0;
}

static int cmp_nla_mac(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(a->mac, b->mac, ETH_ALEN);
}

static int parse_nla_endflavor(struct nlattr **attrs,
			       struct seg6_local_lwt *slwt)
{
	slwt->endflavor = nla_get_u8(attrs[SEG6_LOCAL_ENDFLAVOR]);

	return 0;
}

static int put_nla_endflavor(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u8(skb, SEG6_LOCAL_ENDFLAVOR, slwt->endflavor))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_endflavor(struct seg6_local_lwt *a,
			     struct seg6_local_lwt *b)
{
	if (a->endflavor != b->endflavor)
		return 1;

	return 0;
}

static int parse_nla_argmask(struct nlattr **attrs,
			     struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->argmask, nla_data(attrs[SEG6_LOCAL_ARGMASK]),
	       sizeof(struct in6_addr));

	return 0;
}

static int put_nla_argmask(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_ARGMASK, sizeof(struct in6_addr));
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), &slwt->argmask, sizeof(struct in6_addr));

	return 0;
}

static int cmp_nla_argmask(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->argmask, &b->argmask, sizeof(struct in6_addr));
}

#define MAX_PROG_NAME 256
static const struct nla_policy bpf_prog_policy[SEG6_LOCAL_BPF_PROG_MAX + 1] = {
	[SEG6_LOCAL_BPF_PROG]	   = { .type = NLA_U32, },
	[SEG6_LOCAL_BPF_PROG_NAME] = { .type = NLA_NUL_STRING,
				       .len = MAX_PROG_NAME },
};

static int parse_nla_bpf(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct nlattr *tb[SEG6_LOCAL_BPF_PROG_MAX + 1];
	struct bpf_prog *p;
	int ret;
	u32 fd;

	ret = nla_parse_nested(tb, SEG6_LOCAL_BPF_PROG_MAX,
			       attrs[SEG6_LOCAL_BPF], bpf_prog_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[SEG6_LOCAL_BPF_PROG] || !tb[SEG6_LOCAL_BPF_PROG_NAME])
		return -EINVAL;

	slwt->bpf.name = nla_memdup(tb[SEG6_LOCAL_BPF_PROG_NAME], GFP_KERNEL);
	if (!slwt->bpf.name)
		return -ENOMEM;

	fd = nla_get_u32(tb[SEG6_LOCAL_BPF_PROG]);
	p = bpf_prog_get_type(fd, BPF_PROG_TYPE_LWT_SEG6LOCAL);
	if (IS_ERR(p)) {
		kfree(slwt->bpf.name);
		return PTR_ERR(p);
	}

	slwt->bpf.prog = p;
	return 0;
}

static int put_nla_bpf(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nest;

	if (!slwt->bpf.prog)
		return 0;

	nest = nla_nest_start(skb, SEG6_LOCAL_BPF);
	if (!nest)
		return -EMSGSIZE;

	if (nla_put_u32(skb, SEG6_LOCAL_BPF_PROG, slwt->bpf.prog->aux->id))
		return -EMSGSIZE;

	if (slwt->bpf.name &&
	    nla_put_string(skb, SEG6_LOCAL_BPF_PROG_NAME, slwt->bpf.name))
		return -EMSGSIZE;

	return nla_nest_end(skb, nest);
}

static int cmp_nla_bpf(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (!a->bpf.name && !b->bpf.name)
		return 0;

	if (!a->bpf.name || !b->bpf.name)
		return 1;

	return strcmp(a->bpf.name, b->bpf.name);
}

struct seg6_action_param {
	int (*parse)(struct nlattr **attrs, struct seg6_local_lwt *slwt);
	int (*put)(struct sk_buff *skb, struct seg6_local_lwt *slwt);
	int (*cmp)(struct seg6_local_lwt *a, struct seg6_local_lwt *b);
};

static struct seg6_action_param seg6_action_params[SEG6_LOCAL_MAX + 1] = {
	[SEG6_LOCAL_SRH]	= { .parse = parse_nla_srh,
				    .put = put_nla_srh,
				    .cmp = cmp_nla_srh },

	[SEG6_LOCAL_TABLE]	= { .parse = parse_nla_table,
				    .put = put_nla_table,
				    .cmp = cmp_nla_table },

	[SEG6_LOCAL_NH4]	= { .parse = parse_nla_nh4,
				    .put = put_nla_nh4,
				    .cmp = cmp_nla_nh4 },

	[SEG6_LOCAL_NH6]	= { .parse = parse_nla_nh6,
				    .put = put_nla_nh6,
				    .cmp = cmp_nla_nh6 },

	[SEG6_LOCAL_IIF]	= { .parse = parse_nla_iif,
				    .put = put_nla_iif,
				    .cmp = cmp_nla_iif },

	[SEG6_LOCAL_OIF]	= { .parse = parse_nla_oif,
				    .put = put_nla_oif,
				    .cmp = cmp_nla_oif },

	[SEG6_LOCAL_MAC]	= { .parse = parse_nla_mac,
				    .put = put_nla_mac,
				    .cmp = cmp_nla_mac },

	[SEG6_LOCAL_ENDFLAVOR]	= { .parse = parse_nla_endflavor,
				    .put = put_nla_endflavor,
				    .cmp = cmp_nla_endflavor },

	[SEG6_LOCAL_ARGMASK]	= { .parse = parse_nla_argmask,
				    .put = put_nla_argmask,
				    .cmp = cmp_nla_argmask },

	[SEG6_LOCAL_BPF]	= { .parse = parse_nla_bpf,
				    .put = put_nla_bpf,
				    .cmp = cmp_nla_bpf },

};

static int parse_nla_action(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct seg6_action_param *param;
	struct seg6_action_desc *desc;
	int i, err;

	desc = __get_action_desc(slwt->action);
	if (!desc)
		return -EINVAL;

	if (!desc->input)
		return -EOPNOTSUPP;

	slwt->desc = desc;
	slwt->headroom += desc->static_headroom;

	for (i = 0; i < SEG6_LOCAL_MAX + 1; i++) {
		if (desc->attrs & (1 << i)) {
			if (!attrs[i])
				return -EINVAL;

			param = &seg6_action_params[i];

			err = param->parse(attrs, slwt);
			if (err < 0)
				return err;
		}
	}

	return 0;
}

static int seg6_local_build_state(struct nlattr *nla, unsigned int family,
				  const void *cfg, struct lwtunnel_state **ts,
				  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[SEG6_LOCAL_MAX + 1];
	struct lwtunnel_state *newts;
	struct seg6_local_lwt *slwt;
	int err;

	if (family != AF_INET6 && family != AF_INET) {
		pr_err("%s: invalid af %u\n", __func__, family);
		return -EINVAL;
	}

	err = nla_parse_nested(tb, SEG6_LOCAL_MAX, nla, seg6_local_policy,
			       extack);

	if (err < 0)
		return err;

	if (!tb[SEG6_LOCAL_ACTION])
		return -EINVAL;

	newts = lwtunnel_state_alloc(sizeof(*slwt));
	if (!newts)
		return -ENOMEM;

	slwt = seg6_local_lwtunnel(newts);
	slwt->lwt = newts;
	slwt->action = nla_get_u32(tb[SEG6_LOCAL_ACTION]);

	if (family == AF_INET &&
	    slwt->action != SEG6_LOCAL_ACTION_END_AF4_I_T &&
	    slwt->action != SEG6_LOCAL_ACTION_END_AC_I_T) {
		/* only AF4_I_T allows AF_INET */
		err = -EINVAL;
		goto out_free;
	}

	err = parse_nla_action(tb, slwt);
	if (err < 0)
		goto out_free;

	newts->type = LWTUNNEL_ENCAP_SEG6_LOCAL;
	newts->flags = LWTUNNEL_STATE_INPUT_REDIRECT;
	newts->headroom = slwt->headroom;

	*ts = newts;

	return 0;

out_free:
	kfree(slwt->srh);
	kfree(newts);
	return err;
}

static void seg6_local_destroy_state(struct lwtunnel_state *lwt)
{
	struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);

	kfree(slwt->srh);

	if (slwt->desc->attrs & (1 << SEG6_LOCAL_BPF)) {
		kfree(slwt->bpf.name);
		bpf_prog_put(slwt->bpf.prog);
	}

	if (slwt->action == SEG6_LOCAL_ACTION_END_AC_E)
		seg6_cache_remove(slwt->iif);

	return;
}

static int seg6_local_fill_encap(struct sk_buff *skb,
				 struct lwtunnel_state *lwt)
{
	struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);
	struct seg6_action_param *param;
	int i, err;

	if (nla_put_u32(skb, SEG6_LOCAL_ACTION, slwt->action))
		return -EMSGSIZE;

	for (i = 0; i < SEG6_LOCAL_MAX + 1; i++) {
		if (slwt->desc->attrs & (1 << i)) {
			param = &seg6_action_params[i];
			err = param->put(skb, slwt);
			if (err < 0)
				return err;
		}
	}

	return 0;
}

static int seg6_local_get_encap_size(struct lwtunnel_state *lwt)
{
	struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);
	unsigned long attrs;
	int nlsize;

	nlsize = nla_total_size(4); /* action */

	attrs = slwt->desc->attrs;

	if (attrs & (1 << SEG6_LOCAL_SRH))
		nlsize += nla_total_size((slwt->srh->hdrlen + 1) << 3);

	if (attrs & (1 << SEG6_LOCAL_TABLE))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_NH4))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_NH6))
		nlsize += nla_total_size(16);

	if (attrs & (1 << SEG6_LOCAL_IIF))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_OIF))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_MAC))
		nlsize += nla_total_size(ETH_ALEN);

	if (attrs & (1 << SEG6_LOCAL_ENDFLAVOR))
		nlsize += nla_total_size(1);

	if (attrs & (1 << SEG6_LOCAL_ARGMASK))
		nlsize += nla_total_size(16);

	if (attrs & (1 << SEG6_LOCAL_BPF))
		nlsize += nla_total_size(sizeof(struct nlattr)) +
		       nla_total_size(MAX_PROG_NAME) +
		       nla_total_size(4);

	return nlsize;
}

static int seg6_local_cmp_encap(struct lwtunnel_state *a,
				struct lwtunnel_state *b)
{
	struct seg6_local_lwt *slwt_a, *slwt_b;
	struct seg6_action_param *param;
	int i;

	slwt_a = seg6_local_lwtunnel(a);
	slwt_b = seg6_local_lwtunnel(b);

	if (slwt_a->action != slwt_b->action)
		return 1;

	if (slwt_a->desc->attrs != slwt_b->desc->attrs)
		return 1;

	for (i = 0; i < SEG6_LOCAL_MAX + 1; i++) {
		if (slwt_a->desc->attrs & (1 << i)) {
			param = &seg6_action_params[i];
			if (param->cmp(slwt_a, slwt_b))
				return 1;
		}
	}

	return 0;
}

static const struct lwtunnel_encap_ops seg6_local_ops = {
	.build_state	= seg6_local_build_state,
	.destroy_state	= seg6_local_destroy_state,
	.input		= seg6_local_input,
	.fill_encap	= seg6_local_fill_encap,
	.get_encap_size	= seg6_local_get_encap_size,
	.cmp_encap	= seg6_local_cmp_encap,
	.owner		= THIS_MODULE,
};

int __init seg6_local_init(void)
{
	int ret;

	ret = register_pernet_subsys(&seg6_net_ops);
	if (ret != 0) {
		pr_err("%s: init nets failed\n", __func__);
		return ret;
	}

	return lwtunnel_encap_add_ops(&seg6_local_ops,
				      LWTUNNEL_ENCAP_SEG6_LOCAL);
}

void seg6_local_exit(void)
{
	lwtunnel_encap_del_ops(&seg6_local_ops, LWTUNNEL_ENCAP_SEG6_LOCAL);
	unregister_pernet_subsys(&seg6_net_ops);
}
