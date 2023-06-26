
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/host_ops.h>
#include <uapi/asm/dpdkio.h>


/* XXX: shoud be a list */
#define MAX_DPDK_PORTS	4
static int dpdk_ports[MAX_DPDK_PORTS];	/* dpdk ports */
static int dpdk_nports;

static int __init dpdkio_append_dpdk_port(char *str)
{
	long port;
	int ret;

	if (dpdk_nports >= MAX_DPDK_PORTS) {
		pr_err("too many dpdk ports (> %d)\n", dpdk_nports);
		return -EINVAL;
	}

	pr_info("add dpdk port %s\n", str);
	ret = kstrtol(str, 00, &port);
	if (ret) {
		pr_err("failed to add dpdk port %s: %ld\n", str, port);
		return -EINVAL;
	}

	dpdk_ports[dpdk_nports++] = port;
	return 0;
}
early_param("lkl_dpdkio", dpdkio_append_dpdk_port);


/* dpdkio device */
struct dpdkio_dev {
	struct list_head	list;

	int			portid;	/* dpdk port id */
	struct net_device	*dev;	/* netdevice */

	struct lkl_dpdkio_slot	txslots[LKL_DPDKIO_SLOT_NUM];
	struct lkl_dpdkio_slot	rxslots[LKL_DPDKIO_SLOT_NUM];
	uint32_t		txhead;
	uint32_t		rxhead;

	/* txslots and rxslots are managed in a skimped circular queue
	 * manner; it does not have `tail`, because releasing mbuf
	 * (TX) and skb (RX) is done in a asynchronous manner. For
	 * transmitting or receiving a pakcet, xxslots[xxhead] is
	 * used. If xxslots[xxhead] is still being used (mbuf or skb
	 * is not NULL), it means slot is full, wait.
	 */

	/* tx */
#define DPDKIO_TX_MAX_BATCH	16
	uint8_t 		slot_batch_count; /* # of pkts on tx batch */
	struct lkl_dpdkio_slot *slot_batch[DPDKIO_TX_MAX_BATCH + 1];
	/* batch of packet slots to be transmitted */

	/* rx */
	int			irq;		/* rx interrupt number */
	int			irq_ack_fd;	/* eventfd for ack irq */
	struct napi_struct	napi;

	/* skb queue to be released */
	struct lkl_dpdkio_ring free_skb_ring;
};

static struct dpdkio_dev *dpdk_devs[MAX_DPDK_PORTS];

static inline struct dpdkio_dev *dpdkio_dev_get(int portid)
{
	return dpdk_devs[portid];
}


static void dpdkio_check_link_status(struct dpdkio_dev *dpdk)
{
	int linkup;

	if (netif_carrier_ok(dpdk->dev))
		return;

	linkup = lkl_ops->dpdkio_ops->get_link_status(dpdk->portid);

	if (linkup && !netif_carrier_ok(dpdk->dev)) {
		pr_info("%s Link Up\n", netdev_name(dpdk->dev));
		netif_carrier_on(dpdk->dev);
	} else if (!linkup && netif_carrier_ok(dpdk->dev)) {
		pr_info("%s Link Down\n", netdev_name(dpdk->dev));
		netif_carrier_off(dpdk->dev);
	}
}

/* XXX: We need work struct for updating link status like ixgbe_watchdog */
#if 0
static void dpdkio_service_task(struct work_struct *work)
{
	struct dpdkio_dev *dpdk = container_of(work,
					       struct dpdkio_dev,
					       service_task);
}
#endif


/* net device ops */

static int dpdkio_open(struct net_device *dev)
{
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	int ret;

	ret = lkl_ops->dpdkio_ops->start(dpdk->portid);
	if (ret < 0)
		return ret;

	ret = netif_set_real_num_tx_queues(dev, 1);	/* XXX */
	if (ret) {
		pr_err("netif_set_real_numx_tx_queues failed: %d\n", ret);
		return ret;
	}

	ret = netif_set_real_num_rx_queues(dev, 1);
	if (ret) {
		pr_err("netif_set_real_numx_rx_queues failed: %d\n", ret);
		return ret;
	}

	dpdkio_check_link_status(dpdk);

	lkl_ops->dpdkio_ops->enable_rx_interrupt(dpdk->portid);
	napi_enable(&dpdk->napi);

	return 0;
}

static int dpdkio_close(struct net_device *dev)
{
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	int ret;

	ret = lkl_ops->dpdkio_ops->stop(dpdk->portid);
	if (ret < 0)
		return ret;

	napi_disable(&dpdk->napi);

	netif_carrier_off(dev);

	return 0;
}

#define MAX_FREE_SKB_BULK_NUM 8

static void dpdkio_free_tx_skb(struct dpdkio_dev *dpdk)
{
	struct lkl_dpdkio_ring *r = &dpdk->free_skb_ring;
	struct sk_buff *skb;
	unsigned int b, n;

	b = lkl_dpdkio_ring_read_avail(r);
	b = b > MAX_FREE_SKB_BULK_NUM ? MAX_FREE_SKB_BULK_NUM : b;
	if (!b) {
		return;
	}

	for (n = 0; n < b; n++) {
		skb = r->ptrs[(r->tail + n) & LKL_DPDKIO_RING_MASK];
		dev_kfree_skb_any(skb);
	}

	lkl_dpdkio_ring_read_next(r, b);
}

static void dpdkio_fill_slot_tx_offload(struct sk_buff *skb,
					struct lkl_dpdkio_slot *slot)
{
	unsigned char *l2, *l3, *l4, *l5;
	struct tcphdr *tcp;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return;

	slot->tso_segsz = 0;
	slot->eth_protocol = skb->protocol;

	l2 = skb_mac_header(skb);
	l3 = skb_network_header(skb);
	l4 = skb_transport_header(skb);

	switch(skb->csum_offset) {

	case offsetof(struct tcphdr, check):
		slot->ip_protocol = IPPROTO_TCP;
		tcp = (struct tcphdr *)l4;
		l5 = l4 + (tcp->doff << 2);

		/* XXX: we need to negotiate offload between kernel and dpdk */
		if (skb_shinfo(skb)->gso_size)
			slot->tso_segsz = skb_shinfo(skb)->gso_size;
		else
			slot->tso_segsz = skb->len;

		break;

	case offsetof(struct udphdr, check):
		slot->ip_protocol = IPPROTO_UDP;
		l5 = l4 + sizeof(struct udphdr);
		break;

	default:
		slot->ip_protocol = 0;
		l5 = NULL;
	}

	slot->l2_len = l3 - l2;
	slot->l3_len = l4 - l3;
	slot->l4_len = (l5) ? l5 - l4 : 0;
}

static struct lkl_dpdkio_slot *dpdkio_get_free_tx_slot(struct dpdkio_dev *dpdk)
{
	struct lkl_dpdkio_slot *s, *slot = NULL;
	uint32_t txhead;

	txhead = dpdk->txhead;

	do {
		s = &dpdk->txslots[txhead];
		if (READ_ONCE(s->skb) == NULL) {
			slot = s;
			break;
		}
		/* advance the txhead */
		txhead = (txhead + 1) & LKL_DPDKIO_SLOT_MASK;
	} while (txhead != dpdk->txhead);

	if (slot)
		dpdk->txhead = txhead;

	return slot;
}

static netdev_tx_t dpdkio_xmit_frame(struct sk_buff *skb,
				     struct net_device *dev)
{
	struct netdev_queue *txq = skb_get_tx_queue(dev, skb);
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	struct skb_frag_struct *frag;
	struct lkl_dpdkio_slot *slot;
	struct lkl_dpdkio_seg *seg;
	unsigned int data_len, size, pkt_len;
	unsigned short f;
	int ret;

	/* XXX: we assume that there is no race conditions on the
	 * dpdkio TX path because of LKL */

	/* XXX: free TXed skbs. should it be workqueue??? */
	dpdkio_free_tx_skb(dpdk);

#ifdef DUMP_TX
 	pr_info("\n========== dump tx ==========\n");
	skb_dump(KERN_WARNING, skb, false);
#endif

	slot = dpdkio_get_free_tx_slot(dpdk);
	if (!slot) {
		/* slot is not released yet */
		panic("tx slot is full\n");
		//dev->stats.tx_dropped++;
		return NETDEV_TX_BUSY;
	}

	/* let's fill the slot */
	pkt_len = skb->len;
	slot->pkt_len = skb->len;
	slot->nsegs = skb_shinfo(skb)->nr_frags + 1;
	if (unlikely(slot->nsegs > LKL_DPDKIO_MAX_SEGS)) {
		net_err_ratelimited("too many frags %d (> %d)\n",
				    slot->nsegs, LKL_DPDKIO_MAX_SEGS);
		goto out_drop;
	}

	/* the first segment, usually header */
	seg = &slot->segs[0];
	seg->buf_addr = (uintptr_t)skb->head;
	seg->buf_len = skb_end_offset(skb);
	seg->data_off = skb_headroom(skb);
	seg->data_len = skb_headlen(skb);

	/* append frags */
	data_len = skb->data_len;
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++) {
		unsigned int buf_len;

		seg = &slot->segs[1 + f];
		frag = &skb_shinfo(skb)->frags[f];
		size = skb_frag_size(frag);
		buf_len = size + frag->page_offset;

		seg->buf_addr = (uintptr_t)page_address(frag->page.p);
		seg->buf_len = (buf_len <= PAGE_SIZE) ?
			PAGE_SIZE : (buf_len & PAGE_MASK) + PAGE_SIZE;
 		seg->data_off = frag->page_offset;
		seg->data_len = size;

		data_len -= size;
	}

	if (unlikely(data_len)) {
		net_err_ratelimited("remaining %u bytes!\n", data_len);
		dev->stats.tx_dropped++;
		goto out_drop;
	}

	dpdkio_fill_slot_tx_offload(skb, slot);

	/* set skb to slot to free skb when mbuf is released */
	slot->skb = skb;

	/* batch the tx packets*/
	/* append this packet to the end of batch */
	dpdk->slot_batch[dpdk->slot_batch_count] = slot;
	dpdk->slot_batch_count++;


	/* xmit batched packets */

	if (dpdk->slot_batch_count >= DPDKIO_TX_MAX_BATCH ||
	    netif_xmit_stopped(txq) || !netdev_xmit_more()) {
		ret = lkl_ops->dpdkio_ops->tx(dpdk->portid,
					      dpdk->slot_batch,
					      dpdk->slot_batch_count);
		if (unlikely(ret == 0)) {
			net_err_ratelimited("dpdkio tx failed\n");
			dev->stats.tx_carrier_errors += dpdk->slot_batch_count;
		}

		dpdk->slot_batch_count = 0;
	}


	dev->stats.tx_packets++;
	dev->stats.tx_bytes += pkt_len;

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static bool dpdkio_recycle_rx_slot(int portid, struct lkl_dpdkio_slot *slot)
{
	struct sk_buff *skb;

	if (slot->skb == NULL)
		return true;

	skb = slot->skb;

	if (refcount_read(&skb->users) == 1) {
		/* skb is attached, but it is already consumed. relelase
		 * skb and associating mbuf */
		kfree_skb(skb);
		slot->skb = NULL;

		if (slot->mbuf) {
			lkl_ops->dpdkio_ops->mbuf_free(portid, slot->mbuf);
			slot->mbuf = NULL;
		}
		return true;
	}

	return false;
}

static void dpdkio_rx_cksum(struct dpdkio_dev *dpdk,
			    struct lkl_dpdkio_slot *slot, struct sk_buff *skb)
{
	skb_checksum_none_assert(skb);	/* XXX: RX checksum offload? */

	if (slot->rx_ip_cksum_result == LKL_DPDKIO_RX_IP_CKSUM_GOOD) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		return;
	}

	if (slot->rx_ip_cksum_result == LKL_DPDKIO_RX_IP_CKSUM_BAD ||
	    slot->rx_ip_cksum_result == LKL_DPDKIO_RX_IP_CKSUM_NONE)
		dpdk->dev->stats.rx_errors++;
}

struct sk_buff *dpdkio_rx_slot_to_skb(struct dpdkio_dev *dpdk,
				      struct lkl_dpdkio_slot *slot)
{

	struct sk_buff *skb;
	unsigned int gso_type = 0;
	uint32_t truesize;
	int n;

	/* build an skb to around the first segment
	 * XXX: really there is tail room for shared_info?
	 */
	truesize = (SKB_DATA_ALIGN(slot->segs[0].buf_len));

	skb = build_skb((void *)(slot->segs[0].buf_addr), truesize);
	if (!skb)
		return NULL;

	skb_reserve(skb, slot->segs[0].data_off);
	__skb_put(skb, slot->segs[0].data_len);

	/* Note, increment refcnt of skb. By this trick, skb is not
	 * free()ed after a socket and other consumes this skb. They
	 * calls kfree_skb(), and it calls skb_unref(), and then it
	 * decrements the refcnt of skb. So, we can determine the skb
	 * (and associating mbuf) can be freed if refcnt is 1 */
	skb_get(skb);

	for (n = 1; n < slot->nsegs; n++) {
		struct lkl_dpdkio_seg *seg;
		struct page *page;

		seg = &slot->segs[n];
		page = pfn_to_page(seg->buf_addr >> PAGE_SHIFT);
		/* Note: in lkl, va = pa (asm-generic/io.h and
		 * page.h), so there is no need to use
		 * phys_to_virt. */

		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
				seg->data_off, seg->data_len, seg->buf_len);
	}

	dpdkio_rx_cksum(dpdk, slot, skb);

	if (slot->ip_protocol == IPPROTO_TCP && slot->tso_segsz) {
		if (slot->eth_protocol == htons(ETH_P_IP))
			gso_type = SKB_GSO_TCPV4;
		else if (slot->eth_protocol == htons(ETH_P_IPV6))
			gso_type = SKB_GSO_TCPV6;
		/* XXX: UDP GSO?? */

		skb_shinfo(skb)->gso_size = slot->tso_segsz;
		skb_shinfo(skb)->gso_type = gso_type;
	}


	skb_reset_mac_header(skb);
	if (slot->l2_len)
		skb_set_network_header(skb, slot->l2_len);
	if (slot->l2_len && slot->l3_len)
		skb_set_transport_header(skb, slot->l2_len + slot->l3_len);

	skb->protocol = eth_type_trans(skb, dpdk->dev);

	slot->skb = skb;

	return skb;
}

int dpdkio_poll(struct napi_struct *napi, int budget)
{
	struct dpdkio_dev *dpdk = container_of(napi, struct dpdkio_dev, napi);
	struct lkl_dpdkio_slot *slots[LKL_DPDKIO_MAX_BURST], *slot;
	struct net_device *dev = dpdk->dev;
	uint64_t nr_bytes, nr_pkts;
	uint32_t head, b;
	int n, i, nr_rx;

	head = dpdk->rxhead;
	b = min(budget, LKL_DPDKIO_MAX_BURST);

	/* obtain free slots while walking around the rxslot ring */
	for (i = 0, n = 0; n < LKL_DPDKIO_SLOT_NUM; n++) {
		slot = &dpdk->rxslots[head];
		if (dpdkio_recycle_rx_slot(dpdk->portid, slot)) {
			slots[i++] = slot;
			if (i >= b)
				break;
		}

		head = (head + 1) & LKL_DPDKIO_SLOT_MASK;
	}

	if (unlikely(i == 0)) {
		panic("no free rx slots\n");
		return 0;
	}

	/* advnce rxhead */
	dpdk->rxhead = (head + 1) & LKL_DPDKIO_SLOT_MASK;

	/* receive packets into `slots` */
	nr_rx = lkl_ops->dpdkio_ops->rx(dpdk->portid, slots, i);

	/* build skb */
	nr_bytes = 0;
	nr_pkts = 0;
	for (n = 0; n < nr_rx; n++) {
		struct sk_buff *skb;

		skb = dpdkio_rx_slot_to_skb(dpdk, slots[n]);
		if (unlikely(!skb)) {
			dev->stats.rx_dropped++;
			continue;
		}

		napi_gro_receive(&dpdk->napi, skb);

		nr_pkts++;
		nr_bytes += slots[n]->pkt_len;
	}

	dev->stats.rx_packets += nr_pkts;
	dev->stats.rx_bytes += nr_bytes;

	/* exit polling mode */
	napi_complete_done(napi, nr_pkts);
	lkl_ops->dpdkio_ops->enable_rx_interrupt(dpdk->portid);

	return nr_pkts;
}

static irqreturn_t dpdkio_handle_irq(int irq, void *data)
{
	struct dpdkio_dev *dpdk = data;

	/* disalbe rx irq and ack this itnerrupt */
	lkl_ops->dpdkio_ops->disable_rx_interrupt(dpdk->portid);
	lkl_ops->dpdkio_ops->ack_rx_interrupt(dpdk->irq_ack_fd);

	/* go to napi context */
	napi_schedule(&dpdk->napi);

	return IRQ_HANDLED;
}

static const struct net_device_ops dpdkio_netdev_ops = {
	.ndo_open	= dpdkio_open,
	.ndo_stop	= dpdkio_close,
	.ndo_start_xmit	= dpdkio_xmit_frame,
};


static int dpdkio_init_netdev(struct net_device *dev)
{
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	char mac[ETH_ALEN];
	int ret;

	/* much based on ixgbe_probe() */

	dev->netdev_ops = &dpdkio_netdev_ops;
	/* XXX: ethtool_ops */

	snprintf(dev->name, sizeof(dev->name), "dpdkio%d", dpdk->portid);

	dev->features = (NETIF_F_SG |
			 NETIF_F_TSO |
			 NETIF_F_TSO6 |
			 NETIF_F_HW_CSUM |
			 NETIF_F_RXCSUM |
			 NETIF_F_LRO);
	dev->hw_features = dev->features;

	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = 9216;

	lkl_ops->dpdkio_ops->get_macaddr(dpdk->portid, mac);
	memcpy(dev->dev_addr, mac, dev->addr_len);

	if (!is_valid_ether_addr(dev->dev_addr)) {
		pr_err("invalid MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	ret = register_netdev(dev);
	if (ret) {
		pr_err("failed to register netdevice: %d\n", ret);
		return ret;
	}

	netif_carrier_off(dev);

	netif_napi_add(dev, &dpdk->napi, dpdkio_poll, LKL_DPDKIO_MAX_BURST);

	return 0;
}

static int dpdkio_init_dev(int port)
{

	struct dpdkio_dev *dpdk;
	struct net_device *dev;
	size_t rx_mem_size;
	int nb_rxd, nb_txd;
	int ret = 0, n;

	dev = alloc_etherdev(sizeof(struct dpdkio_dev));
	if (!dev) {
		pr_err("failed to alloc netdev\n");
		return -ENOMEM;
	}

	dpdk = netdev_priv(dev);
	memset(dpdk, 0, sizeof(*dpdk));
	dpdk->dev = dev;
	dpdk->portid = port;
	

	for (n = 0; n < LKL_DPDKIO_SLOT_NUM; n++) {
		dpdk->txslots[n].portid = port;
		dpdk->rxslots[n].portid = port;
	}

	dpdk_devs[port] = dpdk;

	ret = lkl_ops->dpdkio_ops->init_port(dpdk->portid);
	if (ret < 0) {
		pr_err("failed to init underlaying dpdkio port\n");
		goto free_dpdkio;
	}

	/* prepare memory region for receiving packets */
	for (rx_mem_size = 0; rx_mem_size < LKL_DPDKIO_RX_MEMPOOL_SIZE;) {
		size_t size = MAX_ORDER_NR_PAGES * PAGE_SIZE;
		struct page *page;
		void *mem;

		page = alloc_pages(GFP_KERNEL, MAX_ORDER - 1);
		if (!page) {
			pr_err("failed to alloc %lu-bytes pages \n", size);
			goto free_dpdkio;
		}

		mem = page_address(page);
		ret = lkl_ops->dpdkio_ops->add_rx_region(dpdk->portid,
							 (uintptr_t)mem, size);
		if (ret) {
			pr_err("failed to add rx mem region\n");
			goto free_dpdkio;
		}

		rx_mem_size += size;
	}

	ret = lkl_ops->dpdkio_ops->init_rx_irq(dpdk->portid,
					       &dpdk->irq,
					       &dpdk->irq_ack_fd);

	nb_rxd = LKL_DPDKIO_DESC_NUM;
	nb_txd = LKL_DPDKIO_DESC_NUM;
	ret = lkl_ops->dpdkio_ops->setup(dpdk->portid, &nb_rxd, &nb_txd);
	if (ret < 0)
		goto free_dpdkio;

	ret = dpdkio_init_netdev(dev);
	if (ret < 0)
		goto free_dpdkio;

	/* init rx irq */
	ret = request_irq(dpdk->irq, dpdkio_handle_irq, 0, netdev_name(dev),
			  dpdk);

	pr_info("netdev %s nb_rxd=%d nb_txd=%d irq=%d loaded\n",
		netdev_name(dev), nb_txd, nb_rxd, dpdk->irq);

	return ret;

free_dpdkio:
	kfree(dpdk);
	return ret;
}

static void dpdkio_free_skb(int portid, void *skb)
{
	struct dpdkio_dev *dpdk = dpdkio_dev_get(portid);
	struct lkl_dpdkio_ring *r = &dpdk->free_skb_ring;

	if (unlikely(lkl_dpdkio_ring_full(r)))
		panic("skb free ring full on port %d!\n", portid);

	r->ptrs[r->head] = skb;
	lkl_dpdkio_ring_write_next(r, 1);
}

static int __init dpdkio_init(void)
{
	int n, ret = 0;

	if (!lkl_ops->dpdkio_ops)
		return 0;

	pr_info("start to init lkl dpdkio\n");

	lkl_ops->dpdkio_ops->free_skb = dpdkio_free_skb;

	for (n = 0; n < dpdk_nports; n++) {
		ret = dpdkio_init_dev(dpdk_ports[n]);
		if (ret < 0) {
			pr_err("failed to init dpdk port %d\n", dpdk_ports[n]);
			return ret;
		}
	}

	pr_info("lkl dpdkio init done\n");

	return ret;
}

device_initcall(dpdkio_init);
