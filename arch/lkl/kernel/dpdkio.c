
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


static struct list_head dpdkio_list;	/* struct dpdkio_dev */

/* dpdkio device */
struct dpdkio_dev {
	struct list_head	list;

	int			portid;	/* dpdk port id */
	struct net_device	*dev;	/* netdevice */

	void	*rx_mem_region;	/* mempool region for rx */

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

	int			irq;		/* rx interrupt number */
	int			irq_ack_fd;	/* eventfd for ack irq */
	struct napi_struct	napi;
};

static void dpdkio_prepare(void)
{
	INIT_LIST_HEAD(&dpdkio_list);
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

static void dpdkio_debug_slot(struct lkl_dpdkio_slot *slot, const char *prefix)
{
	int n;

	pr_info("%s: nsegs=%d pkt_len=%u skb=0x%lx\n",
		prefix, slot->nsegs, slot->pkt_len, (uintptr_t)slot->skb);

	for (n = 0; n < slot->nsegs; n++) {
		pr_info("%s: slot->segs[%d] is %ld-bytes\n",
			prefix, n, slot->segs[n].iov_len);
	}
}

static void dpdkio_fill_slot_tx_offload(struct sk_buff *skb,
					struct lkl_dpdkio_slot *slot)
{
	unsigned char *l2, *l3, *l4, *l5;
	struct tcphdr *tcp;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		pr_info("not checksum partial\n");
		return;
	}

	err = skb_cow_head(skb, 0);
	if (err < 0) {
		pr_info("skb_cow_head failed\n");
		return;
	}

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

		pr_info("tcp\n");
		break;

	case offsetof(struct udphdr, check):
		slot->ip_protocol = IPPROTO_UDP;
		l5 = l4 + sizeof(struct udphdr);
		pr_info("udp\n");
		break;

	default:
		pr_info("fall through\n");
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
		if (!s->skb) {
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
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	struct skb_frag_struct *frag;
	struct lkl_dpdkio_slot *slot;
	unsigned int data_len, size, pkt_len;
	struct iovec *seg;
	unsigned short f;
	int ret;

	/* XXX: we assume that there is no race conditions on the
	 * dpdkio TX path because of LKL */

	pr_info("try to xmit pkt\n");

	pr_info("gso_size is %u type is %u\n",
		skb_shinfo(skb)->gso_size, skb_shinfo(skb)->gso_type);

	slot = dpdkio_get_free_tx_slot(dpdk);
	if (!slot) {
		/* slot is not released yet */
		panic("tx slot is full\n");
		//dev->stats.tx_dropped++;
		return NETDEV_TX_BUSY;
	}

	/* let's fill the slot slot */
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
	seg->iov_base = skb->data;	/* yeah, we are in LKL, va == pa */
	seg->iov_len = skb_headlen(skb);

	/* append frags */
	data_len = skb->data_len;
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++) {
		seg = &slot->segs[1 + f];
		frag = &skb_shinfo(skb)->frags[f];
		size = skb_frag_size(frag);

		seg->iov_base = skb_frag_address(frag);
		seg->iov_len = size;

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

	/* XXX: pass the slot slot to dpdk backend. we need to batch
	 * packets. How to handle that? check enqueued packets in
	 * qdisc? or check xmit_more?
	 */
	ret = lkl_ops->dpdkio_ops->tx(dpdk->portid, slot, 1);
	if (unlikely(ret == 0)) {
		pr_err("dpdkio tx failed, returns 0 !!!!!!!!!!!!!!!!!!!\n");
		dev->stats.tx_carrier_errors++;
	}

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += pkt_len;
	pr_info("tx pkt cnt %lu\n", dev->stats.tx_packets);


	dpdkio_debug_slot(slot, "tx");

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(skb);

	pr_err("xmit failed\n");

	return NETDEV_TX_OK;
}

static bool dpdkio_recycle_rx_slot(struct lkl_dpdkio_slot *slot)
{
	struct sk_buff *skb;

	if (slot->skb == NULL)
		return true;

	skb = slot->skb;

	if (refcount_read(&skb->users) == 1) {
		/* skb is attached, but it is already consumed. free it */
		kfree_skb(skb);
		slot->skb = NULL;

		/* XXX: no need to check the existance of mbuf? */
		if (slot->mbuf) {
			lkl_ops->dpdkio_ops->mbuf_free(slot->mbuf);
			slot->mbuf = NULL;
			pr_info("!!!!!!!!!! release mbuf and reuse it!!\n");
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
		pr_info("good checksum\n");
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
	struct iovec *seg;
	struct page *page;
	uint64_t offset, phy_addr;
	unsigned int gso_type = 0;
	uint32_t truesize;
	int n;

	/* build an skb to around the first segment
	 * XXX: really there is tail room for shared_info?
	 */
	truesize = (SKB_DATA_ALIGN(slot->segs[0].iov_len) +
		    SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));


	skb = build_skb(slot->segs[0].iov_base, truesize);
	if (!skb)
		return NULL;


	__skb_put(skb, slot->segs[0].iov_len);

	/* Note, increment refcnt of skb. By this trick, skb is not
	 * free()ed after a socket and other consumes this skb. They
	 * calls kfree_skb(), and it calls skb_unref(), and then it
	 * decrements the refcnt of skb. So, we can determine the skb
	 * (and associating mbuf) can be freed if refcnt is 1 */
	skb_get(skb);

	for (n = 1; n < slot->nsegs; n++) {
		seg = &slot->segs[n];
		phy_addr = (uintptr_t)seg->iov_base;

		/* Note: in lkl, va = pa (asm-generic/io.h and
		 * page.h), so there is no need to use
		 * phys_to_virt. */
		page = virt_to_page(phys_to_virt(phy_addr));
		offset = phys_to_virt(phy_addr) - page_address(page);

		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
				offset, seg->iov_len, seg->iov_len);
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

		/* XXX: copied from virtio_net_hdr_to_skb() */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	skb->protocol = eth_type_trans(skb, dpdk->dev);

	slot->skb = skb;

	pr_info("skb->len is %u skb->data_len is %u\n",
		skb->len, skb->data_len);
	pr_info("gso_size is %u type is %u\n",
		skb_shinfo(skb)->gso_size, skb_shinfo(skb)->gso_type);


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
		if (dpdkio_recycle_rx_slot(slot)) {
			slots[i++] = slot;
			if (i > b)
				break;
		}

		head = (head + 1) & LKL_DPDKIO_SLOT_MASK;
	}

	if (i == 0) {
		pr_err("no free rx pages!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
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

		pr_info("recv %u-byte pkt\n", skb->len);
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

#if 1
	dev->features = (NETIF_F_SG |
			 NETIF_F_TSO |
			 NETIF_F_TSO6 |
			 NETIF_F_HW_CSUM |
			 NETIF_F_RXCSUM);
#else
	dev->features = (NETIF_F_HW_CSUM |
			 NETIF_F_RXCSUM);
#endif
	/* XXX: we needs NETIF_F_LRO */
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

	netif_napi_add(dev, &dpdk->napi, dpdkio_poll, 64);

	return 0;
}

static int dpdkio_init_dev(int port)
{
	struct dpdkio_dev *dpdk;
	struct net_device *dev;
	int nb_rxd, nb_txd;
	int ret = 0;

	dev = alloc_etherdev(sizeof(struct dpdkio_dev));
	if (!dev) {
		pr_err("failed to alloc netdev\n");
		return -ENOMEM;
	}

	dpdk = netdev_priv(dev);
	memset(dpdk, 0, sizeof(*dpdk));
	dpdk->dev = dev;
	dpdk->portid = port;

	ret = lkl_ops->dpdkio_ops->init_port(dpdk->portid);
	if (ret < 0) {
		pr_err("failed to init underlaying dpdkio port\n");
		goto free_dpdkio;
	}

	/* prepare rx pool */
	dpdk->rx_mem_region = kmalloc(LKL_DPDKIO_MEMPOOL_SIZE, GFP_KERNEL);
	if (!dpdk->rx_mem_region) {
		pr_err("failed to allocate memory for rx mempool %d-byte\n",
		       LKL_DPDKIO_MEMPOOL_SIZE);
		ret = -ENOMEM;
		goto free_dpdkio;
	}
	memset(dpdk->rx_mem_region, 0, LKL_DPDKIO_MEMPOOL_SIZE);

	ret = lkl_ops->dpdkio_ops->init_rxring(dpdk->portid,
					       (uintptr_t)dpdk->rx_mem_region,
					       LKL_DPDKIO_MEMPOOL_SIZE,
					       &dpdk->irq,
					       &dpdk->irq_ack_fd);
	if (ret < 0)
		goto free_rx_mem_region;

	nb_rxd = LKL_DPDKIO_SLOT_NUM;
	nb_txd = LKL_DPDKIO_SLOT_NUM;
	ret = lkl_ops->dpdkio_ops->setup(dpdk->portid, &nb_rxd, &nb_txd);
	if (ret < 0)
		goto free_rx_mem_region;

	ret = dpdkio_init_netdev(dev);
	if (ret < 0)
		goto free_rx_mem_region;

	/* init rx irq */
	ret = request_irq(dpdk->irq, dpdkio_handle_irq, 0, netdev_name(dev),
			  dpdk);

	pr_info("netdev %s nb_rxd=%d nb_txd=%d rxpool 0x%lx irq=%d loaded\n",
		netdev_name(dev), nb_txd, nb_rxd,
		(uintptr_t)dpdk->rx_mem_region, dpdk->irq);

	return ret;

free_rx_mem_region:
	kfree(dpdk->rx_mem_region);
free_dpdkio:
	kfree(dpdk);
	return ret;
}

static void dpdkio_kfree_skb(void *skb)
{
	kfree_skb((struct sk_buff *)skb);
}

static int __init dpdkio_init(void)
{
	int ret;

	if (!lkl_ops->dpdkio_ops)
		return 0;

	pr_info("start to init lkl dpdkio\n");

	dpdkio_prepare();
	lkl_ops->dpdkio_ops->free_skb = dpdkio_kfree_skb;

	ret = dpdkio_init_dev(2); /* XXX: first port for the time being */
	if (ret < 0)
		return ret;

	pr_info("lkl dpdkio init done\n");

	return ret;
}

device_initcall(dpdkio_init);
