
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <asm/host_ops.h>
#include <uapi/asm/dpdkio.h>


static struct list_head dpdkio_list;	/* struct dpdkio_dev */

/* dpdkio device */
struct dpdkio_dev {
	struct list_head	list;

	int			portid;	/* dpdk port id */
	struct net_device	*dev;	/* netdevice */

	void	*rx_mem_region;	/* mempool region for rx */

	struct lkl_dpdkio_pkt	txslots[LKL_DPDKIO_SLOT_NUM];
	struct lkl_dpdkio_pkt	rxslots[LKL_DPDKIO_SLOT_NUM];
	uint32_t		txhead;
	uint32_t		rxhead;

	/* txslots and rxslots are managed in a skimped circular queue
	 * manner; it does not have `tail`, because releasing mbuf
	 * (TX) and skb (RX) is done in a asynchronous manner. For
	 * transmitting or receiving a pakcet, xxslots[xxhead] is
	 * used. If xxslots[xxhead] is still being used (mbuf or skb
	 * is not NULL), it means slot is full, wait.
	 */
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

	return 0;
}

static int dpdkio_close(struct net_device *dev)
{
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	int ret;

	ret = lkl_ops->dpdkio_ops->stop(dpdk->portid);
	if (ret < 0)
		return ret;

	netif_carrier_off(dev);

	return 0;
}

static void dpdkio_debug_pkt(struct lkl_dpdkio_pkt *pkt, const char *prefix)
{
	pr_info("%s: nsegs=%d pkt_len=%u skb=0x%lx\n",
		prefix, pkt->nsegs, pkt->pkt_len, (uintptr_t)pkt->skb);
}

static netdev_tx_t dpdkio_xmit_frame(struct sk_buff *skb,
				     struct net_device *dev)
{
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	struct skb_frag_struct *frag;
	struct lkl_dpdkio_pkt *pkt;
	unsigned int data_len, size;
	unsigned short f;
	struct iovec *seg;
	int ret;

	/* XXX: we assume that there is no race conditions on the
	 * dpdkio TX path because of LKL */

	pkt = &dpdk->txslots[dpdk->txhead];
	if (READ_ONCE(pkt->skb)) {
		/* slot is not released yet */
		dev->stats.tx_dropped++;
		return NETDEV_TX_BUSY;
	}

	/* let's fill the pkt slot */
	pkt->pkt_len = skb->len;
	pkt->nsegs = skb_shinfo(skb)->nr_frags + 1;
	if (unlikely(pkt->nsegs > LKL_DPDKIO_MAX_SEGS)) {
		net_err_ratelimited("too many frags %d (> %d)\n",
				    pkt->nsegs, LKL_DPDKIO_MAX_SEGS);
		goto out_drop;
	}

	/* the first segment, usually header */
	seg = &pkt->segs[0];
	seg->iov_base = skb->data;	/* yeah, we are in LKL, va == pa */
	seg->iov_len = skb_headlen(skb);

	/* append frags */
	data_len = skb->data_len;
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++) {
		seg = &pkt->segs[1 + f];
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

	/* set skb to pkt to free skb when mbuf is released */
	pkt->skb = skb;

	/* XXX: pass the pkt slot to dpdk backend. we need to batch
	 * packets. How to handle that? check enqueued packets in
	 * qdisc? or check xmit_more?
	 */
	ret = lkl_ops->dpdkio_ops->tx(dpdk->portid, pkt, 1);
	if (unlikely(ret))
		dev->stats.tx_carrier_errors++;

	/* advance the txhead */
	dpdk->txhead = (dpdk->txhead + 1) & LKL_DPDKIO_SLOT_MASK;
	/* XXX: do we need memory barrier? */

	dpdkio_debug_pkt(pkt, "tx");

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
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
			 NETIF_F_RXCSUM |
			 NETIF_F_HW_CSUM |
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
					       LKL_DPDKIO_MEMPOOL_SIZE);
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


	pr_info("netdev %s, nb_rxd=%d nb_txd=%d, rx mempool 0x%lx, loaded\n",
		netdev_name(dev), nb_txd, nb_rxd,
		(uintptr_t)dpdk->rx_mem_region);

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

	ret = dpdkio_init_dev(0); /* XXX: first port for the time being */
	if (ret < 0)
		return ret;

	pr_info("lkl dpdkio init done\n");

	return ret;
}

device_initcall(dpdkio_init);
