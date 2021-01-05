
#define pr_fmt(fmt) "dpdkio:%s:" fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <asm/host_ops.h>
#include <uapi/asm/dpdkio.h>


static struct list_head dpdkio_list;	/* struct dpdkio_dev */

/* dpdkio device */

#define DPDKIO_SLOT_NUM		1024
#define DPDKIO_MEMPOOL_SIZE	(4096 * DPDKIO_SLOT_NUM)

struct dpdkio_dev {
	struct list_head	list;

	void	*rx_mempool;	/* mempool region for rx */

	struct lkl_dpdkio_pkt	txslots[DPDKIO_SLOT_NUM];
	struct lkl_dpdkio_pkt	rxslots[DPDKIO_SLOT_NUM];

	struct net_device	*dev;
};


static void dpdkio_prepare(void)
{
	INIT_LIST_HEAD(&dpdkio_list);
}


/* net device ops */

static int dpdkio_open(struct net_device *netdev)
{
	return 0;
}

static int dpdkio_close(struct net_device *netdev)
{
	return 0;
}

static netdev_tx_t dpdkio_xmit_frame(struct sk_buff *skb,
				     struct net_device *netdev)
{
	return NETDEV_TX_OK;
}

static const struct net_device_ops dpdkio_netdev_ops = {
	.ndo_open	= dpdkio_open,
	.ndo_stop	= dpdkio_close,
	.ndo_start_xmit	= dpdkio_xmit_frame,
};

static int dpdkio_init_netdev(struct net_device *dev)
{
	char mac[ETH_ALEN];
	int ret;

	/* much based on ixgbe_probe() */

	dev->netdev_ops = &dpdkio_netdev_ops;
	/* XXX: ethtool_ops */

	strlcpy(dev->name, "dpdkio", sizeof(dev->name));

	dev->features = (NETIF_F_SG |
			 NETIF_F_TSO |
			 NETIF_F_TSO6 |
			 NETIF_F_RXCSUM |
			 NETIF_F_HW_CSUM |
			 NETIF_F_LRO);
	dev->hw_features = dev->features;

	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = 9216;

	lkl_ops->dpdkio_ops->get_macaddr(mac);
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

static int dpdkio_init_dev(void)
{
	struct dpdkio_dev *dpdk;
	struct net_device *dev;
	int ret = 0;

	dev = alloc_etherdev(sizeof(struct dpdkio_dev));
	if (!dev) {
		pr_err("failed to alloc netdev\n");
		return -ENOMEM;
	}

	dpdk = netdev_priv(dev);
	memset(dpdk, 0, sizeof(*dpdk));
	dpdk->dev = dev;

	/* prepare rx pool */
	dpdk->rx_mempool = kmalloc(DPDKIO_MEMPOOL_SIZE, GFP_KERNEL);
	if (!dpdk->rx_mempool) {
		pr_err("failed to allocate memory for rx mempool\n");
		ret = -ENOMEM;
		goto free_dpdkio;
	}
	memset(dpdk->rx_mempool, 0, DPDKIO_MEMPOOL_SIZE);

	ret = lkl_ops->dpdkio_ops->init_rxring(dpdk->rx_mempool,
					       DPDKIO_MEMPOOL_SIZE);
	if (ret < 0)
		goto free_rx_mempool;

	ret = lkl_ops->dpdkio_ops->setup(DPDKIO_SLOT_NUM, DPDKIO_SLOT_NUM);
	if (ret < 0)
		goto free_rx_mempool;

	ret = dpdkio_init_netdev(dev);
	if (ret < 0)
		goto free_rx_mempool;

	return ret;

free_rx_mempool:
	kfree(dpdk->rx_mempool);
free_dpdkio:
	kfree(dpdk);
	return ret;
}

static int __init lkl_dpdkio_init(void)
{
	int ret;

	if (!lkl_ops->dpdkio_ops)
		return 0;

	pr_info("start to init lkl dpdkio\n");

	dpdkio_prepare();

	ret = dpdkio_init_dev();
	if (ret < 0)
		return ret;

	pr_info("lkl dpdkio init done\n");

	return ret;
}

device_initcall(lkl_dpdkio_init);
