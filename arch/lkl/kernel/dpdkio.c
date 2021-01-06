
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

	int	port;		/* dpdk port id */

	void	*rx_mem_region;	/* mempool region for rx */

	struct lkl_dpdkio_pkt	txslots[LKL_DPDKIO_SLOT_NUM];
	struct lkl_dpdkio_pkt	rxslots[LKL_DPDKIO_SLOT_NUM];

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
	struct dpdkio_dev *dpdk = netdev_priv(dev);
	char mac[ETH_ALEN];
	int ret;

	/* much based on ixgbe_probe() */

	dev->netdev_ops = &dpdkio_netdev_ops;
	/* XXX: ethtool_ops */

	snprintf(dev->name, sizeof(dev->name), "dpdkio%d", dpdk->port);

	dev->features = (NETIF_F_SG |
			 NETIF_F_TSO |
			 NETIF_F_TSO6 |
			 NETIF_F_RXCSUM |
			 NETIF_F_HW_CSUM |
			 NETIF_F_LRO);
	dev->hw_features = dev->features;

	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = 9216;

	lkl_ops->dpdkio_ops->get_macaddr(dpdk->port, mac);
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
	dpdk->port = port;

	ret = lkl_ops->dpdkio_ops->init_port(dpdk->port);
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

	ret = lkl_ops->dpdkio_ops->init_rxring(dpdk->port,
					       (uintptr_t)dpdk->rx_mem_region,
					       LKL_DPDKIO_MEMPOOL_SIZE);
	if (ret < 0)
		goto free_rx_mem_region;

	nb_rxd = LKL_DPDKIO_SLOT_NUM;
	nb_txd = LKL_DPDKIO_SLOT_NUM;
	ret = lkl_ops->dpdkio_ops->setup(dpdk->port, &nb_rxd, &nb_txd);
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

static int __init dpdkio_init(void)
{
	int ret;

	if (!lkl_ops->dpdkio_ops)
		return 0;

	pr_info("start to init lkl dpdkio\n");

	dpdkio_prepare();

	ret = dpdkio_init_dev(0); /* XXX: first port for the time being */
	if (ret < 0)
		return ret;

	pr_info("lkl dpdkio init done\n");

	return ret;
}

device_initcall(dpdkio_init);
