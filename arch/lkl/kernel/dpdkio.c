
#define pr_fmt(fmt) "dpdkio: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
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
	struct net		*net;
};


static void dpdkio_prepare(void)
{
	INIT_LIST_HEAD(&dpdkio_list);
}

static int dpdkio_init_dev(void)
{
	struct dpdkio_dev *dpdk;
	struct net_device *dev;
	int ret = 0;

	/* prepare a dpdkio device */
	dpdk = kmalloc(sizeof(*dpdk), GFP_KERNEL);
	if (!dpdk) {
		pr_err("failed to allocate memory\n");
		return -ENOMEM;
	}
	memset(dpdk, 0, sizeof(*dpdk));

	/* prepare rx pool */
	dpdk->rx_mempool = kmalloc(DPDKIO_MEMPOOL_SIZE, GFP_KERNEL);
	if (!dpdk->rx_mempool) {
		pr_err("failed to allocate memory for rx mempool\n");
		ret = -ENOMEM;
		goto out1;
	}
	memset(dpdk->rx_mempool, 0, DPDKIO_MEMPOOL_SIZE);

	return ret;

out1:
	kfree(dpdk);
	return ret;
}

static int __init lkl_dpdkio_init(void)
{
	int ret;

	if (!lkl_ops->dpdkio_ops)
		return 0;

	dpdkio_prepare();

	ret = dpdkio_init_dev();
	if (ret < 0)
		return ret;

	ret = lkl_ops->dpdkio_ops->start();

	return ret;
}

subsys_initcall(lkl_dpdkio_init);
