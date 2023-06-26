#include <stdlib.h>
#include <lkl_host.h>
#include <lkl/asm/dpdkio.h>

#include "dpdkio.h"


#ifndef LKL_HOST_CONFIG_DPDKIO

int lkl_dpdkio_init(int argc, char **argv)
{
	return 0;
}

#else



#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>


#define pr_info(fmt, ...) fprintf(stdout, "%s(): " fmt,	 \
				  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"     \
				  "WARN:%s(): " fmt "\x1b[0m",  \
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[31m"      \
				 "ERR:%s(): " fmt "\x1b[0m",    \
				 __func__, ##__VA_ARGS__)


/* lkl_dpdkio_init()
 *
 * initialize dpdk eal invoked from lkl/lib. This function must be
 * called before lkl strats. */
int lkl_dpdkio_init(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		pr_err("cannot init EAL: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}



#define DPDKIO_MEM_NAME_MAX	32

/* structure representing lkl dpdkio backend port */
struct dpdkio_port {
	int portid;

	/* rx */
	uintptr_t	rx_region;	/* passed through init_rxring */
	int		rx_region_size;
	char		rx_heap_name[DPDKIO_MEM_NAME_MAX];
	char		rx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*rx_mempool;

	/* tx */
	char		tx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*tx_mempool;
};

#define DPDKIO_PORT_MAX	32
struct dpdkio_port ports[DPDKIO_PORT_MAX];

static inline struct dpdkio_port *dpdkio_port_get(int portid)
{
	assert(portid < DPDKIO_PORT_MAX);
	return &ports[portid];
}



static void *dpdkio_malloc(int size) {
	return rte_malloc(NULL, size, 0);
}

static int dpdkio_init_port(int portid)
{
	struct dpdkio_port *port;

	if (portid >= DPDKIO_PORT_MAX) {
		pr_err("too many dpdkio ports (%d > %d)\n",
		       portid, DPDKIO_PORT_MAX);
		return -ENOMEM;
	}

	if (portid >= rte_eth_dev_count_avail()) {
		pr_err("no port %d, available %d ports\n", portid,
		       rte_eth_dev_count_avail());
		return -ENODEV;
	}

	port = dpdkio_port_get(portid);
	if (port->rx_region) {
		pr_err("port %d is already initialized\n", portid);
		return -EBUSY;
	}

	snprintf(port->rx_heap_name, DPDKIO_MEM_NAME_MAX,
		 "rxheap-%d", portid);
	snprintf(port->rx_mempool_name, DPDKIO_MEM_NAME_MAX,
		 "rxpool-%d", portid);
	snprintf(port->tx_mempool_name, DPDKIO_MEM_NAME_MAX,
		 "txpool-%d", portid);

	return 0;
}

static int dpdkio_init_rxring(int portid, unsigned long addr, int size)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	rte_iova_t iova[LKL_DPDKIO_MEMPOOL_PAGE_NUM];
	rte_iova_t iova_start, iova_rx;
	int ret, n, sock_id;

	port->rx_region = addr;
	port->rx_region_size = size;

	if (size != LKL_DPDKIO_MEMPOOL_SIZE) {
		pr_err("invalid rx region size %d bytes, must be %d bytes\n",
		       size, LKL_DPDKIO_MEMPOOL_SIZE);
		return -EINVAL; /* XXX: should be variable? */
	}

	/* verify iova of the lkl boot memory */
	iova_start = rte_malloc_virt2iova((void *)(lkl_host_ops.memory_start));
	if (iova_start == RTE_BAD_IOVA) {
		pr_err("failed to get iova of memory_start 0x%lx\n",
		       lkl_host_ops.memory_start);
		return -EINVAL;
	}

	/* prepare 4k-byte-aligned iova array */
	iova_rx = iova_start + (addr - lkl_host_ops.memory_start);
	for (n = 0; n < LKL_DPDKIO_MEMPOOL_PAGE_NUM; n++)
		iova[n] = iova_rx + (LKL_DPDKIO_PAGE_SIZE * n);

	/* create heap and mempool for rx */
	ret = rte_malloc_heap_create(port->rx_heap_name);
	if (ret < 0) {
		pr_err("failed to create rx heap: %s\n", strerror(rte_errno));
		return -1 * rte_errno;
	}

	ret = rte_malloc_heap_memory_add(port->rx_heap_name,
					 (void *)addr, size, iova,
					 LKL_DPDKIO_MEMPOOL_PAGE_NUM,
					 LKL_DPDKIO_PAGE_SIZE);
	if (ret < 0) {
		pr_err("failed to add rx memory regtion to rte heap: %s\n",
		       strerror(rte_errno));
		return -1 * rte_errno;
	}

	sock_id = rte_malloc_heap_get_socket(port->rx_heap_name);
	if (sock_id < 0) {
		pr_err("rte heap %s not found\n", port->rx_heap_name);
		return -ENOENT;
	}

	port->rx_mempool = rte_pktmbuf_pool_create(port->rx_mempool_name,
						   LKL_DPDKIO_SLOT_NUM, 256, 0,
						   RTE_MBUF_DEFAULT_BUF_SIZE,
						   sock_id);
	if (!port->rx_mempool) {
		pr_err("failed to create rx mempool %s "
		       "on %s (socket id %d): %s\n",
		       port->rx_mempool_name, port->rx_heap_name,
		       sock_id, strerror(rte_errno));
		return -1 * rte_errno;
	}

	return 0;
}

static int dpdkio_setup(int portid, int *nb_rx_desc, int *nb_tx_desc)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct rte_eth_conf port_conf = {
		.rxmode = { .split_hdr_size = 0, },
		.txmode = { .mq_mode = ETH_MQ_TX_NONE, },
	};
	struct rte_eth_dev_info dev_info;
	uint16_t nb_txd = *nb_tx_desc;
	uint16_t nb_rxd = *nb_rx_desc;
	int ret;

	if (*nb_tx_desc < 1 || *nb_rx_desc < 1) {
		pr_err("invalid number of desc tx=%d rx=%d\n",
		       *nb_tx_desc, *nb_rx_desc);
		return -EINVAL;
	}

	if (!rte_eth_dev_is_valid_port(portid)) {
		pr_err("invalid portid %d\n", portid);
		return -EINVAL;
	}

	/* adjust descriptors */
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (ret < 0) {
		pr_err("failed to adjust nb tx(%u) rx(%u) desc: %s\n",
		       nb_txd, nb_rxd, strerror(ret * -1));
		return ret;
	}
	*nb_rx_desc = nb_rxd;
	*nb_tx_desc = nb_txd;

	/* setup port */
	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret < 0) {
		pr_err("failed to get dev info of port %d: %s\n",
		       portid, strerror(errno));
		return ret;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	pr_info("port %d tx offload capa is 0x%lx\n",
		portid, dev_info.tx_offload_capa);
	pr_info("port %d tx offload conf is 0x%lx\n",
		portid, port_conf.txmode.offloads);

	ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
	if (ret < 0) {
		pr_err("failed to configure dpdk port %d: %s\n",
		       portid, strerror(ret * -1));
		return ret;
	}


	/* setup queue */
	/* XXX: RX offload setting here */
	ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, SOCKET_ID_ANY,
				     NULL, port->rx_mempool);
	if (ret < 0) {
		pr_err("failed to setup rx queue port %d queue 0: %s\n",
		       portid, strerror(ret * -1));
		return ret;
	}

	/* XXX: TX offload setting here */
	struct rte_eth_txconf txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, SOCKET_ID_ANY,
				     &txconf);
	if (ret < 0) {
		pr_err("failed to setup tx queue port %d queue 0: %s\n",
		       portid, strerror(ret * 1));
		return ret;
	}

	return 0;
}

static int dpdkio_start(int portid)
{
	int ret;

	ret = rte_eth_dev_start(portid);
	if (ret < 0) {
		pr_err("rte_eth_dev_start: %s\n", strerror(ret * 1));
		return ret;
	}

	ret = rte_eth_dev_set_link_up(portid);
	if (ret < 0) {
		pr_err("rte_eth_dev_set_link_up: %s\n", strerror(ret * 1));
		return ret;
	}

	return 0;
}

static int dpdkio_stop(int portid)
{
	int ret;

	ret = rte_eth_dev_stop(portid);
	if (ret < 0) {
		pr_err("rte_eth_dev_stop: %s\n", strerror(ret * 1));
		return ret;
	}

	return 0;
}

static int dpdkio_rx(int portid, struct lkl_dpdkio_pkt *pkts, int nb_pkts)
{
	return 0;
}

static void dpdkio_mbuf_free(void *mbuf)
{
	return;
}

static int dpdkio_tx(int portid, struct lkl_dpdkio_pkt *pkts, int nb_pkts)
{
	return 0;
}

static void dpdkio_free_skb(void *skb)
{
	return;
}

static void dpdkio_get_macaddr(int portid, char *mac)
{
	struct rte_ether_addr addr;
	int ret;

	ret = rte_eth_macaddr_get(portid, &addr);
	if (ret < 0) {
		pr_err("rte_eth_macaddr_get: %s\n", strerror(ret * -1));
		return;
	}

	memcpy(mac, addr.addr_bytes, LKL_ETH_ALEN);
}

static int dpdkio_get_link_stat(int portid)
{
	struct rte_eth_link link;
	int ret;

	ret = rte_eth_link_get_nowait(portid, &link);
	if (ret < 0) {
		pr_err("rte_eth_link_get_nowait: %s\n", strerror(ret * -1));
		return -1;
	}

	return link.link_status; /* ETH_LINK_UP 1 or ETH_LINK_DOWN 0 */
}

struct lkl_dpdkio_ops dpdkio_ops = {
	.malloc			= dpdkio_malloc,
	.init_port		= dpdkio_init_port,
	.init_rxring		= dpdkio_init_rxring,
	.setup			= dpdkio_setup,
	.start			= dpdkio_start,
	.stop			= dpdkio_stop,
	.rx			= dpdkio_rx,
	.mbuf_free		= dpdkio_mbuf_free,
	.tx			= dpdkio_tx,
	.free_skb		= dpdkio_free_skb,
	.get_macaddr		= dpdkio_get_macaddr,
	.get_link_status	= dpdkio_get_link_stat,
};


#endif /* LKL_HOST_CONFIG_DPDKIO */
