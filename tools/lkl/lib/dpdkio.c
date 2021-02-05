#include <lkl_host.h>
#include <lkl/asm/dpdkio.h>
#include "dpdkio.h"

#ifndef LKL_HOST_CONFIG_DPDKIO

int lkl_dpdkio_init(int argc, char **argv)
{
	return 0;
}

#else

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/eventfd.h>
#include <linux/if_ether.h>

#include <rte_eal.h>
#include <rte_net.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>


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

	rte_iova_t	iova_start;	/* start iova of bootmem */

	/* rx */
	uintptr_t	rx_region;	/* passed through init_rxring */
	int		rx_region_size;
	char		rx_heap_name[DPDKIO_MEM_NAME_MAX];
	char		rx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*rx_mempool;

	int		irq;		/* rx interrupt number */
	int		irq_ack_fd;	/* eventfd to receive irq ack */
	lkl_thread_t	poll_tid;	/* rx polling thread id */
	int		poll_hup;	/* 1 indicates stopping rx polling */
	int		poll_enabled;

	/* tx */
	char		tx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*tx_mempool;

#ifdef DEBUG_PCAP
	/* debug */
	int	tx_pcap_fd;	/* packet dump fd */
	int	rx_pcap_fd;
#endif
};

#define DPDKIO_PORT_MAX	32
struct dpdkio_port ports[DPDKIO_PORT_MAX];

static inline struct dpdkio_port *dpdkio_port_get(int portid)
{
	assert(portid < DPDKIO_PORT_MAX);
	return &ports[portid];
}

#ifdef DEBUG_PCAP
/* just for debug!! */
struct pcap_hdr {
	uint32_t	magic_number;
	uint16_t	version_major;
	uint16_t	version_minor;
	int		thiszone;
	uint32_t	sigfigs;
	uint32_t	snaplen;
	uint32_t	network;
};

struct pcap_pkt_hdr {
	uint32_t	ts_sec;
	uint32_t	ts_usec;
	uint32_t	incl_len;
	uint32_t	orig_len;
};

static int pcap_init_file(const char *filename)
{
	struct pcap_hdr ph;
	int fd, ret;

	fd = open(filename, O_RDWR | O_CREAT,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n",
			filename, strerror(errno));
		return fd;
	}

	memset(&ph, 0, sizeof(ph));
	ph.magic_number =  0xA1B2C3D4;
	ph.version_major = 0x0002;
	ph.version_minor = 0x0004;
	ph.snaplen = 0xFFFF;
	ph.network = 0x0001;

	ret = write(fd, &ph, sizeof(ph));
	if (ret < 0) {
		fprintf(stderr, "failed to write pcap file header: %s\n",
			strerror(errno));
		return ret;
	}

	return fd;
}

static int pcap_write_packet(int fd, struct lkl_iovec *segs, int nsegs)
{
	struct pcap_pkt_hdr hdr;
	int n, ret, pktlen = 0;

	for (n = 0; n < nsegs; n++)
		pktlen += segs[n].iov_len;

	hdr.ts_sec = 0;
	hdr.ts_usec = 0;
	hdr.incl_len = pktlen;
	hdr.orig_len = pktlen;

	ret = write(fd, &hdr, sizeof(hdr));
	if (ret < 0) {
		fprintf(stderr, "failed to write a pcap pkt hdr: %s\n",
			strerror(errno));
		return -1;
	}

	ret = writev(fd, (struct iovec *)segs, nsegs);
	if (ret < 0) {
		fprintf(stderr, "failed to write a packet: %s\n",
			strerror(errno));
		return -1;
	}

	fsync(fd);

	return 0;
}

#endif /* DEBUG_PCAP */

static void *dpdkio_malloc(int size)
{
	return rte_malloc(NULL, size, 0);
}

static void dpdkio_free(void *addr)
{
	rte_free(addr);
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

	port->portid = portid;
	snprintf(port->rx_heap_name, DPDKIO_MEM_NAME_MAX,
		 "rxheap-%d", portid);
	snprintf(port->rx_mempool_name, DPDKIO_MEM_NAME_MAX,
		 "rxpool-%d", portid);
	snprintf(port->tx_mempool_name, DPDKIO_MEM_NAME_MAX,
		 "txpool-%d", portid);

	/* tx mbuf can be small because packet payload is allocated
	 * along with sk_buff. It is attached as extmem. */
	port->tx_mempool = rte_pktmbuf_pool_create(port->tx_mempool_name,
						   LKL_DPDKIO_SLOT_NUM << 4,
						   LKL_DPDKIO_SLOT_NUM,
						   0, 64,
						   rte_socket_id());
	if (!port->tx_mempool) {
		pr_err("faield to create tx mbuf pool %s: %s\n",
		       port->tx_mempool_name, strerror(rte_errno));
		return rte_errno * -1;
	}

	return 0;
}

static int dpdkio_init_rxring(int portid, unsigned long addr, int size,
			      int *irq, int *irq_ack_fd)
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
	port->iova_start = iova_start;	/* save the start of iova */

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

	/* Note, create LKL_DPDKIO_SLOT_NUM + 64 mbufs on the rx
	 * mempool.  dpdkio driver releases an RXed buffer with mbuf
	 * when recycle the buffer. So, if the number of slots and the
	 * number of mbufs on the rx pool are identical, dpdk RX is
	 * stuck because there are no mbufs on the pool. So, we
	 * allocate LKL_DPDKIO_SLOT_NUM + 64 mbufs.
	 */
	port->rx_mempool = rte_pktmbuf_pool_create(port->rx_mempool_name,
						   LKL_DPDKIO_SLOT_NUM + 64,
						   256, 0,
						   RTE_MBUF_DEFAULT_DATAROOM,
						   sock_id);
	if (!port->rx_mempool) {
		pr_err("failed to create rx mempool %s "
		       "on %s (socket id %d): %s\n",
		       port->rx_mempool_name, port->rx_heap_name,
		       sock_id, strerror(rte_errno));
		return -1 * rte_errno;
	}

	/* initialize irq */
	port->irq = lkl_get_free_irq("dpdkio");
	if (port->irq < 0) {
		pr_err("failed to get free irq\n");
		return port->irq;
	}
	*irq = port->irq;

	port->irq_ack_fd = eventfd(0, EFD_CLOEXEC);
	if (port->irq_ack_fd < 0) {
		pr_err("failed to create eventfd: %s\n", strerror(errno));
		return -1 * errno;
	}
	*irq_ack_fd = port->irq_ack_fd;

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

	port_conf.txmode.offloads = dev_info.tx_offload_capa;
	port_conf.rxmode.offloads = DEV_RX_OFFLOAD_CHECKSUM;

	pr_info("port %d tx offload capa is 0x%lx\n",
		portid, dev_info.tx_offload_capa);
	pr_info("port %d tx offload conf is 0x%lx\n",
		portid, port_conf.txmode.offloads);
	pr_info("port %d rx offload capa is 0x%lx\n",
		portid, dev_info.rx_offload_capa);
	pr_info("port %d rx offload conf is 0x%lx\n",
		portid, port_conf.rxmode.offloads);

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
	txconf.tx_free_thresh = nb_txd >> 1;	/* half of descriptors */
	ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, SOCKET_ID_ANY,
				     &txconf);
	if (ret < 0) {
		pr_err("failed to setup tx queue port %d queue 0: %s\n",
		       portid, strerror(ret * 1));
		return ret;
	}

	/* just debug */
#ifdef DEBUG_PCAP
	port->tx_pcap_fd = pcap_init_file("debug-tx.pcap");
	port->rx_pcap_fd = pcap_init_file("debug-rx.pcap");
#endif

	return 0;
}

static void dpdkio_ack_rx_interrupt(int irq_ack_fd)
{
	unsigned long v = 1;
	int ret;

	ret = write(irq_ack_fd, &v, sizeof(v));
	if (unlikely(ret < 0))
		pr_err("write: %s\n", strerror(errno));
}

static void dpdkio_deliver_irq(struct dpdkio_port *port)
{
	uint64_t v;
	int ret;

	lkl_trigger_irq(port->irq);

	/* wait until irq is acked. write(irq_ack_fd) is called via
	 * host_ops->dpdkio_ops->ack_rx_interrupt, which means
	 * dpdkio_ack_rx_interrupt() shown above.
	 */
	ret = read(port->irq_ack_fd, &v, sizeof(v));
	if(unlikely(ret < 0))
		pr_err("read: %s\n", strerror(errno));
}

static void dpdkio_rx_poll_thread(void *arg)
{
	struct dpdkio_port *port = arg;
	int nb_rx, wait = 0;

	/* XXX: there are too many rooms for optimization.
	 *
	 * wait is the number of poll results on which queued packet
	 * is 0.
	 */

	do {
		if (port->poll_hup)
			break;

		nb_rx = rte_eth_rx_queue_count(port->portid, 0);

		if (0 < nb_rx)
			wait = 0;
		else if (nb_rx == 0)
			wait = ((wait + 1) & 0xFF) | 0x01;
		else {
			pr_err("rte_eth_rx_queue_count: %s\n",
			       strerror(-1 * nb_rx));
			return;
		}

		if (wait == 0) {
			/* there are pending packet(s) in the rx queue */
			if (port->poll_enabled)
				dpdkio_deliver_irq(port);
			else
				rte_delay_us_sleep(1);
		} else
			rte_delay_us_sleep(wait);

	} while (1);
}

static int dpdkio_start_rx_poll_thread(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);

	port->poll_hup = 0;
	port->poll_tid = lkl_host_ops.thread_create(dpdkio_rx_poll_thread,
						    port);
	if (port->poll_tid == 0) {
		pr_err("failed to spawn rx poll thread: %s\n",
		       strerror(errno));
		return -1 * errno;
	}

	return 0;
}

static void dpdkio_stop_rx_poll_thread(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);

	port->poll_hup = 1;
	__sync_synchronize();
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

	ret = dpdkio_start_rx_poll_thread(portid);
	if (ret < 0)
		return ret;

	return 0;
}

static int dpdkio_stop(int portid)
{
	int ret;

	dpdkio_stop_rx_poll_thread(portid);

	ret = rte_eth_dev_stop(portid);
	if (ret < 0) {
		pr_err("rte_eth_dev_stop: %s\n", strerror(ret * 1));
		return ret;
	}

	return 0;
}

static void dpdkio_enable_rx_interrupt(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	port->poll_enabled = 1;
	__sync_synchronize();	/* XXX: heavy? */
}

static void dpdkio_disable_rx_interrupt(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	port->poll_enabled = 0;
	__sync_synchronize();	/* XXX: heavy? */
}

static int dpdkio_rx_mbuf_to_slot(int portid, struct rte_mbuf *_mbuf,
				  struct lkl_dpdkio_slot *slot)
{
	struct rte_net_hdr_lens hdr_lens;
	struct rte_mbuf *mbuf;
	uint32_t ptype;
	uint16_t mtu;
	int n;

	if (_mbuf->nb_segs > LKL_DPDKIO_MAX_SEGS) {
		pr_err("too many segments in a mbuf %d (> max %d)\n",
		       _mbuf->nb_segs, LKL_DPDKIO_MAX_SEGS);
		rte_pktmbuf_free(_mbuf);
		return -1;
	}

	mbuf = _mbuf;

	for (n = 0; n < _mbuf->nb_segs; n++) {
		slot->segs[n].iov_base = rte_pktmbuf_mtod(mbuf, void *);
		slot->segs[n].iov_len = mbuf->data_len;
		mbuf = mbuf->next;
	}

	slot->nsegs = _mbuf->nb_segs;
	slot->pkt_len = rte_pktmbuf_pkt_len(_mbuf);
	slot->mbuf = _mbuf;

	/* initialize */
	slot->tx_offload = 0;
	slot->eth_protocol = 0;
	slot->ip_protocol = 0;

	/* just debug !!!*/
#ifdef DEBUG_PCAP
	do {
		struct dpdkio_port *port = dpdkio_port_get(portid);
		pcap_write_packet(port->rx_pcap_fd, slot->segs, slot->nsegs);
	} while (0);
#endif

	switch (_mbuf->ol_flags & PKT_RX_IP_CKSUM_MASK) {
	case PKT_RX_IP_CKSUM_GOOD:
		slot->rx_ip_cksum_result = LKL_DPDKIO_RX_IP_CKSUM_GOOD;
		break;
	case PKT_RX_IP_CKSUM_UNKNOWN:
		slot->rx_ip_cksum_result = LKL_DPDKIO_RX_IP_CKSUM_UNKNOWN;
		break;
	case PKT_RX_IP_CKSUM_BAD:
		slot->rx_ip_cksum_result = LKL_DPDKIO_RX_IP_CKSUM_BAD;
		break;
	case PKT_RX_IP_CKSUM_NONE:
		slot->rx_ip_cksum_result = LKL_DPDKIO_RX_IP_CKSUM_NONE;
		break;
	default:
		slot->rx_ip_cksum_result = 0;
	}


	ptype = rte_net_get_ptype(_mbuf, &hdr_lens, RTE_PTYPE_ALL_MASK);

	if ((ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4)
		slot->eth_protocol = htons(ETH_P_IP);
	else if ((ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV6)
		slot->eth_protocol = htons(ETH_P_IPV6);

	if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {
		slot->ip_protocol = IPPROTO_TCP;

		slot->l2_len = hdr_lens.l2_len;
		slot->l3_len = hdr_lens.l3_len;
		slot->l4_len = hdr_lens.l4_len;
		/* XXX: should consider encapsulation */

		/* copied from __dpdk_net_rx() */
		rte_eth_dev_get_mtu(portid, &mtu);

		if (slot->pkt_len > mtu) {
			slot->tso_segsz = (mtu - hdr_lens.l3_len -
					   hdr_lens.l4_len);
		}
	}

	return 0;
}

static int dpdkio_rx(int portid, struct lkl_dpdkio_slot **slots, int nb_pkts)
{
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_BURST];
	int nb_rx, n, i, ret;

	nb_rx = rte_eth_rx_burst(portid, 0, mbufs, nb_pkts);

	for (i = 0, n = 0; n < nb_rx; n++) {
		ret = dpdkio_rx_mbuf_to_slot(portid, mbufs[n], slots[i]);
		if (unlikely(ret < 0))
			continue; /* advance only mbuf index 'n', not 'i' */
		i++;
	}

	return i;
}

static void dpdkio_mbuf_free(void *mbuf)
{
	rte_pktmbuf_free((struct rte_mbuf *)mbuf);
	return;
}

static struct rte_mbuf_ext_shared_info *
dpdkio_get_mbuf_shared_info(struct lkl_dpdkio_slot *slot)
{
	return (struct rte_mbuf_ext_shared_info *)slot->opaque;
}

static void dpdkio_extmem_free_cb(void *addr, void *opaque)
{
	struct lkl_dpdkio_slot *slot = opaque;

	/* Note, all segments of a mbuf has an identical pointer to a
	 * shinfo. refcnt of shinfo indicates how many mbufs with
	 * extmem have reference to the slot and shinfo. dpdk tx
	 * process decerements refcnt, and if it is 0, there is no
	 * mbuf with extmem referencing the slot and shinfo. Then
	 * release skb.
	 *
	 * ^- it is changed. chained mbufs is counted as refcnt 1?
	 */

	lkl_host_ops.dpdkio_ops->free_skb(slot->skb);
	slot->skb = NULL;
	__sync_synchronize();
}

static inline rte_iova_t dpdkio_seg_iova(struct dpdkio_port *port,
					 struct lkl_iovec *seg)
{
	unsigned long iova;

	iova = (port->iova_start +
		((uintptr_t)seg->iov_base) - lkl_host_ops.memory_start);

	return (rte_iova_t)iova;
}

static void dpdkio_fill_mbuf_tx_offload(struct lkl_dpdkio_slot *slot,
					struct rte_mbuf *mbuf)
{
	switch (ntohs(slot->eth_protocol)) {
	case ETH_P_IP:
		mbuf->ol_flags = (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
		break;
	case ETH_P_IPV6:
		mbuf->ol_flags = PKT_TX_IPV6;
		break;
	}

	if (slot->ip_protocol == IPPROTO_TCP) {
		mbuf->ol_flags |= PKT_TX_TCP_CKSUM;

		if (slot->nsegs > 1) {
			mbuf->ol_flags |= PKT_TX_TCP_SEG;
			mbuf->l2_len = slot->l2_len;
			mbuf->l3_len = slot->l3_len;
			mbuf->l4_len = slot->l4_len;
			mbuf->tso_segsz = slot->tso_segsz;
		}
	}
}

static int dpdkio_tx(int portid, struct lkl_dpdkio_slot *slots, int nb_pkts)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_BURST], *head;
	struct rte_mbuf *mbufs_tx[LKL_DPDKIO_MAX_BURST];
	struct rte_mbuf_ext_shared_info *shinfo;
	struct lkl_dpdkio_slot *slot;
	int ret, n, i, nsegs, mbufcnt, mbufs_tx_cnt;

	nsegs = 0;
	for (n = 0; n < nb_pkts; n++) {
		slot = &slots[n];
		nsegs += slot->nsegs;
	}

	ret = rte_pktmbuf_alloc_bulk(port->tx_mempool, mbufs, nsegs);
	if (ret < 0)
		return ret;

	/* XXX: we need to handle over LKL_DPDKIO_MAX_BURST packets
	 * and segments. usually, ndo_start_xmit is called per packet.
	 * we might consider xmit_more for more performance.
	 */

	/* attach packets to mbufs */
	mbufcnt = 0;
	mbufs_tx_cnt = 0;
	for (n = 0; n < nb_pkts; n++) {

		slot = &slots[n];

#ifdef DEBUG_PCAP
		/* pcap debugg!!  */
		pcap_write_packet(port->tx_pcap_fd, slot->segs, slot->nsegs);
#endif

		shinfo = dpdkio_get_mbuf_shared_info(slot);
		shinfo->free_cb = dpdkio_extmem_free_cb;
		shinfo->fcb_opaque = slot;
		rte_mbuf_ext_refcnt_set(shinfo, 1);
		/* XXX: Note, multiple mubfs share a same shinfo, but,
		 * its refcnt is 1, not the number of mbufs of a packet.
		 */

		head = NULL;

		for (i = 0; i < slot->nsegs; i++) {
			struct lkl_iovec *seg = &slot->segs[i];
			struct rte_mbuf *mbuf = mbufs[mbufcnt++];

			rte_pktmbuf_attach_extbuf(mbuf,
						  seg->iov_base,
						  dpdkio_seg_iova(port, seg),
						  seg->iov_len, shinfo);
			mbuf->pkt_len = seg->iov_len;
			mbuf->data_len = seg->iov_len;

			if (head == NULL) {
				/* the first mbuf of this packet */
				head = mbuf;
				mbufs_tx[mbufs_tx_cnt] = mbuf;
			} else {
				ret = rte_pktmbuf_chain(head, mbuf);
				if (unlikely(ret < 0)) {
					pr_err("too many mbuf chain: %s\n",
					       strerror(errno));
					assert(0);
				}
			}
		}

		dpdkio_fill_mbuf_tx_offload(slot, mbufs_tx[mbufs_tx_cnt]);

		mbufs_tx_cnt++;
	}


	ret = rte_eth_tx_burst(portid, 0, mbufs_tx, nb_pkts);

	return ret;
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

static int dpdkio_get_link_status(int portid)
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
	.free			= dpdkio_free,
	.init_port		= dpdkio_init_port,
	.init_rxring		= dpdkio_init_rxring,
	.setup			= dpdkio_setup,
	.start			= dpdkio_start,
	.stop			= dpdkio_stop,
	.rx			= dpdkio_rx,
	.ack_rx_interrupt	= dpdkio_ack_rx_interrupt,
	.enable_rx_interrupt	= dpdkio_enable_rx_interrupt,
	.disable_rx_interrupt	= dpdkio_disable_rx_interrupt,
	.mbuf_free		= dpdkio_mbuf_free,
	.tx			= dpdkio_tx,
	.free_skb		= NULL,	/* fillled by lkl/kernel/dpdkio.c */
	.get_macaddr		= dpdkio_get_macaddr,
	.get_link_status	= dpdkio_get_link_status,
};


void dpdkio_lkl_netdev_free(struct lkl_netdev *nd)
{
	free(nd);
}

struct lkl_dev_net_ops dpdkio_dev_net_ops = {
	.free = dpdkio_lkl_netdev_free,
};

struct lkl_netdev *lkl_dpdkio_create(void)
{
	struct lkl_netdev *nd;

	nd = malloc(sizeof(*nd));
	if (!nd) {
		lkl_printf("%s: dpdkio: failed to allocate memory\n",
			   __func__);
		return NULL;
	}
	memset(nd, 0, sizeof(*nd));

	nd->ops = &dpdkio_dev_net_ops;
	return nd;
}


#endif /* LKL_HOST_CONFIG_DPDKIO */
