#include <lkl_host.h>
#include <lkl/asm/dpdkio.h>
#include "dpdkio.h"

#ifndef LKL_HOST_CONFIG_DPDKIO

int lkl_dpdkio_init(int argc, char **argv)
{
	return 0;
}

int lkl_dpdkio_exit(void)
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

#define min(a, b) a < b ? a : b

//#define DEBUG_PKT_TX
//#define DEBUG_PKT_RX
//#define DEBUG_STATS
//#define DEBUG_PCAP

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

int lkl_dpdkio_exit(void)
{
	return rte_eal_cleanup();
}

#define DPDKIO_MEM_NAME_MAX	32
#define DPDKIO_MAX_RX_REGIONS	72

/* structure representing lkl dpdkio backend port */
struct dpdkio_port {
	int portid;

	rte_iova_t	iova_start;	/* start iova of bootmem */

	/* rx */
	char				rx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool		*rx_mempool;
	struct rte_pktmbuf_extmem	*rx_extmems; /* array of extmem */
	struct lkl_dpdkio_ring		pending_mbuf_ring;
	int				nb_rx_extmems;

	int		irq;		/* rx interrupt number */
	int		irq_ack_fd;	/* eventfd to receive irq ack */
	lkl_thread_t	poll_tid;	/* rx polling thread id */
	uint8_t		poll_hup;	/* 1 indicates stopping rx polling */
	uint8_t		poll_enabled;

	/* tx */
	char			tx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*tx_mempool;
	unsigned long	txed;

	/* mbuf queue to be released */
	struct lkl_dpdkio_ring free_mbuf_ring;

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

static int pcap_write_packet(int fd, struct lkl_dpdkio_seg *segs, int nsegs)
{
	struct pcap_pkt_hdr hdr;
	int n, ret, pktlen = 0;

	for (n = 0; n < nsegs; n++)
		pktlen += segs[n].data_len;

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

	for (n = 0; n < nsegs; n++) {
		void *addr = (void *)(segs[n].buf_addr + segs[n].data_off);
		ret = write(fd, addr, segs[n].data_len);
		if (ret < 0) {
			fprintf(stderr, "failed to write a packet: %s\n",
				strerror(errno));
			return -1;
		}
	}

	fsync(fd);

	return 0;
}

#endif /* DEBUG_PCAP */

#if defined(DEBUG_PKT_TX) || defined(DEBUG_PKT_RX)
static void dpdkio_slot_dump(struct lkl_dpdkio_slot *slot)
{
	int n;

	printf("dump lkl_dpdkio_slot: 0x%lx\n", (uintptr_t)slot);
	printf("  - nsegs    %d\n", slot->nsegs);
	printf("  - pkt_len  %u\n", slot->pkt_len);
	printf("  - mbuf     0x%lx\n", (uintptr_t)slot->mbuf);
	printf("  - skb      0x%lx\n", (uintptr_t)slot->skb);
	printf("  - l2:%u l3:%u l4:%u segsz:%u\n",
	       slot->l2_len, slot->l3_len, slot->l4_len, slot->tso_segsz);

	for (n = 0; n < slot->nsegs; n++) {
		struct lkl_dpdkio_seg *seg = &slot->segs[n];
		printf("  seg[%02d] buf 0x%lx %u byte, data off %u len %u\n",
		       n, seg->buf_addr, seg->buf_len,
		       seg->data_off, seg->data_len);
	}
	printf("\n");
}
#endif

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
	rte_iova_t iova_start;

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
	memset(port, 0, sizeof(*port));
	port->portid = portid;
	snprintf(port->rx_mempool_name, DPDKIO_MEM_NAME_MAX,
		 "rxpool-%d", portid);
	snprintf(port->tx_mempool_name, DPDKIO_MEM_NAME_MAX,
		 "txpool-%d", portid);

	/* save the iova of the lkl boot memory */
	iova_start = rte_malloc_virt2iova((void *)(lkl_host_ops.memory_start));
	if (iova_start == RTE_BAD_IOVA) {
		pr_err("failed to get iova of memory_start 0x%lx\n",
		       lkl_host_ops.memory_start);
		return -EINVAL;
	}
	port->iova_start = iova_start;	/* save the start of iova */

	/* prepare extmem */
	port->rx_extmems = calloc(sizeof(struct rte_pktmbuf_extmem),
				  LKL_DPDKIO_RX_PAGE_NUM);
	if (!port->rx_extmems) {
		pr_err("failed to alloc memory for rx_extmems\n");
		return -ENOMEM;
	}
	port->nb_rx_extmems = 0;

	return 0;
}

static int dpdkio_add_rx_page(int portid, unsigned long addr)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct rte_pktmbuf_extmem *x;

	x = &port->rx_extmems[port->nb_rx_extmems];
	x->buf_ptr = (void *)addr;
	x->buf_iova = rte_mem_virt2iova((void *)addr);
	x->buf_len = 4096;
	x->elt_size = 4096;

	port->nb_rx_extmems++;

	return 0;
}

static int dpdkio_init_rx_irq(int portid, int *irq, int *irq_ack_fd)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);

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
	struct rte_eth_conf port_conf = {};
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
	pr_info("adjusted desc: tx %u -> %u, rx %u -> %u\n",
		*nb_tx_desc, nb_txd, *nb_rx_desc, nb_rxd);

	*nb_rx_desc = nb_rxd;
	*nb_tx_desc = nb_txd;

	/* setup tx/rx configurations  */
	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret < 0) {
		pr_err("failed to get dev info of port %d: %s\n",
		       portid, strerror(errno));
		return ret;
	}

	port_conf.txmode.offloads = (DEV_TX_OFFLOAD_IPV4_CKSUM |
				     DEV_TX_OFFLOAD_UDP_CKSUM |
				     DEV_TX_OFFLOAD_TCP_CKSUM |
				     DEV_TX_OFFLOAD_TCP_TSO);
	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

	port_conf.rxmode.offloads = (DEV_RX_OFFLOAD_CHECKSUM |
				     DEV_RX_OFFLOAD_TCP_LRO |
				     DEV_RX_OFFLOAD_SCATTER);
	port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
	port_conf.rxmode.max_lro_pkt_size = dev_info.max_lro_pkt_size;

	pr_info("port %d tx offload capa=0x%lx conf=0x%lx\n",
		portid, dev_info.tx_offload_capa, port_conf.txmode.offloads);
	pr_info("port %d rx offload capa=0x%lx conf=0x%lx lro_size=%u\n",
		portid, dev_info.rx_offload_capa, port_conf.rxmode.offloads,
		port_conf.rxmode.max_lro_pkt_size);

	ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
	if (ret < 0) {
		pr_err("failed to configure dpdk port %d: %s\n",
		       portid, strerror(ret * -1));
		return ret;
	}

	/*** TX ***/
	/* tx mbuf can be small because packet payload is allocated
	 * along with sk_buff. It is attached as extmem. */
	port->tx_mempool = rte_pktmbuf_pool_create(port->tx_mempool_name,
						   nb_txd << 3, 512, 0,
						   64, rte_socket_id());
	if (!port->tx_mempool) {
		pr_err("faield to create tx mbuf pool %s: %s\n",
		       port->tx_mempool_name, strerror(rte_errno));
		return rte_errno * -1;
	}

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

	/*** RX ***/
	int mbuf_size = 1 << 12; /* must be 4k!! 2021/5/17 17:31 */
	port->rx_mempool = rte_pktmbuf_pool_create_extbuf
		(port->rx_mempool_name, nb_rxd << 2, 512, 0, mbuf_size,
		 rte_socket_id(), port->rx_extmems, port->nb_rx_extmems);

	if (!port->rx_mempool) {
		pr_err("faield to create rx mbuf pool %s: %s\n",
		       port->rx_mempool_name, strerror(rte_errno));
		return rte_errno * -1;
	}

	struct rte_eth_rxconf rxconf = dev_info.default_rxconf;
	//rxconf.rx_free_thresh = nb_rxd >> 1;
	rxconf.rx_drop_en = 1;
	rxconf.offloads = port_conf.rxmode.offloads;

	ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_socket_id(),
				     &rxconf, port->rx_mempool);
	if (ret < 0) {
		pr_err("failed to setup rx queue port %d queue 0: %s\n",
		       portid, strerror(ret * -1));
		return ret;
	}

	/* just debug */
#ifdef DEBUG_PCAP
	pr_warn("debug pcap capture enabled\n");
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



static int dpdkio_start_rx_poll_thread(int portid);
static void dpdkio_stop_rx_poll_thread(int portid);

#ifdef DEBUG_STATS
static void dpdkio_eth_stats_thread(void *arg)
{
	struct dpdkio_port *port = arg;
	struct rte_eth_stats s;

	while (1) {
		rte_eth_stats_get(port->portid, &s);
		printf("======== stats ========\n");
		printf("rx pkts:        %lu\n", s.ipackets);
		printf("tx pkts:        %lu\n", s.opackets);
		printf("rx missed pkts: %lu\n", s.imissed);
		printf("rx err pkts:    %lu\n", s.ierrors);
		printf("tx err pkts:    %lu\n", s.ierrors);
		printf("rx err mbufs:   %lu\n", s.rx_nombuf);
		printf("txburst pkts:   %lu\n", port->txed);
		sleep(1);
	}
}
#endif

static int dpdkio_start(int portid)
{
	int ret;

#ifdef DEBUG_STATS
	lkl_thread_t tid;
	tid = lkl_host_ops.thread_create(dpdkio_eth_stats_thread,
					 dpdkio_port_get(portid));
#endif

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


/**** polling thread *****/

static void dpdkio_mbuf_free(int portid, void *mbuf)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct lkl_dpdkio_ring *r = &port->free_mbuf_ring;

	if (unlikely(lkl_dpdkio_ring_full(r))) {
		pr_err("mbuf free ring full on port %d!\n!", portid);
		assert(0); /* XXX */
	}

	r->ptrs[r->head] = mbuf;
	__sync_synchronize();
	lkl_dpdkio_ring_write_next(r, 1);
}

#define MAX_FREE_MBUF_BULK_NUM	32

static void dpdkio_free_rx_mbuf(struct dpdkio_port *port)
{
	struct lkl_dpdkio_ring *r = &port->free_mbuf_ring;
	struct rte_mbuf *mbufs[MAX_FREE_MBUF_BULK_NUM];
	unsigned int b, n;

	b = lkl_dpdkio_ring_read_avail(r);
	b = min(b, MAX_FREE_MBUF_BULK_NUM);
	if (!b)
		return;

	for (n = 0; n < b; n++)
		mbufs[n] = r->ptrs[(r->tail + n) & LKL_DPDKIO_RING_MASK];

	rte_pktmbuf_free_bulk(mbufs, b);
	lkl_dpdkio_ring_read_next(r, b);
}

static void dpdkio_rx_burst(struct dpdkio_port *port)
{
	struct lkl_dpdkio_ring *r = &port->pending_mbuf_ring;
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_BURST];
	int b, nb_rx, n;

	b = lkl_dpdkio_ring_write_avail(r);
	b = min(LKL_DPDKIO_MAX_BURST, b);

	if (!b)
		return;

	nb_rx = rte_eth_rx_burst(port->portid, 0, mbufs, b);

	for (n = 0; n < nb_rx; n++)
		r->ptrs[(r->head + n) & LKL_DPDKIO_RING_MASK] = mbufs[n];

	__sync_synchronize();
	lkl_dpdkio_ring_write_next(r, nb_rx);
}


static void dpdkio_rx_poll_thread(void *arg)
{
	struct dpdkio_port *port = arg;
	struct lkl_dpdkio_ring *r = &port->pending_mbuf_ring;
	uint8_t wait = 0, disabled_wait = 0;
	int pending;

	/* XXX: there are too many rooms for optimization.
	 *
	 * wait is the number of poll results on which queued packet
	 * is 0.
	 */

	do {
		if (port->poll_hup)
			break;

		dpdkio_free_rx_mbuf(port);
		dpdkio_rx_burst(port);
		pending = lkl_dpdkio_ring_read_avail(r);

		if (pending > 0)
			wait = 0;
		else if (pending == 0)
			wait = (((wait + 1) & 0x07) | 0x01);

		if (wait == 0) {
			/* there are pending packet(s). kick irq */
			if (port->poll_enabled)
				dpdkio_deliver_irq(port);
			else {
				disabled_wait = (disabled_wait + 1) & 0x07;
				if (disabled_wait == 0)
					rte_delay_us_sleep(1);
			}
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



/**** rx call from kernel ****/

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
		slot->segs[n].buf_addr = (uintptr_t)mbuf->buf_addr;
		slot->segs[n].buf_len = mbuf->buf_len;
		slot->segs[n].data_off = mbuf->data_off;
		slot->segs[n].data_len = mbuf->data_len;
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
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct lkl_dpdkio_ring *r = &port->pending_mbuf_ring;
	struct rte_mbuf *mbuf;
	int pending, n, i, nb_rx, ret;

	pending = lkl_dpdkio_ring_read_avail(r);

	nb_rx = min(nb_pkts, pending);

	for (i = 0, n = 0; n < nb_rx; n++) {

		mbuf = r->ptrs[(r->tail + n) & LKL_DPDKIO_RING_MASK];
		ret = dpdkio_rx_mbuf_to_slot(portid, mbuf, slots[i]);

#ifdef DEBUG_PKT_RX
		pr_warn("======== RX ========\n");
		rte_pktmbuf_dump(stdout, mbuf, 0);
		printf("\n");
		dpdkio_slot_dump(slots[i]);
#endif

		if (unlikely(ret < 0)) {
			pr_err("dpdkio_rx_mbuf_to_slot failed\n");
			rte_pktmbuf_free(mbuf);
			continue; /* advance only mbuf index 'n', not 'i' */
		}
		i++;
	}

	lkl_dpdkio_ring_read_next(r, nb_rx);

	return i;
}


static struct rte_mbuf_ext_shared_info *
dpdkio_get_mbuf_shared_info(struct lkl_dpdkio_slot *slot)
{
	return (struct rte_mbuf_ext_shared_info *)slot->opaque;
}

static __always_inline void set_null(volatile void *p)
{
	*(volatile __u64 *)p = 0;
}

static void dpdkio_extmem_free_cb(void *addr, void *opaque)
{
	struct lkl_dpdkio_slot *slot = opaque;
	int portid = slot->portid;
	void *skb = slot->skb;

	set_null(&slot->skb); /* mark this slot is usable for tx */
	lkl_host_ops.dpdkio_ops->free_skb(portid, skb);
}

static void dpdkio_fill_mbuf_tx_offload(struct lkl_dpdkio_slot *slot,
					struct rte_mbuf *mbuf)
{
	switch (ntohs(slot->eth_protocol)) {
	case ETH_P_IP:
		mbuf->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
		break;
	case ETH_P_IPV6:
		mbuf->ol_flags |=  PKT_TX_IPV6;
		break;
	}

	if (slot->ip_protocol == IPPROTO_TCP) {
		mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
		mbuf->l2_len = slot->l2_len;
		mbuf->l3_len = slot->l3_len;
		mbuf->l4_len = slot->l4_len;

		if (slot->nsegs > 1) {
			mbuf->ol_flags |= PKT_TX_TCP_SEG;
			mbuf->tso_segsz = slot->tso_segsz;
		}
	}
}

static struct rte_mbuf *dpdkio_tx_slot_to_mbuf(int portid,
					       struct lkl_dpdkio_slot *slot)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct rte_mbuf_ext_shared_info *shinfo;
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_SEGS];
	int ret, n;

	ret = rte_pktmbuf_alloc_bulk(port->tx_mempool, mbufs, slot->nsegs);
	if (unlikely(ret < 0)) {
		pr_err("failed to alloc mbuf!!\n");
		return NULL;
	}

	shinfo = dpdkio_get_mbuf_shared_info(slot);
	shinfo->free_cb = dpdkio_extmem_free_cb;
	shinfo->fcb_opaque = slot;
	rte_mbuf_ext_refcnt_set(shinfo, 1);

	for (n = 0; n < slot->nsegs; n++) {
		struct lkl_dpdkio_seg *seg = &slot->segs[n];
		struct rte_mbuf *mbuf = mbufs[n];
		void *buf_addr = (void *)seg->buf_addr;

		rte_pktmbuf_attach_extbuf(mbuf, buf_addr,
					  rte_mem_virt2iova(buf_addr),
					  seg->buf_len, shinfo);
		mbuf->data_len = seg->data_len;
		mbuf->data_off = seg->data_off;
		mbuf->pkt_len = seg->data_len;

		if (n > 0) {
			ret = rte_pktmbuf_chain(mbufs[0], mbuf);
			if (unlikely(ret < 0)) {
				pr_err("mbuf chain failed\n");
				assert(0);
			}
		}
	}

	dpdkio_fill_mbuf_tx_offload(slot, mbufs[0]);

	return mbufs[0];
}

static int dpdkio_tx(int portid, struct lkl_dpdkio_slot **slots, int nb_pkts)
{
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_BURST], *mbuf;
	struct dpdkio_port *port = dpdkio_port_get(portid);
	int n, i, ret;

	for (i = 0, n = 0; n < nb_pkts; n++) {

		mbuf = dpdkio_tx_slot_to_mbuf(portid, slots[n]);

#ifdef DEBUG_PKT_TX
		pr_warn("======== TX ========\n");
		dpdkio_slot_dump(slots[n]);
		rte_pktmbuf_dump(stdout, mbuf, 0);
		printf("\n");
#endif

#ifdef DEBUG_PCAP
		pcap_write_packet(port->tx_pcap_fd,
				  slots[n]->segs, slots[n]->nsegs);
#endif

		if (likely(mbuf)) {
			mbufs[i] = mbuf;
			i++;
		}
	}

	if (unlikely(i == 0)) {
		pr_err("0 tx\n");
		return 0;
	}

	ret = rte_eth_tx_prepare(portid, 0, mbufs, i);
	if (unlikely(ret < i))
		pr_err("prep failed\n");

	ret = rte_eth_tx_burst(portid, 0, mbufs, ret);
	port->txed += ret;

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

#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
static int dpdkio_get_link_status(int portid)
{
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];
	struct rte_eth_link link;
	int ret, count, old_status = 0;

	/* referred from testpmd.c */
	pr_info("Checking link status...\n");
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		memset(&link, 0, sizeof(link));
		ret = rte_eth_link_get_nowait(portid, &link);
		if (ret < 0) {
			pr_warn("Port %u link get failed: %s\n",
				portid, rte_strerror(-ret));
			continue;
		}

		if (old_status != link.link_status){
			rte_eth_link_to_str(link_status,
					    sizeof(link_status), &link);
			pr_info("Port %d %s\n", portid, link_status);
		}
		if (link.link_status == ETH_LINK_UP)
			break;

		old_status = link.link_status;
		rte_delay_ms(CHECK_INTERVAL);
	}

	return link.link_status; /* ETH_LINK_UP 1 or ETH_LINK_DOWN 0 */
}

struct lkl_dpdkio_ops dpdkio_ops = {
	.malloc			= dpdkio_malloc,
	.free			= dpdkio_free,
	.init_port		= dpdkio_init_port,
	.add_rx_page		= dpdkio_add_rx_page,
	.init_rx_irq		= dpdkio_init_rx_irq,
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
