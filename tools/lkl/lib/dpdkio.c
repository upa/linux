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

#define min(a, b) (a > b) ? b : a


//#define DEBUG_PKT_TX
//#define DEBUG_PKT_RX

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

struct dpdkio_irq {
	int irq;
	int irq_ack_fd;

	uint8_t enabled;
	uint8_t	no_ack;		/* do not wait ack when deliver irq */
};

/* structure representing lkl dpdkio backend port */
struct dpdkio_port {
	int portid;

	rte_iova_t	iova_start;	/* start iova of bootmem */

	/* rx */
	struct lkl_iovec	rx_regions[DPDKIO_MAX_RX_REGIONS];
	char			rx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*rx_mempool;

	struct lkl_dpdkio_ring	rx_ring; /* ring of mbuf for rx */
	uint8_t			rx_stop; /* 1 indicates stopping rx polling */
	struct dpdkio_irq	rx_irq;
	lkl_thread_t		rx_tid;

	/* tx */
	char			tx_mempool_name[DPDKIO_MEM_NAME_MAX];
	struct rte_mempool	*tx_mempool;

	struct lkl_dpdkio_ring	tx_ring; /* ring of lkl_dpdkio_slot for tx */
	int			tx_clean_count;
	uint8_t			tx_stop;
	struct dpdkio_irq	tx_irq;
	lkl_thread_t		tx_tid;

	/* mbuf queue to be released */
	struct lkl_dpdkio_ring free_rx_mbuf;

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
		void *addr = (void *)(segs[n].buf_addr + data_off);
		ret = write(fd, addr, data_len);
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

static inline void dpdkio_delay_us_sleep(unsigned int us)
{
	/* to reduce -Wdeprecated-declarations warnings at the compilet time */
	rte_delay_us_sleep(1000);
}

/* malloc for host_ops */

static void *dpdkio_malloc(int size)
{
	return rte_malloc(NULL, size, 0);
}

static void dpdkio_free(void *addr)
{
	rte_free(addr);
}


/**** irq handling ****/

static int dpdkio_init_irq(int *irq, int *irq_ack_fd)
{
	int irqn, ackfd = 0; /* irq_ack_fd 0 means ack is not needed */

	irqn = lkl_get_free_irq("dpdkio");
	if (irqn < 1) {
		pr_err("failed to get free irq\n");
		return irqn;
	}

	if (irq_ack_fd) {
		ackfd = eventfd(0, EFD_CLOEXEC);
		if (ackfd < 0) {

			pr_err("failed to create eventfd: %s\n",
			       strerror(errno));
			return -1 * errno;
		}
		*irq_ack_fd = ackfd;
	}

	*irq = irqn;

	return irqn;
}

static int dpdkio_init_tx_irq(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct dpdkio_irq *irq = &port->tx_irq;

	/* tx irq, which notifies lkl kernel that there are returned
	 * tx(ed) stlos. it does not need to wait ack. */
	return dpdkio_init_irq(&irq->irq, NULL);
}

static int dpdkio_init_rx_irq(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct dpdkio_irq *irq = &port->rx_irq;

	return dpdkio_init_irq(&irq->irq, &irq->irq_ack_fd);
}

static struct dpdkio_irq *dpdkio_which_irq(struct dpdkio_port *port,
					   int _irq)
{
	struct dpdkio_irq *irq;

	if (port->tx_irq.irq == _irq)
		irq = &port->tx_irq;
	else if (port->rx_irq.irq == _irq)
		irq = &port->rx_irq;
	else {
		pr_err("invalid irq number %d\n", _irq);
		assert(0);
	}
	return irq;
}

static void dpdkio_enable_irq(int portid, int _irq)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct dpdkio_irq *irq = dpdkio_which_irq(port, _irq);

	irq->enabled = 1;
}

static void dpdkio_disable_irq(int portid, int _irq)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct dpdkio_irq *irq = dpdkio_which_irq(port, _irq);

	irq->enabled = 0;
}

#define dpdkio_is_irq_enabled(irq) ((irq)->enabled)

static void dpdkio_ack_irq(int portid, int _irq)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct dpdkio_irq *irq = dpdkio_which_irq(port, _irq);
	unsigned long v = 1;
	int ret;

	ret = write(irq->irq_ack_fd, &v, sizeof(v));
	if (unlikely(ret < 0))
		pr_err("write: %s\n", strerror(errno));
}

static void dpdkio_deliver_irq(struct dpdkio_irq *irq)
{
	uint64_t v;
	int ret;

	lkl_trigger_irq(irq->irq);

	if (irq->irq_ack_fd == 0)
		return;

	/* wait until irq is acked. write(irq_ack_fd) is called via
	 * host_ops->dpdkio_ops->ack_irq, which is dpdkio_ack_irq.
	 */
	ret = read(irq->irq_ack_fd, &v, sizeof(v));
	if(unlikely(ret < 0))
		pr_err("read: %s\n", strerror(errno));
}



/**** rx path ****/

static void dpdkio_return_rx_mbuf(int portid, void *mbuf)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct lkl_dpdkio_ring *r = &port->free_rx_mbuf;

	/* called by lkl kernel (recycle to consumed rx packet) */

	if (unlikely(lkl_dpdkio_ring_full(r))) {
		pr_err("mbuf free ring full on port %d!\n!", portid);
		assert(0); /* XXX */
	}

	r->ptrs[r->head] = mbuf;
	lkl_dpdkio_ring_write_next(r, 1);
}

#define MAX_FREE_MBUF_BULK_NUM	32

static void dpdkio_free_rx_mbuf(struct dpdkio_port *port)
{
	struct lkl_dpdkio_ring *r = &port->free_rx_mbuf;
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

/**** rx packets ****/

static unsigned int dpdkio_rx(struct dpdkio_port *port)
{
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_BURST];
	struct lkl_dpdkio_ring *r = &port->rx_ring;
	unsigned int a, b, n, nb_rx;

	/* call rte_eth_rx_burst and save the received *mbufs* on
	 * rx_ring. the received mbufs will be converted into slots by
 	 * dpdkio_dequeue() because slots are exist on the lkl kernel
	 * side. */

	dpdkio_free_rx_mbuf(port);

	a = lkl_dpdkio_ring_write_avail(r);
	b = min(LKL_DPDKIO_MAX_BURST, a);

	if (!b)
		return 0;

	nb_rx = rte_eth_rx_burst(port->portid, 0, mbufs, b);

	for (n = 0; n < nb_rx; n++) {
#ifdef DEBUG_PKT_RX
		pr_warn("======== RX ========\n");
		rte_pktmbuf_dump(stdout, mbufs[n], 0);
		printf("\n");
#endif
		r->ptrs[(r->head + n) & LKL_DPDKIO_RING_MASK] = mbufs[n];
	}

	lkl_dpdkio_ring_write_next(r, nb_rx);

	return nb_rx;
}

static void dpdkio_rx_thread(void *arg)
{
	struct dpdkio_port *port = arg;
	struct lkl_dpdkio_ring *r = &port->rx_ring;
	unsigned int nb_rx, wait = 0, a;

	/* receive packets from dpdk and store the packets into
	 * rx_ring as lkl_dpdkio_slot.
	 */

	do {
		if (unlikely(port->rx_stop)) {
			dpdkio_delay_us_sleep(100);
			continue;
		}

		nb_rx = dpdkio_rx(port);
		a = lkl_dpdkio_ring_read_avail(r);
			

		if (0 < nb_rx || a) {
			wait = 0;
		} else if (nb_rx == 0)
			wait = (((wait + 1) & 0x0F) | 0x01);
		else {
			pr_err("rte_eth_rx_queue_count: %s\n",
			       strerror(-1 * nb_rx));
		}

		if (wait == 0) {
			/* there are pending packet(s) in the rx queue */
			if (dpdkio_is_irq_enabled(&port->rx_irq))
				dpdkio_deliver_irq(&port->rx_irq);
			else
				dpdkio_delay_us_sleep(1);
		} else
			dpdkio_delay_us_sleep(wait);

	} while (1);
}


/**** dequeue ****/

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

static int dpdkio_dequeue(int portid, struct lkl_dpdkio_slot **slots,
			  unsigned int nb_pkts)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct lkl_dpdkio_ring *r = &port->rx_ring;
	struct rte_mbuf *mbuf;
	unsigned int a, b, n;
	int ret, i;

	a = lkl_dpdkio_ring_read_avail(r);
	b = min(a, nb_pkts);

	if (!b)
		return 0;

	for (i = 0, n = 0; n < b; n++) {
		mbuf = r->ptrs[(r->tail + n) & LKL_DPDKIO_RING_MASK];
		ret = dpdkio_rx_mbuf_to_slot(portid, mbuf, slots[i]);
		if (unlikely(ret < 0)) {
			pr_err("failed to convert mbuf to slot\n");
			rte_pktmbuf_free(mbuf);
			continue;
		}
		i++;
	}

	lkl_dpdkio_ring_read_next(r, n);

	return i;
}

/**** tx path *****/

static void dpdkio_extmem_free_cb(void *addr, void *opaque)
{
	struct lkl_dpdkio_slot *slot = opaque;
	struct dpdkio_port *port = dpdkio_port_get(slot->portid);

	lkl_host_ops.dpdkio_ops->return_tx_slot(slot->portid, slot);

#define DPDKIO_TX_CLEAN_COUNT_FOR_IRQ	16

	port->tx_clean_count++;
	if (port->tx_clean_count > DPDKIO_TX_CLEAN_COUNT_FOR_IRQ &&
	    dpdkio_is_irq_enabled(&port->tx_irq)) {
		dpdkio_deliver_irq(&port->tx_irq);
		port->tx_clean_count = 0;
	}
}

/**** tx packets ****/

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

		if (slot->nsegs > 1) {
			mbuf->ol_flags |= PKT_TX_TCP_SEG;
			mbuf->l2_len = slot->l2_len;
			mbuf->l3_len = slot->l3_len;
			mbuf->l4_len = slot->l4_len;
			mbuf->tso_segsz = slot->tso_segsz;
		}
	}
}

static struct rte_mbuf_ext_shared_info *
dpdkio_get_mbuf_shared_info(struct lkl_dpdkio_slot *slot)
{
	return (struct rte_mbuf_ext_shared_info *)slot->opaque;
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


static void dpdkio_tx(int portid, struct lkl_dpdkio_slot **slots, int nb_pkts)
{
	struct rte_mbuf *mbufs[LKL_DPDKIO_MAX_BURST], *mbuf;
	int n, i, nb_tx;

	for (i = 0, n = 0; n < nb_pkts; n++) {
#ifdef DEBUG_PKT_TX
		pr_warn("======== TX ========\n");
		dpdkio_slot_dump(slots[n]);
#endif

		mbuf = dpdkio_tx_slot_to_mbuf(portid, slots[n]);

#ifdef DEBUG_PKT_TX
		rte_pktmbuf_dump(stdout, mbuf, 0);
		printf("\n");
#endif
		if (likely(mbuf)) {
			mbufs[i] = mbuf;
			i++;
		}
	}

	if (unlikely(i == 0))
		pr_err("0 tx\n");

	do {
		nb_tx = rte_eth_tx_burst(portid, 0, mbufs, i);
		i -= nb_tx;
	} while (i > 0);
}

static void dpdkio_tx_thread(void *arg)
{
	struct lkl_dpdkio_slot *slots[LKL_DPDKIO_MAX_BURST];
	struct dpdkio_port *port = arg;
	struct lkl_dpdkio_ring *r = &port->tx_ring;
	unsigned int n, b, a, wait = 0;

	/* transmit packets on tx_ring */

	do {
		if (unlikely(port->tx_stop)) {
			dpdkio_delay_us_sleep(1000);
			continue;
		}

		a = lkl_dpdkio_ring_read_avail(r);
		b = min(a, LKL_DPDKIO_MAX_BURST);

#if 1
		if (0 < b)
			wait = 0;
		else if (b == 0)
			wait = (((wait + 1) & 0x0F) | 0x01);

		if (wait > 0) {
			dpdkio_delay_us_sleep(wait);
			continue;
		}
#else
		/* busy loop */
		if (b == 0)
			continue;
#endif
		/* there are pending packets on the tx_ring */
		for (n = 0; n < b; n++) {
			slots[n] = r->ptrs[((r->tail + n) &
					    LKL_DPDKIO_RING_MASK)];
		}
		dpdkio_tx(port->portid, slots, b);
		lkl_dpdkio_ring_read_next(r, b);

	} while (1);
}


/**** enqueue ****/

static unsigned int dpdkio_enqueue(int portid, struct lkl_dpdkio_slot *slot)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct lkl_dpdkio_ring *r = &port->tx_ring;
	unsigned int a;

	a = lkl_dpdkio_ring_write_avail(r);

	if (a == 0) {
		pr_warn("no available slot on tx queue\n");
		return 0;
	}

	r->ptrs[r->head] = slot;
	lkl_dpdkio_ring_write_next(r, 1);

	return 1;
}


/**** port initialization, setup, start, and stop ****/

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

	return 0;
}

static int dpdkio_add_rx_region(int portid, unsigned long addr, int size)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	int n;

	if (size <= 0) {
		pr_err("invalid size %d\n", size);
		return -EINVAL;
	}

	for (n = 0; n < DPDKIO_MAX_RX_REGIONS; n++) {
		struct lkl_iovec *reg = &port->rx_regions[n];
		if (reg->iov_len == 0) {
			reg->iov_base = (void *)addr;
			reg->iov_len = size;
			return 0;
		}
	}

	pr_err("no available slot for the rx region\n");
	return -1;
}

/* mainly copied from dpdk/app/test-pmd/testpmd.c*/

static int dpdkio_rx_region_to_extmem(int portid,
				      int mbuf_size, struct lkl_iovec *reg,
				      struct rte_pktmbuf_extmem **ext_mem)
{
	struct rte_pktmbuf_extmem *xmem;
	int n, elt_num, elt_size;

	/* I assume mbuf_size aligned to pagesz, so next line has no sense */
	elt_size = RTE_ALIGN_CEIL(mbuf_size, RTE_CACHE_LINE_SIZE);
	elt_num = reg->iov_len / elt_size;

	xmem = malloc(sizeof(struct rte_pktmbuf_extmem) * elt_num);
	if (!xmem) {
		pr_err("failed to alloc rte_pktmbuf_extmem: %s",
		       strerror(errno));
		return -ENOMEM;
	}

	for (n = 0; n < elt_num; n++) {
		struct rte_pktmbuf_extmem *x = xmem + n;
		void *addr = reg->iov_base + (elt_size * n);
		x->buf_ptr = addr;
		x->buf_iova = rte_mem_virt2iova(addr);
		x->buf_len = elt_size;
		x->elt_size = elt_size;
	}

	*ext_mem = xmem;
	return n;
}

static int dpdkio_rx_regions_to_extmem(int portid, int mbuf_size,
				       struct rte_pktmbuf_extmem **ext_mem)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	struct rte_pktmbuf_extmem *xmem = NULL;
	int nr_extmem = 0, nr_extmem_new = 0;
	size_t segs_size = 0, nr_segs = 0;
	int n, i, ret;

	for (n = 0; n < DPDKIO_MAX_RX_REGIONS; n++) {
		struct lkl_iovec *reg = &port->rx_regions[n];
		struct rte_pktmbuf_extmem *x;

		if (reg->iov_len == 0)
			break;
		segs_size += reg->iov_len;
		nr_segs++;

		ret = dpdkio_rx_region_to_extmem(portid, mbuf_size, reg, &x);
		if (ret < 0)
			return -1;

		nr_extmem_new = nr_extmem + ret;
		xmem = realloc(xmem, sizeof(*xmem) * nr_extmem_new);
		if (!xmem) {
			pr_err("failed to alloc for extmem\n");
			return -1;
		}

		for (i = 0; i < ret; i++)
			xmem[nr_extmem + i] = x[i];
		free(x); /* malloc()ed in dpdkio_rx_region_to_extmem */

		nr_extmem = nr_extmem_new;
	}

	*ext_mem = xmem;

	pr_info("%d extmem segs on %lu-byte %lu rx regions\n",
		nr_extmem, segs_size, nr_segs);

	return nr_extmem;
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
	struct rte_pktmbuf_extmem *ext_mem;
	int nr_extmem;
	int mbuf_size = 1 << 12; /* must be 4k!! 2021/5/17 17:31 */

	nr_extmem = dpdkio_rx_regions_to_extmem(portid, mbuf_size, &ext_mem);
	if (nr_extmem < 0) {
		pr_err("failed to prepare extmem on rx region\n");
		return nr_extmem;
	}

	port->rx_mempool = rte_pktmbuf_pool_create_extbuf
		(port->rx_mempool_name, nb_rxd << 2, 512, 0, mbuf_size,
		 rte_socket_id(), ext_mem, nr_extmem);

	if (!port->rx_mempool) {
		pr_err("faield to create rx mbuf pool %s: %s\n",
		       port->rx_mempool_name, strerror(rte_errno));
		return rte_errno * -1;
	}

	struct rte_eth_rxconf rxconf = dev_info.default_rxconf;
	//rxconf.rx_free_thresh = nb_rxd >> 1;
	//rxconf.rx_drop_en = 1;
	rxconf.offloads = port_conf.rxmode.offloads;

	ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_socket_id(),
				     &rxconf, port->rx_mempool);
	if (ret < 0) {
		pr_err("failed to setup rx queue port %d queue 0: %s\n",
		       portid, strerror(ret * -1));
		return ret;
	}

	/* launch tx and rx threads */
	port->tx_tid = lkl_host_ops.thread_create(dpdkio_tx_thread, port);
	if (port->tx_tid == 0) {
		pr_err("failed to launch tx thread\n");
		return ret;
	}

	port->rx_tid = lkl_host_ops.thread_create(dpdkio_rx_thread, port);
	if (port->rx_tid == 0) {
		pr_err("failed to launch rx thread\n");
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


static void dpdkio_start_tx_thread(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	port->tx_stop = 0;
}

static void dpdkio_stop_tx_thread(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	port->tx_stop = 1;
}

static void dpdkio_start_rx_thread(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	port->rx_stop = 0;
}

static void dpdkio_stop_rx_thread(int portid)
{
	struct dpdkio_port *port = dpdkio_port_get(portid);
	port->rx_stop = 1;
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

	dpdkio_start_tx_thread(portid);
	dpdkio_start_rx_thread(portid);

	return 0;
}

static int dpdkio_stop(int portid)
{
	int ret;

	dpdkio_stop_tx_thread(portid);
	dpdkio_stop_rx_thread(portid);

	ret = rte_eth_dev_stop(portid);
	if (ret < 0) {
		pr_err("rte_eth_dev_stop: %s\n", strerror(ret * 1));
		return ret;
	}

	return 0;
}


/**** misc ****/

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
	.add_rx_region		= dpdkio_add_rx_region,

	.init_tx_irq		= dpdkio_init_tx_irq,
	.init_rx_irq		= dpdkio_init_rx_irq,
	.enable_irq		= dpdkio_enable_irq,
	.disable_irq		= dpdkio_disable_irq,
	.ack_irq		= dpdkio_ack_irq,

	.setup			= dpdkio_setup,
	.start			= dpdkio_start,
	.stop			= dpdkio_stop,

	.dequeue		= dpdkio_dequeue,
	.return_rx_mbuf		= dpdkio_return_rx_mbuf,

	.enqueue		= dpdkio_enqueue,
	.return_tx_slot		= NULL,	/* filled by lkl/kernel/dpdkio.c */

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
