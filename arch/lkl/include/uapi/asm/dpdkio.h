#ifndef _ASM_UAPI_LKL_DPDKIO_H
#define _ASM_UAPI_LKL_DPDKIO_H

#define LKL_DPDKIO_MAX_BURST	32
#define LKL_DPDKIO_MAX_SEGS	16

struct lkl_dpdkio_seg {
	unsigned long	buf_addr;
	unsigned int	buf_len;
	unsigned int	data_off;
	unsigned int	data_len;
};

struct lkl_dpdkio_slot {
	struct lkl_dpdkio_seg	segs[LKL_DPDKIO_MAX_SEGS]; /* packet  */
	uint16_t		nsegs;		/* number of segs */
	uint16_t		pkt_len;	/* total packet length */

	void 	*mbuf;	/* pointer to struct mbuf of this packet */
	void	*skb;	/* pointer to struct sk_buff of this packet */

	/* header sizes from rte_mbuf_core.h for TX offload */
	union {
		uint64_t tx_offload;
		struct {
			uint64_t	l2_len:7;
			uint64_t	l3_len:9;
			uint64_t	l4_len:8;
			uint64_t	tso_segsz:16;
			uint64_t	outer_l3_len:9;
			uint64_t	outer_l2_len:7;
		};
	};
	uint16_t	eth_protocol;	/* ETH_P_* */
	uint8_t		ip_protocol;	/* IPPROTO_* */

	/* rx checksum, LKL_DPDKIO_RX_IP_CKSUM_* */
	uint8_t		rx_ip_cksum_result;

	uint16_t	portid;	/* dpdkio port id */

	char opaque[32];  /* used as rte_mbuf_ext_shared_info structures */
};

/* XXX: we need to consider L4 checksum */
#define LKL_DPDKIO_RX_IP_CKSUM_UNKNOWN	0
#define LKL_DPDKIO_RX_IP_CKSUM_BAD	1
#define LKL_DPDKIO_RX_IP_CKSUM_GOOD	2
#define LKL_DPDKIO_RX_IP_CKSUM_NONE	3

#define LKL_DPDKIO_PAGE_SIZE		4096

#define LKL_DPDKIO_SLOT_NUM		1024	/* must be power of 2*/
#define LKL_DPDKIO_SLOT_MASK		(LKL_DPDKIO_SLOT_NUM - 1)
/* Note that a lkl_dpdkio_slot represents a packet including multiple
 * segments. Thus, the numbers of mbufs on tx/rx mempool must be
 * larger than LKL_DPDKIO_SLOT_NUM, for exmaple,
 (LKL_DPDKIO_SLOT_NUM x LKL_DPDKIO_MAX_SEGS). */


#define LKL_DPDKIO_TX_DESC_NUM		512
#define LKL_DPDKIO_RX_DESC_NUM		1024
#define LKL_DPDKIO_RX_PAGE_NUM		8192

/* tools/lkl/lib/dpdkio.c */
int lkl_dpdkio_init(int argc, char **argv);
int lkl_dpdkio_exit(void);


/* ring queue for freeing mbuf (lkl rx -> dpdk) and skb (dpdk tx -> lkl) */

#define LKL_DPDKIO_RING_SIZE	512	/* power of 2*/
#define LKL_DPDKIO_RING_MASK   	(LKL_DPDKIO_RING_SIZE - 1)

struct lkl_dpdkio_ring {
	unsigned int	head;
	unsigned int	tail;

	void		*ptrs[LKL_DPDKIO_RING_SIZE];
};
/* XXX: needs lock? there are only a reader and a writer */

static inline int lkl_dpdkio_ring_emtpy(struct lkl_dpdkio_ring *r)
{
	return (r->head == r->tail) ? 1 : 0;
}

static inline int lkl_dpdkio_ring_full(struct lkl_dpdkio_ring *r)
{
	return (((r->head + 1) & LKL_DPDKIO_RING_MASK) == r->tail) ? 1: 0;
}

static inline void lkl_dpdkio_ring_write_next(struct lkl_dpdkio_ring *r,
					  unsigned int n)
{
	r->head = (r->head + n) & LKL_DPDKIO_RING_MASK;
}

static inline void lkl_dpdkio_ring_read_next(struct lkl_dpdkio_ring *r,
					 unsigned int n)
{
	r->tail = (r->tail + n) & LKL_DPDKIO_RING_MASK;
}

static inline unsigned int lkl_dpdkio_ring_write_avail(struct lkl_dpdkio_ring *r)
{
	int ret;

	ret = r->tail - r->head;
	if (ret <= 0)
		ret += LKL_DPDKIO_RING_SIZE;
	return ret;
}

static inline unsigned int lkl_dpdkio_ring_read_avail(struct lkl_dpdkio_ring *r)
{
	int ret;

	ret = r->head - r->tail;
	if (ret < 0)
		ret += LKL_DPDKIO_RING_SIZE;
	return ret;
}


#endif
