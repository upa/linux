#ifndef _ASM_UAPI_LKL_DPDKIO_H
#define _ASM_UAPI_LKL_DPDKIO_H

#define LKL_DPDKIO_MAX_BURST	128
#define LKL_DPDKIO_MAX_SEGS	32

struct lkl_dpdkio_slot {
	struct iovec	segs[LKL_DPDKIO_MAX_SEGS]; /* sg list for a packet */
	int		nsegs;			/* number of segs */
	uint32_t	pkt_len;		/* total packet length */

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

	char opaque[32]; /* used as rte_mbuf_ext_shared_info structures */
};

/* XXX: we need to consider L4 checksum */
#define LKL_DPDKIO_RX_IP_CKSUM_UNKNOWN	0
#define LKL_DPDKIO_RX_IP_CKSUM_BAD	1
#define LKL_DPDKIO_RX_IP_CKSUM_GOOD	2
#define LKL_DPDKIO_RX_IP_CKSUM_NONE	3

#define LKL_DPDKIO_PAGE_SIZE		4096

#define LKL_DPDKIO_SLOT_NUM		512	/* must be power of 2*/
#define LKL_DPDKIO_SLOT_MASK		(LKL_DPDKIO_SLOT_NUM - 1)

#define LKL_DPDKIO_MEMPOOL_SURPLUS	512

#define LKL_DPDKIO_MEMPOOL_PAGE_NUM	\
	(LKL_DPDKIO_SLOT_NUM + LKL_DPDKIO_MEMPOOL_SURPLUS)

#define LKL_DPDKIO_MEMPOOL_SIZE	\
	(LKL_DPDKIO_PAGE_SIZE * LKL_DPDKIO_MEMPOOL_PAGE_NUM)


/* tools/lkl/lib/dpdkio.c */
int lkl_dpdkio_init(int argc, char **argv);

#endif
