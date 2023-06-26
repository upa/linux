#ifndef _ASM_UAPI_LKL_DPDKIO_H
#define _ASM_UAPI_LKL_DPDKIO_H

#define LKL_DPDKIO_MAX_SEGS	32

struct lkl_dpdkio_pkt {
	struct iovec	segs[LKL_DPDKIO_MAX_SEGS]; /* sg list for a packet */
	int		nsegs;			/* number of segs */
	uint32_t	pkt_len;		/* total packet length */

	void 	*mbuf;	/* pointer to struct mbuf of this packet */
	void	*skb;	/* pointer to struct sk_buff of this packet */
};

#define LKL_DPDKIO_PAGE_SIZE		4096

#define LKL_DPDKIO_SLOT_NUM		512

#define LKL_DPDKIO_MEMPOOL_SURPLUS	512

#define LKL_DPDKIO_MEMPOOL_PAGE_NUM	\
	(LKL_DPDKIO_SLOT_NUM + LKL_DPDKIO_MEMPOOL_SURPLUS)

#define LKL_DPDKIO_MEMPOOL_SIZE	\
	(LKL_DPDKIO_PAGE_SIZE * LKL_DPDKIO_MEMPOOL_PAGE_NUM)


/* tools/lkl/lib/dpdkio.c */
int lkl_dpdkio_init(int argc, char **argv);

#endif
