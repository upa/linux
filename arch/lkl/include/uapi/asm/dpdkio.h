#ifndef _ASM_UAPI_LKL_DPDKIO_H
#define _ASM_UAPI_LKL_DPDKIO_H

#define DPDKIO_MAX_SEGS	32

struct lkl_dpdkio_pkt {
	struct iovec	segs[DPDKIO_MAX_SEGS];	/* sg list for a packet */
	int		nsegs;			/* number of segs */
	uint32_t	pkt_len;		/* total packet length */

	void 	*mbuf;	/* pointer to struct mbuf of this packet */
	void	*skb;	/* pointer to struct sk_buff of this packet */
};

#endif
