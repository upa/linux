#include <stdlib.h>
#include <lkl_host.h>
#include <lkl/asm/dpdkio.h>

#include "dpdkio.h"

static void *dpdkio_malloc(int size) {
	return malloc(size);
}

static int dpdkio_init_rxring(void *addr, int size)
{
	return 0;
}

static int dpdkio_setup(int nb_tx_desc, int nb_rx_desc)
{
	return 0;
}

static int dpdkio_start(void)
{
	return 0;
}

static int dpdkio_rx(struct lkl_dpdkio_pkt *pkts, int nb_pkts)
{
	return 0;
}

static void dpdkio_mbuf_free(void *mbuf)
{
	return;
}

static int dpdkio_tx(struct lkl_dpdkio_pkt *pkts, int nb_pkts)
{
	return 0;
}

static void dpdkio_free_skb(void *skb)
{
	return;
}

static void dpdkio_get_macaddr(char *mac)
{
	mac[0] = 0x00;
	mac[1] = 0x01;
	mac[2] = 0x02;
	mac[3] = 0x03;
	mac[4] = 0x04;
	mac[5] = 0x05;
}

struct lkl_dpdkio_ops dpdkio_ops = {
	.malloc		= dpdkio_malloc,
	.init_rxring	= dpdkio_init_rxring,
	.setup		= dpdkio_setup,
	.start		= dpdkio_start,
	.rx		= dpdkio_rx,
	.mbuf_free	= dpdkio_mbuf_free,
	.tx		= dpdkio_tx,
	.free_skb	= dpdkio_free_skb,
	.get_macaddr	= dpdkio_get_macaddr,
};
