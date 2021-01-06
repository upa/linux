#ifndef _LKL_LIB_DPDKIO_NET_H
#define _LKL_LIB_DPDKIO_NET_H

int lkl_dpdkio_init(int argc, char **argv);

#include <lkl/asm/host_ops.h>

extern struct lkl_dpdkio_ops dpdkio_ops;


#endif /* _LKL_LIB_DPDKIO_NET_H */
