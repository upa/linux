#ifndef _LKL_LIB_VHOST_H
#define _LKL_LIB_VHOST_H

#include "iomem.h"

#define LKL_VHOST_TYPE_NET	1
#define LKL_VHOST_TYPE_SCSI	2
#define LKL_VHOST_TYPE_VSOCK	3

struct vhost {
	int	type;
	struct lkl_iomem_ops *vhost_ops;
};

#endif /* _LKL_LIB_VHOST_H */
