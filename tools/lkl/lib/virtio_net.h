#ifndef _LKL_LIB_VIRTIO_NET_H
#define _LKL_LIB_VIRTIO_NET_H

#include "virtio.h"

/**
 * virtio_net_register - register a virtio net device
 *
 * @dev - the virtio dev to be registered
 * returns id of the registered device
 *
 */
int virtio_net_register(struct virtio_dev *dev,
			void (*remove)(struct virtio_dev *, int));

#endif /* _LKL_LIB_VIRTIO_NET_H */
