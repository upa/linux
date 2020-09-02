#include <errno.h>
#include <string.h>
#include <lkl_host.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/if_tun.h>
#include <linux/vhost.h>

#include "virtio.h"


/* copied from virtio_net.c */

#define netdev_of(x) (container_of(x, struct vhost_net_dev, dev))
#define BIT(x) (1ULL << x)

/* We always have 2 queues on a netdev: one for tx, one for rx. */
#define RX_QUEUE_IDX 0
#define TX_QUEUE_IDX 1

#define NUM_QUEUES (TX_QUEUE_IDX + 1)
#define QUEUE_DEPTH 128

/* In fact, we'll hit the limit on the devs string below long before
 * we hit this, but it's good enough for now. */
#define MAX_NET_DEVS 16



#define VIRTIO_DEV_MAGIC		0x74726976
#define VIRTIO_DEV_VERSION		2

#define VIRTIO_MMIO_MAGIC_VALUE		0x000
#define VIRTIO_MMIO_VERSION	     	0x004
#define VIRTIO_MMIO_DEVICE_ID		0x008
#define VIRTIO_MMIO_VENDOR_ID		0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES	0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL	0x014
#define VIRTIO_MMIO_DRIVER_FEATURES	0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL	0x024
#define VIRTIO_MMIO_QUEUE_SEL		0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX	0x034
#define VIRTIO_MMIO_QUEUE_NUM		0x038
#define VIRTIO_MMIO_QUEUE_READY		0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY	0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060
#define VIRTIO_MMIO_INTERRUPT_ACK	0x064
#define VIRTIO_MMIO_STATUS		0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW	0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW     0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH    0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW      0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH     0x0a4
#define VIRTIO_MMIO_CONFIG_GENERATION   0x0fc
#define VIRTIO_MMIO_CONFIG		0x100
#define VIRTIO_MMIO_INT_VRING		0x01
#define VIRTIO_MMIO_INT_CONFIG		0x02

#define BIT(x) (1ULL << x)

#define vhost_net_panic(msg, ...) do {					\
		lkl_printf("LKL vhost-net error" msg, ##__VA_ARGS__);	\
		lkl_host_ops.panic();					\
	} while (0)



struct vhost_net_dev {
	struct virtio_dev dev;
	struct lkl_virtio_net_config config;

	int vhost_net_fd;
	int backend_fd;
	int vnet_hdr_len;

	/* used for poll thread */
	lkl_thread_t poll_tid;
	int qnum;
	int pollstop;
};

static int vhost_net_ioctl(struct vhost_net_dev *dev, unsigned int long req,
			   void *arg)
{
	int ret;

	ret = ioctl(dev->vhost_net_fd, req, arg);
	if (ret < 0) {
		lkl_printf("%s: ioctl %lu: %s\n", __func__, req,
			   strerror(errno));
	}

	return ret;
}

static int vhost_net_set_owner(struct vhost_net_dev *dev)
{
	if (vhost_net_ioctl(dev, VHOST_SET_OWNER, 0) < 0)
		return -1;
	if (vhost_net_ioctl(dev, VHOST_RESET_OWNER, 0) < 0)
		return -1;
	if (vhost_net_ioctl(dev, VHOST_SET_OWNER, 0) < 0)
		return -1;

	return 0;
}

static uint32_t vhost_net_read_device_features(struct vhost_net_dev *dev)
{
	struct virtio_dev *vdev = &dev->dev;

	if (vdev->device_features_sel)
		return (uint32_t)(vdev->device_features >> 32);

	return (uint32_t)vdev->device_features;
}

static int vhost_net_read(void *data, int offset, void *res, int size)
{
	struct virtio_dev *vdev = (struct virtio_dev *)data;
	struct vhost_net_dev *dev = netdev_of(vdev);
	uint32_t val;

	if (offset >= VIRTIO_MMIO_CONFIG) {
		offset -= VIRTIO_MMIO_CONFIG;
		if (offset + size > vdev->config_len)
			return -LKL_EINVAL;
		memcpy(res, vdev->config_data + offset, size);
		return 0;
	}

	if (size != sizeof(uint32_t))
		return -LKL_EINVAL;

	switch(offset) {
	case VIRTIO_MMIO_MAGIC_VALUE:
		val = VIRTIO_DEV_MAGIC;
		break;
	case VIRTIO_MMIO_VERSION:
		val = VIRTIO_DEV_VERSION;
		break;
	case VIRTIO_MMIO_DEVICE_ID:
		val = vdev->device_id;
		break;
	case VIRTIO_MMIO_VENDOR_ID:
		val = vdev->vendor_id;
		break;
	case VIRTIO_MMIO_DEVICE_FEATURES:
		val = vhost_net_read_device_features(dev);
		break;
	case VIRTIO_MMIO_QUEUE_NUM_MAX:
		val = vdev->queue[vdev->queue_sel].num_max;
		break;
	case VIRTIO_MMIO_QUEUE_READY:
		val = vdev->queue[vdev->queue_sel].ready;
		break;
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		val = vdev->int_status;
		break;
	case VIRTIO_MMIO_STATUS:
		val = vdev->status;
		break;
	case VIRTIO_MMIO_CONFIG_GENERATION:
		val = vdev->config_gen;
		break;
	default:
		return -1;
	}

	*(uint32_t *)res = htole32(val);

	return 0;
}

static inline void vhost_net_write_driver_features(struct vhost_net_dev *dev,
						   uint32_t val)
{
	uint64_t tmp;

	if (dev->dev.driver_features_sel) {
		tmp = dev->dev.driver_features & 0xFFFFFFFF;
		dev->dev.driver_features = tmp | (uint64_t)val << 32;
	} else {
		tmp = dev->dev.driver_features & 0xFFFFFFFF00000000;
		dev->dev.driver_features = tmp | val;
	}
}

static int vhost_net_set_vring_num(struct vhost_net_dev *dev, uint32_t num)
{
	struct vhost_vring_state s = {
		.index = dev->dev.queue_sel,
		.num = num,
	};
	return vhost_net_ioctl(dev, VHOST_SET_VRING_NUM, &s);
}

static int vhost_net_set_eventfd(struct vhost_net_dev *dev)
{
	struct virtio_dev *vdev = &dev->dev;
	struct virtio_queue *q = &vdev->queue[vdev->queue_sel];
	struct vhost_vring_file f;

	q->kick_fd = eventfd(0, 0);
	if (q->kick_fd < 0) {
		lkl_printf("%s: eventfd(): %s\n", __func__, strerror(errno));
		return -1;
	}
	q->call_fd = eventfd(0, 0);
	if (q->call_fd < 0) {
		lkl_printf("%s: eventfd(): %s\n", __func__, strerror(errno));
		return -1;
	}

	f.index = vdev->queue_sel;
	f.fd = q->kick_fd;
	if (vhost_net_ioctl(dev, VHOST_SET_VRING_KICK, &f) < 0) {
		lkl_printf("VHOST_SET_VRING_KICK failed\n");
		return -1;
	}

	f.index = vdev->queue_sel;
	f.fd = q->call_fd;
	if (vhost_net_ioctl(dev, VHOST_SET_VRING_CALL, &f) < 0) {
		lkl_printf("VHOST_SET_VRING_CALL failed\n");
		return -1;
	}

	return 0;
}

static int vhost_net_kick(struct vhost_net_dev *dev, uint32_t qidx)
{
	struct virtio_queue *q = &dev->dev.queue[qidx];
	uint64_t v = 1;
	int ret;

	ret = write(q->kick_fd, &v, sizeof(v));
	if (ret < 0)
		lkl_printf("%s: write(): %s\n", __func__, strerror(errno));

	return ret;
}

static int vhost_net_set_vring_addr(struct vhost_net_dev *dev)
{
	struct virtio_dev *vdev = &dev->dev;
	struct virtio_queue *q = &vdev->queue[vdev->queue_sel];
	struct vhost_vring_addr a;

	a.index = vdev->queue_sel;
	a.flags = 0;	/* XXX: how should we use logging? */
	a.desc_user_addr = (uintptr_t)q->desc;
	a.used_user_addr = (uintptr_t)q->used;
	a.avail_user_addr = (uintptr_t)q->avail;
	a.log_guest_addr = (uintptr_t)q->log;

	if (vhost_net_ioctl(dev, VHOST_SET_VRING_ADDR, &a) < 0) {
		lkl_printf("%s: ioctl VHOST_SET_VRING_ADDR failed: %s\n",
			   __func__, strerror(errno));
		return -1;
	}

	return 0;
}

static int vhost_net_set_backend(struct vhost_net_dev *dev)
{
	int ret = 0;
	struct vhost_vring_file f = {
		.index	= dev->dev.queue_sel,
		.fd	= dev->backend_fd,
	};

	ret = vhost_net_ioctl(dev, VHOST_NET_SET_BACKEND, &f);
	if (ret < 0)
		lkl_printf("ioctl VHOSET_NET_SET_BACKEND failed: %s\n",
			   strerror(errno));

	return ret;
}

static int vhost_net_set_mem_table(struct vhost_net_dev *dev)
{
	struct vhost_mem {
		struct vhost_memory m;
		struct vhost_memory_region r[1];
	} vmem;
	int ret;

	vmem.m.nregions = 1;
	vmem.r[0].guest_phys_addr = lkl_host_ops.memory_start;
	vmem.r[0].memory_size = lkl_host_ops.memory_size;
	vmem.r[0].userspace_addr = lkl_host_ops.memory_start;

	ret = vhost_net_ioctl(dev, VHOST_SET_MEM_TABLE, &vmem);
	if (ret < 0)
		lkl_printf("ioctl VHOST_SET_MEM_TABLE faield: %s\n",
			   strerror(errno));

	return ret;
}

static inline void set_ptr_low(void **ptr, uint32_t val)
{
	uint64_t tmp = (uintptr_t)*ptr;

	tmp = (tmp & 0xFFFFFFFF00000000) | val;
	*ptr = (void *)(long)tmp;
}

static inline void set_ptr_high(void **ptr, uint32_t val)
{
	uint64_t tmp = (uintptr_t)*ptr;

	tmp = (tmp & 0x00000000FFFFFFFF) | ((uint64_t)val << 32);
	*ptr = (void *)(long)tmp;
}

static inline void set_status(struct virtio_dev *dev, uint32_t val)
{
	if ((val & LKL_VIRTIO_CONFIG_S_FEATURES_OK) &&
	    (!(dev->driver_features & BIT(LKL_VIRTIO_F_VERSION_1)) ||
	     !(dev->driver_features & BIT(LKL_VIRTIO_RING_F_EVENT_IDX)) ||
	     !(dev->driver_features == dev->device_features)))
		val &= ~LKL_VIRTIO_CONFIG_S_FEATURES_OK;
	dev->status = val;
}

static int vhost_net_write(void *data, int offset, void *res, int size)
{
	struct virtio_dev *vdev = (struct virtio_dev *)data;
	struct vhost_net_dev *dev = netdev_of(vdev);
	struct virtio_queue *q = &vdev->queue[vdev->queue_sel];
	uint32_t val;
	int ret = 0;

	if (offset >= VIRTIO_MMIO_CONFIG) {
		offset -= VIRTIO_MMIO_CONFIG;

		if (offset + size >= vdev->config_len)
			return -LKL_EINVAL;
		memcpy(vdev->config_data + offset, res, size);
		return 0;
	}

	if (size != sizeof(uint32_t))
		return -LKL_EINVAL;

	val = le32toh(*(uint32_t *)res);

	switch (offset) {
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
		if (val > 1)
			return -LKL_EINVAL;
		vdev->device_features_sel = val;
		break;
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
		if (val > 1)
			return -LKL_EINVAL;
		vdev->driver_features_sel  = val;
		break;
	case VIRTIO_MMIO_DRIVER_FEATURES:
		vhost_net_write_driver_features(dev, val);
		break;
	case VIRTIO_MMIO_QUEUE_SEL:
		vdev->queue_sel = val;
		break;
	case VIRTIO_MMIO_QUEUE_NUM:
		vdev->queue[vdev->queue_sel].num = val;	/* XXX: not needed? */
		ret = vhost_net_set_vring_num(dev, val);
		if (ret < 0)
			break;
		ret = vhost_net_set_eventfd(dev);
		q->log = lkl_host_ops.mem_alloc(4096);	/* XXX: ?????? */
		dev->qnum++;
		break;
	case VIRTIO_MMIO_QUEUE_READY:
		vdev->queue[vdev->queue_sel].ready = val;
		if (val) {
			ret = vhost_net_set_backend(dev);
			if (ret < 0)
				break;
			ret = vhost_net_set_mem_table(dev);
			if (ret < 0)
				break;
		}
		break;
	case VIRTIO_MMIO_QUEUE_NOTIFY:
		vhost_net_kick(dev, val);
		break;
	case VIRTIO_MMIO_INTERRUPT_ACK:
		vdev->int_status = 0;
		break;
	case VIRTIO_MMIO_STATUS:
		set_status(vdev, val);
		break;
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
		set_ptr_low((void **)&q->desc, val);
		break;
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
		set_ptr_high((void **)&q->desc, val);
		break;
	case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
		set_ptr_low((void **)&q->avail, val);
		break;
	case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
		set_ptr_high((void **)&q->avail, val);
		break;
	case VIRTIO_MMIO_QUEUE_USED_LOW:
		set_ptr_low((void **)&q->used, val);
		break;
	case VIRTIO_MMIO_QUEUE_USED_HIGH:
		set_ptr_high((void **)&q->used, val);
		break;
	default:
		ret = -1;
	}

	if (offset == VIRTIO_MMIO_QUEUE_DESC_LOW ||
	    offset == VIRTIO_MMIO_QUEUE_DESC_HIGH ||
	    offset == VIRTIO_MMIO_QUEUE_AVAIL_LOW ||
	    offset == VIRTIO_MMIO_QUEUE_AVAIL_HIGH ||
	    offset == VIRTIO_MMIO_QUEUE_USED_LOW ||
	    offset == VIRTIO_MMIO_QUEUE_USED_HIGH)
		ret = vhost_net_set_vring_addr(dev);

	return ret;
}

static struct lkl_iomem_ops vhost_net_ops = {
	.read	= vhost_net_read,
	.write	= vhost_net_write,
};

static struct vhost vhost_net = {
	.type		= LKL_VHOST_TYPE_NET,
	.vhost_ops	= &vhost_net_ops,
};



static void virtio_deliver_irq(struct virtio_dev *dev)
{
	dev->int_status |= VIRTIO_MMIO_INT_VRING;
	__sync_synchronize();
	lkl_trigger_irq(dev->irq);
}

static void vhost_net_poll_thread(void *arg)
{
	struct vhost_net_dev *dev = arg;
	struct virtio_queue *q;
	struct pollfd x[NUM_QUEUES];
	uint64_t val;
	int qnum = 0;
	int ret, n;

	/* unlike virtio_net.c this thread polls call_fd of
	 * virtqueues, and then invokes irq */

	do {
		if (qnum != dev->qnum) {
			qnum = dev->qnum;
			for (n = 0; n < qnum; n++) {
				q = &dev->dev.queue[n];
				x[n].fd = q->call_fd;
				x[n].events = POLLIN;
			}
		}

		if (qnum == 0) {
			usleep(10);	/* no queues enabled */
			continue;
		}

		if (dev->pollstop)
			break;

		if (poll(x, qnum, 10) < 0) {
			lkl_printf("%s: poll failed: %s\n", __func__,
				   strerror(errno));
		}

		for (n = 0; n < qnum; n++) {
			if (!x[n].revents & POLLIN)
				continue;
			else {
				ret = read(x[n].fd, &val, sizeof(val));
				if (ret < 0) {
					lkl_printf("%s: read failed: %s\n",
						   __func__, strerror(errno));
					continue;
				}
				virtio_deliver_irq(&dev->dev);
			}
		}

	} while (1);
}

static int probe_vnet_hdr_len(int fd)
{
	int val;

	if (ioctl(fd, TUNGETVNETHDRSZ, &val) < 0) {
		lkl_printf("ioctl TUNGETVNETHDRSZ failed: %s\n",
			   strerror(errno));
		return -1;
	}

	return val;
}

struct vhost_net_dev *registered_devs[MAX_NET_DEVS];
static int registered_dev_idx = 1;

static int dev_register(struct vhost_net_dev *dev)
{
	if (registered_dev_idx == MAX_NET_DEVS) {
		lkl_printf("Too many vhost_net devices!\n");
		/* THis error code is also a little bit of a lie */
		return -LKL_ENOMEM;
	} else {
		registered_devs[registered_dev_idx] = dev;
		return 0;
	}
}

int lkl_vhost_net_add(int backend_fd, struct lkl_netdev_args *args)
{
	struct vhost_net_dev *dev;
	int ret = -LKL_ENOMEM;
	uint64_t features;

	dev = lkl_host_ops.mem_alloc(sizeof(*dev));
	if (!dev)
		return -LKL_ENOMEM;

	memset(dev, 0, sizeof(*dev));
	dev->dev.device_id = LKL_VIRTIO_ID_NET;
	if (args) {
		if (args->mac) {
			dev->dev.device_features |= BIT(LKL_VIRTIO_NET_F_MAC);
			memcpy(dev->config.mac, args->mac, LKL_ETH_ALEN);
		}
		dev->dev.device_features |= args->offload;
	}
	dev->dev.config_data = &dev->config;
	dev->dev.config_len = sizeof(dev->config);
	dev->backend_fd = backend_fd;

	if ((dev->vhost_net_fd = open("/dev/vhost-net", O_RDWR)) < 0) {
		lkl_printf("failed to open /dev/vhost-net: %d\n",
			   strerror(errno));
		ret = dev->vhost_net_fd;
		goto out_free;
	}

	if (vhost_net_set_owner(dev) < 0) {
		lkl_printf("failed to set vhost owner: %s\n", strerror(errno));
		goto out_free;
	}

	if (vhost_net_ioctl(dev, VHOST_GET_FEATURES, &features) < 0) {
		lkl_printf("ioctl VHOST_GET_FEATURES failed: %s\n",
			   strerror(errno));
		goto out_free;
	}
	dev->dev.device_features |= features;

	if ((dev->vnet_hdr_len = probe_vnet_hdr_len(dev->backend_fd)) < -1)
		goto out_free;

	if (dev->vnet_hdr_len == 0) {
		/* backend does not supports vnet hdr. drop affected
		 * bits from features (I saw qemu/hw/net/virtio-net.c,
		 * virtio_net_get_features).
		 */
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_CSUM);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_HOST_TSO4);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_HOST_TSO6);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_HOST_ECN);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_GUEST_CSUM);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_GUEST_TSO4);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_GUEST_TSO6);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_GUEST_ECN);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_GUEST_UFO);
		dev->dev.device_features &= ~BIT(LKL_VIRTIO_NET_F_HOST_UFO);
	}

	dev->dev.vhost = &vhost_net;

	ret = virtio_dev_setup(&dev->dev, NUM_QUEUES, QUEUE_DEPTH);
	if (ret)
		goto out_close;

	dev->poll_tid = lkl_host_ops.thread_create(vhost_net_poll_thread, dev);
	if (dev->poll_tid == 0)
		goto out_close;

	ret = dev_register(dev);
	if (ret < 0)
		goto out_close;

	return registered_dev_idx++;

out_close:
	close(dev->vhost_net_fd);

out_free:
	lkl_host_ops.mem_free(dev);
	return ret;
}

void lkl_vhost_net_remove(int id)
{
	struct vhost_net_dev *dev;
	int ret;

	if (id >= registered_dev_idx) {
		lkl_printf("%s: invalid id: %d\n", __func__, id);
		return;
	}

	dev = registered_devs[id];

	dev->pollstop = 1;
	lkl_host_ops.thread_join(dev->poll_tid);

	ret = lkl_netdev_get_ifindex(id);
	if (ret < 0) {
		lkl_printf("%s: failed to get ifindex for id %d: %s\n",
			   __func__, id, lkl_strerror(ret));
		return;
	}

	ret = lkl_if_down(ret);
	if (ret < 0) {
		lkl_printf("%s: failed to put interface id %d down: %s\n",
			   __func__, id, lkl_strerror(ret));
		return;
	}

	virtio_dev_cleanup(&dev->dev);
	lkl_host_ops.mem_free(dev);
}
