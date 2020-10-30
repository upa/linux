#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <dirent.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/vhost.h>

#include <lkl_host.h>
#include "virtio.h"
#include "virtio_net.h"

/* copied from virtio_net.c */

#define netdev_of(x) (container_of(x, struct vhost_net_dev, dev))
#define BIT(x) (1ULL << x)

/* We always have 2 queues on a netdev: one for tx, one for rx. */
#define RX_QUEUE_IDX 0
#define TX_QUEUE_IDX 1

#define NUM_QUEUES (TX_QUEUE_IDX + 1)
#define QUEUE_DEPTH 512

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

enum {
	VHOST_NET_FEATURES = (//BIT(VIRTIO_F_NOTIFY_ON_EMPTY) |
			      BIT(VIRTIO_RING_F_INDIRECT_DESC) |
			      BIT(VIRTIO_RING_F_EVENT_IDX) |
			      BIT(VIRTIO_F_ANY_LAYOUT) |
			      BIT(VIRTIO_F_VERSION_1) |
			      //BIT(VHOST_NET_F_VIRTIO_NET_HDR) |
			      BIT(LKL_VIRTIO_NET_F_MRG_RXBUF))
};
/* XXX: 
 * we removed following features from the original VHOST_NET_FEATURES
 * - VIRTIO_F_IOMMU_PLATFORM because lkl does not support iommu
 * - VHOST_F_LOG_ALL because I don't know how to use it...
 */

/* acceptable virtio features through LKL json */
enum {
	OFFLOAD_FEATURES = (BIT(LKL_VIRTIO_NET_F_CSUM) |
			    BIT(LKL_VIRTIO_NET_F_GUEST_CSUM) |
			    BIT(LKL_VIRTIO_NET_F_GUEST_TSO4) |
			    BIT(LKL_VIRTIO_NET_F_GUEST_TSO6) |
			    BIT(LKL_VIRTIO_NET_F_HOST_TSO4) |
			    BIT(LKL_VIRTIO_NET_F_HOST_TSO6) |
			    BIT(LKL_VIRTIO_NET_F_HOST_UFO) |
			    BIT(LKL_VIRTIO_NET_F_MRG_RXBUF))
};



struct vhost_net_dev {
	struct virtio_dev dev;
	struct lkl_netdev nd;
	struct lkl_virtio_net_config config;

	int vhost_net_fd;
	int backend_fd;

	/* used for poll thread */
	lkl_thread_t poll_tid;
	int qnum;
	int pollstop;
};


#define vhost_net_ioctl(d, r, a) _vhost_net_ioctl(d, r, a, #r)

static int _vhost_net_ioctl(struct vhost_net_dev *dev, unsigned int long req,
			    void *arg, char *reqstr)
{
	int ret;

	ret = ioctl(dev->vhost_net_fd, req, arg);
	if (ret < 0) {
		fprintf(stderr, "%s: ioctl %s: %s\n", __func__, reqstr,
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
	uint32_t val = 0;

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

static int vhost_net_write_driver_features(struct vhost_net_dev *dev,
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
	return 0;
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
	struct vhost_vring_file f = { .index = vdev->queue_sel };

	q->kick_fd = eventfd(0, EFD_NONBLOCK);
	if (q->kick_fd < 0) {
		fprintf(stderr, "eventfd(): %s\n", strerror(errno));
		return -1;
	}

	q->call_fd = eventfd(0, EFD_NONBLOCK);
	if (q->call_fd < 0) {
		fprintf(stderr, "eventfd(): %s\n", strerror(errno));
		return -1;
	}

	f.fd = q->kick_fd;
	if (vhost_net_ioctl(dev, VHOST_SET_VRING_KICK, &f) < 0)
		return -1;

	f.fd = q->call_fd;
	if (vhost_net_ioctl(dev, VHOST_SET_VRING_CALL, &f) < 0)
		return -1;

	return 0;
}

static int vhost_net_kick(struct vhost_net_dev *dev, uint32_t qidx)
{
	struct virtio_queue *q = &dev->dev.queue[qidx];
	uint64_t v = 1;
	int ret;

	__sync_synchronize();
	ret = write(q->kick_fd, &v, sizeof(v));
	if (ret < 0) {
		fprintf(stderr, "%s: write(): %s\n", __func__,
			strerror(errno));
		return ret;
	}

	return 0;
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
		fprintf(stderr, "%s: ioctl VHOST_SET_VRING_ADDR failed: %s\n",
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
		fprintf(stderr, "ioctl VHOSET_NET_SET_BACKEND failed: %s\n",
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

	memset(&vmem, 0, sizeof(vmem));

	vmem.m.nregions = 1;
	vmem.r[0].guest_phys_addr = lkl_host_ops.memory_start;
	vmem.r[0].memory_size = lkl_host_ops.memory_size;
	vmem.r[0].userspace_addr = lkl_host_ops.memory_start;

	ret = vhost_net_ioctl(dev, VHOST_SET_MEM_TABLE, &vmem);
	if (ret < 0)
		fprintf(stderr, "ioctl VHOST_SET_MEM_TABLE faield: %s\n",
			strerror(errno));

	return ret;
}

static int vhost_net_set_vring_base(struct vhost_net_dev *dev)
{
	struct vhost_vring_state s;

	s.index = dev->dev.queue_sel;
	s.num = 0;	/* XXX */

	return vhost_net_ioctl(dev, VHOST_SET_VRING_BASE, &s);
}

static int vhost_net_set_busyloop_timeout(struct vhost_net_dev *dev,
					  int index, int timeout)
{
	struct vhost_vring_state s;

	s.index = index;
	s.num = timeout;

	return vhost_net_ioctl(dev, VHOST_SET_VRING_BUSYLOOP_TIMEOUT, &s);
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

static inline int set_status(struct virtio_dev *vdev, uint32_t val)
{
	struct vhost_net_dev *dev = netdev_of(vdev);
	uint64_t f;

	if (val & LKL_VIRTIO_CONFIG_S_FEATURES_OK) {
		f = vdev->driver_features & VHOST_NET_FEATURES;
		if (vhost_net_ioctl(dev, VHOST_SET_FEATURES, &f) < 0)
			return -1;
		vdev->status = val;
 	}

	vdev->status = val;

	return 0;
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
		ret = vhost_net_write_driver_features(dev, val);
		break;
	case VIRTIO_MMIO_QUEUE_SEL:
		vdev->queue_sel = val;
		break;
	case VIRTIO_MMIO_QUEUE_NUM:
		vdev->queue[vdev->queue_sel].num = val;	/* XXX: not needed? */
		ret = vhost_net_set_vring_num(dev, val);
		if (ret < 0)
			break;
		q->log = lkl_host_ops.mem_alloc(4096);	/* XXX: ?????? */
		ret = vhost_net_set_eventfd(dev);
		if (vdev->queue_sel == RX_QUEUE_IDX) {
			ret = vhost_net_set_busyloop_timeout(dev,
							     vdev->queue_sel,
							     10);
			if (ret < 0)
				break;
		}
		dev->qnum++;
		break;
	case VIRTIO_MMIO_QUEUE_READY:
		vdev->queue[vdev->queue_sel].ready = val;
		if (val) {
			ret = vhost_net_set_mem_table(dev);
			if (ret < 0)
				break;
			ret = vhost_net_set_vring_base(dev);
			if (ret < 0)
				break;
			ret = vhost_net_set_backend(dev);
			if (ret < 0)
				break;
		}
		break;
	case VIRTIO_MMIO_QUEUE_NOTIFY:
		ret = vhost_net_kick(dev, val);
		break;
	case VIRTIO_MMIO_INTERRUPT_ACK:
		vdev->int_status = 0;
		break;
	case VIRTIO_MMIO_STATUS:
		ret = set_status(vdev, val);
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

static struct lkl_iomem_ops vhost_net_iomem_ops = {
	.read	= vhost_net_read,
	.write	= vhost_net_write,
};

static struct vhost vhost_net = {
	.type		= LKL_VHOST_TYPE_NET,
	.vhost_ops	= &vhost_net_iomem_ops,
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
	struct epoll_event ev, evs[NUM_QUEUES];
	uint64_t val;
	int efd, nfds;
	int ret, n;

	/* unlike virtio_net.c this thread polls call_fd of
	 * virtqueues, and then invokes irq */

	/* wait until TX and RX queues are prepared */
	while (dev->qnum != NUM_QUEUES)
		usleep(10);

	efd = epoll_create1(0);
	if (efd < 0) {
		fprintf(stderr, "%s: epoll_create1: %s\n",
			__func__, strerror(errno));
		return;
	}

	for (n = 0; n < NUM_QUEUES; n++) {
		q = &dev->dev.queue[n];
		if (q->call_fd) {
			ev.data.fd = q->call_fd;
			ev.events = EPOLLIN;
			ret = epoll_ctl(efd, EPOLL_CTL_ADD, q->call_fd, &ev);
			if (ret) {
				fprintf(stderr, "%s: epoll_ctl: %s\n",
					__func__, strerror(errno));
				return;
			}
		}
	}

	do {
		if (dev->pollstop)
			break;
		do {
			nfds = epoll_wait(efd, evs, NUM_QUEUES, 10);
		} while (nfds == 0 && errno == EINTR);

		if (nfds < 0)
			perror("vhost_net epoll_wait");

		for (n = 0; n < nfds; n++) {
			ret = read(evs[n].data.fd, &val, sizeof(val));
			if (ret < 0) {
				printf("call fd read error: %s\n",
				       strerror(errno));
				continue;
			}
			virtio_deliver_irq(&dev->dev);
		}

	} while (1);
}

static void vhost_net_remove(struct virtio_dev *vdev, int id)
{
	struct vhost_net_dev *dev = netdev_of(vdev);
	int ret;

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



static int ifname_to_tap_path(char *ifname, char *tappath, size_t tappath_len)
{
	DIR *d;
	struct dirent *e;
	char syspath[PATH_MAX];

	/* this function converts ifname of a macvtap interface to
	 * /dev/tapX. */

	snprintf(syspath, sizeof(syspath), "/sys/class/net/%s/macvtap",
		 ifname);
	d = opendir(syspath);
	if (!d)
		return -1;

	while ((e = readdir(d))) {
		if (strncmp(e->d_name, ".", 1) == 0 ||
		    strncmp(e->d_name, "..", 2) == 0)
			continue;

		/* /sys/class/net/IFNAME/macvtap directory contains
		 * only tapX directory. */
		snprintf(tappath, tappath_len, "/dev/%s", e->d_name);
	}

	return 0;
}

int lkl_vhost_net_add(char *ifname, struct lkl_netdev_args *args)
{
	struct vhost_net_dev *dev;
	int backend_fd, ret, tap_arg = 0;
	uint64_t offload = args ? args->offload : 0;
	char tappath[PATH_MAX];

	/* XXX: macvtap + vhost always includes vnethdr ? */
	struct ifreq ifr = { .ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR };
	int vnet_hdr_sz = sizeof(struct lkl_virtio_net_hdr_v1);

	ret = ifname_to_tap_path(ifname, tappath, sizeof(tappath));
	if (ret < 0) {
		fprintf(stderr, "failed to find /dev/tap device for %s: %s\n",
			ifname, strerror(errno));
		return -1;
	}

	backend_fd = open(tappath, O_RDWR);
	if (backend_fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", tappath,
			strerror(errno));
		return -1;
	}

	ret = -LKL_ENOMEM;

	dev = lkl_host_ops.mem_alloc(sizeof(*dev));
	if (!dev)
		return -LKL_ENOMEM;

	memset(dev, 0, sizeof(*dev));
	dev->dev.device_id = LKL_VIRTIO_ID_NET;
	dev->dev.config_data = &dev->config;
	dev->dev.config_len = sizeof(dev->config);
	dev->backend_fd = backend_fd;

	/* use the specified mac addr through LKL json or the assigned
	 * one to the macvtap interface */
	if (args && args->mac)
		memcpy(dev->config.mac, args->mac, LKL_ETH_ALEN);
	else {
		struct ifreq ifrm;
		int fdm = socket(AF_INET, SOCK_DGRAM, 0);
		if (fdm < 0) {
			fprintf(stderr, "failed to open socket: %s\n",
				strerror(errno));
			return -1;
		}
		memset(&ifrm, 0, sizeof(ifrm));
		ifrm.ifr_addr.sa_family = AF_INET;
		strncpy(ifrm.ifr_name, ifname, IFNAMSIZ - 1);
		if (ioctl(fdm, SIOCGIFHWADDR, &ifrm) < 0) {
			fprintf(stderr, "failed to ioctl(SIOCGIFHWADDR): %s\n",
				strerror(errno));
			return -1;
		}
		memcpy(dev->config.mac, ifrm.ifr_hwaddr.sa_data, ETH_ALEN);
		close(fdm);
	}
	dev->dev.device_features |= BIT(LKL_VIRTIO_NET_F_MAC);


	if ((dev->vhost_net_fd = open("/dev/vhost-net", O_RDWR)) < 0) {
		fprintf(stderr, "failed to open /dev/vhost-net: %s\n",
			strerror(errno));
		ret = dev->vhost_net_fd;
		goto out_free;
	}

	if (vhost_net_set_owner(dev) < 0) {
		fprintf(stderr, "failed to set vhost owner: %s\n",
			strerror(errno));
		goto out_free;
	}

	/* drop bits not in offload */
	dev->dev.device_features |= ((VHOST_NET_FEATURES & ~OFFLOAD_FEATURES) |
				     offload);

	/* setup tap offload features */
	if (offload & BIT(LKL_VIRTIO_NET_F_GUEST_CSUM))
		tap_arg |= TUN_F_CSUM;
	if (offload & (BIT(LKL_VIRTIO_NET_F_GUEST_TSO4) |
		       BIT(LKL_VIRTIO_NET_F_MRG_RXBUF))) {
		tap_arg |= TUN_F_TSO4 | TUN_F_CSUM;
	}
	if (offload & BIT(LKL_VIRTIO_NET_F_GUEST_TSO6))
		tap_arg |= TUN_F_TSO6 | TUN_F_CSUM;

	if (offload & BIT(LKL_VIRTIO_NET_F_HOST_UFO))
		tap_arg |= TUN_F_UFO;

	/* setup backend tap fd */
	if (ioctl(backend_fd, TUNSETIFF, &ifr) != 0) {
		fprintf(stderr, "%s: failed to attach to: %s\n",
			ifname, strerror(errno));
		goto out_close;
	}

	if (ioctl(backend_fd, TUNSETVNETHDRSZ, &vnet_hdr_sz) != 0) {
		fprintf(stderr, "%s: failed to TUNSETVNETHDRSZ to: %s\n",
			ifname, strerror(errno));
		goto out_close;
	}

	if (ioctl(backend_fd, TUNSETOFFLOAD, tap_arg) != 0) {
		fprintf(stderr, "%s: failed to TUNSETOFFLOAD: %s\n",
			ifname, strerror(errno));
		goto out_close;
	}

	/* instantiate virtio device */
	dev->dev.vhost = &vhost_net;
	ret = virtio_dev_setup(&dev->dev, NUM_QUEUES, QUEUE_DEPTH);
	if (ret)
		goto out_close;

	dev->poll_tid = lkl_host_ops.thread_create(vhost_net_poll_thread, dev);
	if (dev->poll_tid == 0)
		goto out_close;

	ret = virtio_net_register(&dev->dev, vhost_net_remove);
	if (ret < 0)
		goto out_close;

	return ret;

out_close:
	close(dev->vhost_net_fd);

out_free:
	lkl_host_ops.mem_free(dev);
	return ret;
}

void vhost_net_free(struct lkl_netdev *nd)
{
	free(nd);
}

struct lkl_dev_net_ops vhost_net_dev_net_ops = {
	.free = vhost_net_free,
};

struct lkl_netdev *lkl_vhost_net_create(void)
{
	struct lkl_netdev *nd;

	nd = malloc(sizeof(*nd));
	if (!nd) {
		lkl_printf("%s: vhost-net: failed to allocate memory\n",
			   __func__);
		return NULL;
	}

	nd->ops = &vhost_net_dev_net_ops;
	return nd;
}
