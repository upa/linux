#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <lkl.h>

int lkl_init_dev_usrcall(char *devpath)
{
	int ret, fd, major, minor;
	char buf[1024], *p, *n;

	ret = lkl_sys_access("/proc", F_OK);
	if (ret < 0) {
		ret = lkl_mount_fs("/proc");
		if (ret < 0)
			return ret;
	}

	/* find major number of misc device */
	fd = lkl_sys_open("/proc/devices", 0, 0);
	if (fd < 0)
		return fd;

	ret = lkl_sys_read(fd, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	p = strstr(buf, "misc");
	*(p - 1) = '\0';
	n = p - 4;
	major = atoi(n);

	/* find minor number of usrcall misc device */
	fd = lkl_sys_open("/proc/misc", 0, 0);
	if (fd < 0)
		return fd;

	ret = lkl_sys_read(fd, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	p = strstr(buf, "usrcall");
	if (!p)
		return -ENOENT;
	*(p - 1) = '\0';
	n = p - 4;
	minor = atoi(n);

	ret = lkl_sys_mknod(devpath, LKL_S_IFCHR | 0600,
			    LKL_MKDEV(major, minor));
	if (ret < 0)
		return ret;

	return 0;
}
