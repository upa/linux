#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <asm/usrcall.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "usrcall: " fmt

#define LKL_USRCALL_VERSION	"0.0.0"


/* XXX: need protect usrcall_table with rcu */
static lkl_usrcall_t usrcall_table[LKL_USRCALL_LOC_MAX + 1] = {
	[0 ... LKL_USRCALL_LOC_MAX] = NULL,
};


static int lkl_usrcall_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int lkl_usrcall_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int lkl_usrcall_reg_test(struct lkl_usrcall_reg *reg)
{
	usrcall_table[reg->location](0);
	return 0;
}

static int lkl_usrcall_reg_copy_from_user(struct lkl_usrcall_reg *reg)
{
	return 0;
}

static int lkl_usrcall_reg_copy_to_user(struct lkl_usrcall_reg *reg)
{
	return 0;
}

typedef int (*reg_handle_t)(struct lkl_usrcall_reg *);
static reg_handle_t usrcall_handle[LKL_USRCALL_LOC_MAX + 1] = {
	[LKL_USRCALL_LOC_TEST] = lkl_usrcall_reg_test,
	[LKL_USRCALL_LOC_COPY_FROM_USER] = lkl_usrcall_reg_copy_from_user,
	[LKL_USRCALL_LOC_COPY_TO_USER] = lkl_usrcall_reg_copy_to_user,
};

static long lkl_usrcall_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long data)
{
	struct lkl_usrcall_reg reg;
	int ret = 0;

	if (copy_from_user(&reg, (void *)data, sizeof(reg)) != 0) {
		pr_err("%s: copy_from_user failed\n", __func__);
		return -EFAULT;
	}
	if (reg.location < 0 || reg.location > LKL_USRCALL_LOC_MAX) {
		pr_err("%s: invalid location %d\n", __func__, reg.location);
		return -EINVAL;
	}

	switch (cmd) {
	case LKL_USRCALL_REG:
		if (usrcall_table[reg.location])
			return -EBUSY;

		usrcall_table[reg.location] = reg.function;

		if (usrcall_handle[reg.location])
			ret = usrcall_handle[reg.location](&reg);
		break;

	case LKL_USRCALL_UNREG:
		if (!usrcall_table[reg.location])
			return -ENOENT;

		usrcall_table[reg.location] = NULL;
		break;

	case LKL_USRCALL_GET:
		if (!usrcall_table[reg.location])
			return -ENOENT;

		reg.function = usrcall_table[reg.location];

		if (copy_to_user((void *)data, &reg, sizeof(reg)) != 0) {
			pr_err("%s: copy_to_user failed\n", __func__);
			return -EFAULT;
		}
		break;
	}

	return ret;
}

static const struct file_operations lkl_usrcall_fops = {
	.owner		= THIS_MODULE,	/* ??? */
	.open		= lkl_usrcall_open,
	.release	= lkl_usrcall_release,
	.unlocked_ioctl	= lkl_usrcall_ioctl,
};

static struct miscdevice lkl_usrcall_mdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "usrcall",
	.fops	= &lkl_usrcall_fops,
};

int usrcall_init(void)
{
	int ret = 0;

	ret = misc_register(&lkl_usrcall_mdev);
	if (ret) {
		pr_err("failed to register miscdevice\n");
		goto out;
	}

	pr_info("v%s loaded\n", LKL_USRCALL_VERSION);
out:
	return ret;
}

void usrcall_cleanup(void)
{
	misc_deregister(&lkl_usrcall_mdev);

	pr_info("v%s unloaded\n", LKL_USRCALL_VERSION);
}
