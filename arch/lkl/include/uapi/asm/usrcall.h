#ifndef _ASM_UAPI_LKL_USRCALL_H
#define _ASM_UAPI_LKL_USRCALL_H

enum {
	LKL_USRCALL_LOC_TEST,
	LKL_USRCALL_LOC_COPY_FROM_USER,
	LKL_USRCALL_LOC_COPY_TO_USER,

	__LKL_USRCALL_LOC_MAX,
};
#define LKL_USRCALL_LOC_MAX	(__LKL_USRCALL_LOC_MAX - 1)


typedef int (*lkl_usrcall_t)(long arg1, ...);

struct lkl_usrcall_reg {
	int		location;
	lkl_usrcall_t	function;
};

#define LKL_USRCALL_REG		_IOW('i', 1, struct lkl_usrcall_reg)
#define LKL_USRCALL_UNREG	_IOW('i', 2, struct lkl_usrcall_reg)
#define LKL_USRCALL_GET		_IOWR('i', 3, struct lkl_usrcall_reg)


/* tools/lkl/lib/usrcall.c */
int lkl_init_dev_usrcall(char *devpath);

#endif
