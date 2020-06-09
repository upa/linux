#ifndef _ASM_LKL_USRCALL_H
#define _ASM_LKL_USRCALL_H

int usrcall_init(void);
void usrcall_cleanup(void);


/* hooks
 *
 * return value: 0 means success, -1 means not registered, 1 means fail */
int lkl_usrcall_raw_copy_from_user(void *to, const void __user *from,
				   unsigned long n);
int lkl_usrcall_raw_copy_to_user(void __user *to, const void *from,
				 unsigned long n);
int lkl_usrcall_strncpy_from_user(char *dst, const char __user *src,
				  long count);

#include <uapi/asm/usrcall.h>

#endif /* _ASM_LKL_USRCALL_h */
