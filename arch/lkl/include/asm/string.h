#ifndef _ASM_LKL_STRING_H
#define _ASM_LKL_STRING_H

#include <asm/types.h>
#include <asm/host_ops.h>

#define __HAVE_ARCH_MEMCPY
static inline void *memcpy(void *dest, const void *src, size_t count)
{
	char *tmp = dest;
	const char *s = src;

	if (lkl_ops->memcpy)
		return lkl_ops->memcpy(dest, src, count);

	while (count--)
		*tmp++ = *s++;

	return dest;
}


static inline void *__memset(void *s, int c, size_t count)
{
	char *xs = s;
	while (count--)
		*xs++ = c;
	return s;
}

#define __HAVE_ARCH_MEMSET
static inline void *memset(void *s, int c, size_t count)
{
	if (lkl_ops->memset)
		return lkl_ops->memset(s, c, count);

	return __memset(s, c, count);
}

#define __HAVE_ARCH_MEMSET16
static inline void *memset16(void *s, int c, size_t count)
{
	if (lkl_ops->memset)
		return lkl_ops->memset(s, c, count);

	return __memset(s, c, count);
}

#define __HAVE_ARCH_MEMSET32
static inline void *memset32(void *s, int c, size_t count)
{
	if (lkl_ops->memset)
		return lkl_ops->memset(s, c, count);

	return __memset(s, c, count);
}

#define __HAVE_ARCH_MEMSET64
static inline void *memset64(void *s, int c, size_t count)
{
	if (lkl_ops->memset)
		return lkl_ops->memset(s, c, count);

	return __memset(s, c, count);
}


#endif
