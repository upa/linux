/*
 * system call hijack code fro mino
 *
 * based on tools/lkl/lib/hijack/hijack.c by Hajime Tazaki
 */


#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <dirent.h>
#define __USE_GNU
#include <dlfcn.h>

#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>

#include <lkl.h>
#include <lkl/asm/syscalls.h>
#include "xlate.h"

//#include <mino.h>
#include "util.h"

#ifndef PAGE_SIZE
/* aarch64 does not have PAGE_SIZE in header files unlike
 * x86_64-linux-gnu/sys/user.h. __PAGE_SIZE is passed from cmake */
#define PAGE_SIZE __PAGE_SIZE
#endif

int verbose;	/* for util.h */

/* env variables for configuring mino */
#define ENV_MINOD		"MINOD"		/* ADDRESS:PORT of minod */
#define ENV_MINO_VERBOSE	"MINO_VERBOSE"	/* verbose level */
#define ENV_MINO_DEBUG		"MINO_DEBUG"	/* debug enable */
#define ENV_MINO_EXCLUDE	"MINO_EXCLUDE"	/* exclude paths ','-seped */
#define ENV_MINO_WRITE_MODE	"MINO_WRITE_MODE"	/* use write mode */
#define ENV_MINO_AARCH64	"MINO_AARCH64"	/* offload to aarch64 */

struct exclude_path {
	char	*path;
	int	len;
};

struct mino_hijack {
	char addr[16];	/* minod address */
	char port[16];	/* minod port number */

#define MAX_EXCLUDE_PATH	32
	struct exclude_path	paths[MAX_EXCLUDE_PATH];
	int	aarch64;	/* 1 means offload to aarch64 */

	int	max_fd;	/* saved maximum fd opened by hijacking. */
} hijack;

/* handle paths excluded from hijacking */
static int make_exclude_paths(char *string, struct exclude_path *paths)
{
	char *s, *p;
	int n;

	n = 0;
	s = string;
	p = strstr(s, ",");
	if (!p)
		p = s + strlen(s);

	while (p && n < MAX_EXCLUDE_PATH) {
		struct exclude_path *path = &paths[n++];

		path->len = p - s;
		path->path = malloc(path->len + 1);
		memcpy(path->path, s, path->len);
		path->path[path->len] = '\0';
		pr_v2("exclude path: %s\n", path->path);

		if (*p == '\0')
			break;

		s = p + 1;
		p = strstr(p + 1, ",");
		if (!p)
			p = s + strlen(s);
	}

	return n;
}

static int check_exclude_path(const char *path)
{
	int n, ret;

	for (n = 0; n < MAX_EXCLUDE_PATH; n++) {
		if (hijack.paths[n].len == 0)
			break;

		ret = strncmp(hijack.paths[n].path, path,
			      hijack.paths[n].len);
		if (ret == 0)
			return 1;
	}

	return 0;
}

/* handing file descriptors opened at the lkl server side */
static inline void update_max_fd(int fd)
{
	if (fd > hijack.max_fd)
		hijack.max_fd = fd;
}


__thread struct mino_context *tls_ctx;
__thread bool tls_hijack_enabled;


void __attribute__((constructor(102)))
mino_hijack_init(void)
{
#ifdef MINO
	char *addr_port, *needle;
	int write_mode = 0;
	int v;
#endif

	tls_hijack_enabled = false;

	memset(&hijack, 0, sizeof(hijack));

	if (getenv(ENV_MINO_VERBOSE))
		verbose = atoi(getenv(ENV_MINO_VERBOSE));

#ifdef MINO
	if (getenv(ENV_MINO_DEBUG)) {
		v = atoi(getenv(ENV_MINO_DEBUG));
		if (v)
			mino_debug_enable();
	}
#endif

	if (getenv(ENV_MINO_EXCLUDE))
		make_exclude_paths(getenv(ENV_MINO_EXCLUDE), hijack.paths);
	else {
		pr_v2("if %s is not set, /tmp is excluded by default\n",
		      ENV_MINO_EXCLUDE);
		make_exclude_paths("/tmp", hijack.paths);
	}

#ifdef MINO
	addr_port = getenv(ENV_MINOD);
	if (!addr_port) {
		pr_err("%s=ADDRESS:PORT is required\n", ENV_MINOD);
		assert(0);
	}
	needle = strstr(addr_port, ":");
	if (!needle) {
		pr_err("%s=ADDRESS:PORT is required\n", ENV_MINOD);
		assert(0);
	}
	*needle = '\0';
	strncpy(hijack.addr, addr_port, 16);
	strncpy(hijack.port, needle + 1, 16);

	if (getenv(ENV_MINO_WRITE_MODE)) {
		v = atoi(getenv(ENV_MINO_WRITE_MODE));
		if (v) {
			pr_v1("enable RDMA Write mode\n");
			write_mode = 1;
		}
	}

	if (getenv(ENV_MINO_AARCH64)) {
		v = atoi(getenv(ENV_MINO_AARCH64));
		if (v) {
			pr_v1("offload to aarch64\n");
			hijack.aarch64 = 1;
		}
	}

	tls_ctx = mino_context_init(hijack.addr, hijack.port, write_mode);
	if (!tls_ctx) {
		pr_err("failed to connect %s:%s\n", hijack.addr, hijack.port);
		assert(0);
	}

	pr_v1("connected to %s:%s\n", hijack.addr, hijack.port);
#endif

	tls_hijack_enabled = true;
}

void __attribute__((destructor))
mino_hijack_fini(void)
{
	pr_v1("cleanup\n");
	tls_hijack_enabled = false;
#ifdef MINO
	mino_context_exit(tls_ctx);
#endif
}

/* Function for updating MRRC is wrapped by corresponding macro. This
 * enables print function name, actually syscall name, by pr_err()
 * when mino_mrrc_update failed. */

static inline int _mrrc_update(const void *addr, size_t size, bool writable)
{
	if (addr == NULL)
		return 0;
#ifdef MINO
	return mino_mrrc_update(tls_ctx, writable, addr, size);
#else
	return 0;
#endif
}
#define mrrc_update(a, s, w)				\
	do {						\
		if (_mrrc_update(a, s, w) < 0) {	\
			pr_err("mrrc update failed\n");	\
			assert(0);			\
		}					\
	} while (0)

static int _mrrc_update_iovec(struct iovec *iov, int iovcnt, bool writable)
{
	int n, ret;

	ret = _mrrc_update(iov, sizeof(struct iovec) * iovcnt, false);
	if (ret < 0)
		return ret;
	for (n = 0; n < iovcnt; n++) {
		ret = _mrrc_update(iov[n].iov_base, iov[n].iov_len, writable);
		if (ret < 0)
			return ret;
	}
	return 0;
}
#define mrrc_update_iovec(i, c, w)					\
	do {								\
		if (_mrrc_update_iovec(i, c, w) < 0) {			\
			pr_err("mrrc update for iovec failed\n");	\
			assert(0);					\
		}							\
	} while (0)

static int _mrrc_update_msghdr(const struct msghdr *msg, bool writable)
{
	int ret;

	ret = _mrrc_update(msg, sizeof(struct msghdr), false);
	if (ret < 0)
		return ret;

	if (msg->msg_namelen) {
		ret = _mrrc_update(msg->msg_name, msg->msg_namelen, writable);
		if (ret < 0)
			return ret;
	}

	if (msg->msg_controllen) {
		ret = _mrrc_update(msg->msg_control, msg->msg_controllen,
				   true);
		if (ret < 0)
			return ret;
	}

	return _mrrc_update_iovec(msg->msg_iov, msg->msg_iovlen, writable);
}
#define mrrc_update_msghdr(m, w)					\
	do {								\
		if (_mrrc_update_msghdr(m, w) < 0) {			\
			pr_err("mrrc update for msghdr failed\n");	\
			assert(0);					\
		}							\
	} while (0)


static int rsyscall(long no, long *args, int size)
{
#ifdef MINO
	int ret, err;
	ret = mino_rsyscall(tls_ctx, no, args, size, &err);
	if (unlikely(ret == MINO_RDMAERR))
		assert(0);

	errno = err;
	return ret;
#else
	return lkl_set_errno(lkl_syscall(no, args));
#endif
}


typedef long (*host_call)(long p1, long p2, long p3,
                          long p4, long p5, long p6);
static host_call host_calls[__lkl__NR_syscalls];

static int dupped_fd = -1;

static inline int is_lklfd(int fd)
{
	/* XXX: work-around for busybox ping that calls dup2(fd, 0) */
	if (dupped_fd > -1 && dupped_fd == fd)
		return 1;

	if (fd == LKL_AT_FDCWD)
		return 1;

	if (fd < LKL_FD_OFFSET)
		return 0;

	return 1;
}

static void *resolve_sym(const char *sym)
{
	void *resolv;

	resolv = dlsym(RTLD_NEXT, sym);
	if (!resolv) {
		pr_err("dlsym failed for %s: %s\n", sym, dlerror());
		assert(0);
	}
	return resolv;
}

#define HOOK_CALL(name)							\
	long name##_hook(long p1, long p2, long p3, long p4, long p5,   \
			 long p6)					\
	{								\
		long p[6] = {p1, p2, p3, p4, p5, p6};			\
		int ret;						\
									\
		if (!host_calls[__lkl__NR_##name])			\
			host_calls[__lkl__NR_##name] = resolve_sym(#name); \
									\
		if (!tls_hijack_enabled)				\
			return host_calls[__lkl__NR_##name](p1, p2, p3, \
							    p4, p5, p6); \
									\
		ret = rsyscall( __lkl__NR_##name, p, 0);		\
		update_max_fd(ret);					\
		return ret;						\
	}								\
	asm(".global " #name);						\
	asm(".set " #name "," #name "_hook");



static long p0; /* this is a little trick for p##mra1 and so on. when
		 * mra1, mra2, ipva, msga, or arv is 0, p0 is used,
		 * and mrrc_update() is not called.
		 */

#define _HOOK_FD_CALL(name,						\
		      mra1, mrs1, w1,					\
		      iova, iovc, iovw,					\
		      arv, arvlen, arvw)				\
	static void __attribute__((constructor(101)))			\
	init_host_##name(void)						\
	{								\
		host_calls[__lkl__NR_##name] = resolve_sym(#name);      \
	}								\
									\
	long name##_hook(long p1, long p2, long p3, long p4, long p5,   \
			 long p6)					\
	{								\
		long p[6] = {p1, p2, p3, p4, p5, p6};			\
		int ret;						\
									\
		if (!host_calls[__lkl__NR_##name])			\
			host_calls[__lkl__NR_##name] = resolve_sym(#name); \
									\
		if (!tls_hijack_enabled || !is_lklfd(p1))		\
			return host_calls[__lkl__NR_##name](p1, p2, p3,	\
							    p4, p5, p6); \
									\
		if (p##mra1)						\
			mrrc_update((void *)p##mra1, p##mrs1, w1);	\
		if (p##iova)						\
			mrrc_update_iovec((void *)p##iova, p##iovc, iovw); \
		if (p##arv)						\
			mrrc_update((void *)p##arv, arvlen, arvw);	\
									\
		ret = rsyscall(__lkl__NR_##name, p, 0);			\
		update_max_fd(ret);					\
		return ret;						\
	}								\
	asm(".global " #name);						\
	asm(".set " #name "," #name "_hook");

#define HOOK_FD_CALL(name)			\
	_HOOK_FD_CALL(name,			\
		      0, 0, 0,			\
		      0, 0, 0,			\
		      0, 0, 0)

#define HOOK_FD_CALL_1MR(name, mra1, mrs1, w1)	\
	_HOOK_FD_CALL(name,			\
		      mra1, mrs1, w1,		\
		      0, 0, 0,			\
		      0, 0, 0)

#define HOOK_FD_CALL_IOV(name, iova, iovc, iovw)	\
	_HOOK_FD_CALL(name,				\
		      0, 0, 0,				\
		      iova, iovc, iovw,			\
		      0, 0, 0)


#define HOOK_FD_CALL_ARV(name, arv, arvlen, arvw)	\
	_HOOK_FD_CALL(name,				\
		      0, 0, 0,				\
		      0, 0, 0,				\
		      arv, arvlen, arvw)
	

HOOK_CALL(socket);
HOOK_CALL(socketpair);
HOOK_FD_CALL(close);

HOOK_FD_CALL(listen);
HOOK_FD_CALL_1MR(bind, 2, 3, false);
HOOK_FD_CALL(shutdown);
HOOK_FD_CALL_1MR(connect, 2, 3, false);

HOOK_FD_CALL_1MR(write, 2, 3, false);
HOOK_FD_CALL_IOV(writev, 2, 3, false);
HOOK_FD_CALL_1MR(pwrite64, 2, 3, false);
HOOK_FD_CALL_IOV(pwritev, 2, 3, false);

HOOK_FD_CALL_1MR(read, 2, 3, true);
HOOK_FD_CALL_IOV(readv, 2, 3, true);
HOOK_FD_CALL_1MR(pread64, 2, 3, true);
HOOK_FD_CALL_IOV(preadv, 2, 3, true);

HOOK_FD_CALL(sendfile);

HOOK_CALL(epoll_create1);




#define WRAP_CALL(name)					\
	static long (*host_##name)();			\
	static void __attribute__((constructor(101)))   \
	init_host_##name(void)				\
	{						\
		host_##name = resolve_sym(#name);       \
	}

#define WRAP_VOIDP_CALL(name)			    \
	static void *(*host_##name)();		  \
	static void __attribute__((constructor(101)))   \
	init_host_##name(void)			  \
	{					       \
		host_##name = resolve_sym(#name);       \
	}

#define WRAP_VOID_CALL(name)			    \
	static void (*host_##name)();		  \
	static void __attribute__((constructor(101)))   \
	init_host_##name(void)			  \
	{					       \
		host_##name = resolve_sym(#name);       \
	}

#define _CHECK_CALL(fd, name,  ...)					\
	do {								\
		if (!host_##name)					\
			host_##name = resolve_sym(#name);		\
									\
		if (!tls_hijack_enabled)				\
			return host_##name(__VA_ARGS__);		\
									\
		if (fd > -1 && fd != LKL_AT_FDCWD && !is_lklfd(fd))	\
			return host_##name(__VA_ARGS__);		\
	} while (0)

#define CHECK_CALL(name, ...) _CHECK_CALL(-1, name, __VA_ARGS__)
#define CHECK_CALL_WITH_FD(fd, name, ...) _CHECK_CALL(fd, name, __VA_ARGS__)


WRAP_CALL(accept);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, accept, sockfd, addr, addrlen);

	p[0] = sockfd;
	p[1] = (uintptr_t)addr;
	p[2] = (uintptr_t)addrlen;

	mrrc_update(addr, *addrlen, true);
	mrrc_update(addrlen, sizeof(socklen_t), true);

	return rsyscall(__lkl__NR_accept, p, 0);
}

WRAP_CALL(accept4);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, accept, sockfd, addr, addrlen);

	p[0] = sockfd;
	p[1] = (uintptr_t)addr;
	p[2] = (uintptr_t)addrlen;
	p[3] = flags;

	mrrc_update(addr, *addrlen, true);
	mrrc_update(addrlen, sizeof(socklen_t), true);

	return rsyscall(__lkl__NR_accept4, p, 0);
}

WRAP_CALL(sendto);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, sendto, sockfd, buf, len, flags,
			   dest_addr, addrlen);

	p[0] = sockfd;
	p[1] = (uintptr_t)buf;
	p[2] = len;
	p[3] = flags;
	p[4] = (uintptr_t)dest_addr;
	p[5] = addrlen;

	mrrc_update(buf, len, false);
	mrrc_update(dest_addr, addrlen, false);

	return rsyscall(__lkl__NR_sendto, p, 0);
}

WRAP_CALL(recvfrom);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, recvfrom, sockfd, buf, len, flags,
			   src_addr, addrlen);

	p[0] = sockfd;
	p[1] = (uintptr_t)buf;
	p[2] = len;
	p[3] = flags;
	p[4] = (uintptr_t)src_addr;
	p[5] = (uintptr_t)addrlen;

	mrrc_update(buf, len, true);
	if (src_addr && addrlen)
		mrrc_update(src_addr, *addrlen, true);
	mrrc_update(addrlen, sizeof(*addrlen), true);

	return rsyscall(__lkl__NR_recvfrom, p, 0);
}

WRAP_CALL(sendmsg);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, sendmsg, sockfd, msg, flags);

	p[0] = sockfd;
	p[1] = (uintptr_t)msg;
	p[2] = flags;

	mrrc_update_msghdr(msg, false);

	return rsyscall(__lkl__NR_sendmsg, p, 0);
}


WRAP_CALL(recvmsg);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, recvmsg, sockfd, msg, flags);

	p[0] = sockfd;
	p[1] = (uintptr_t)msg;
	p[2] = flags;

	mrrc_update_msghdr(msg, true);

	return rsyscall(__lkl__NR_recvmsg, p, 0);
}


WRAP_CALL(open64);
int open64(const char *file, int flags, ...)
{
	mode_t mode;
	va_list v;

	va_start(v, flags);
	mode = va_arg(v, mode_t);
	va_end(v);

	return open(file, flags, mode);
}

WRAP_CALL(open);
int open(const char *file, int flags, ...)
{
	mode_t mode;
	va_list v;

	va_start(v, flags);
	mode = va_arg(v, mode_t);
	va_end(v);

	/* go to hijacked openat() */
	return openat(LKL_AT_FDCWD, file, flags, mode);
}

WRAP_CALL(openat);
int openat(int dirfd, const char *pathname, int flags, ...)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	mode_t mode;
	va_list v;
	int size;
	int fd;
	va_start(v, flags);
	mode = va_arg(v, mode_t);
	va_end(v);

	CHECK_CALL_WITH_FD(dirfd, openat, dirfd, pathname, flags, mode);
	if (check_exclude_path(pathname))
		return host_openat(dirfd, pathname, flags, mode);

	size = strlen(pathname) + 1;
	p[0] = dirfd;
	p[1] = (uintptr_t)pathname;
	p[2] = lkl_open_flag_xlate(flags);
	memcpy(&p[3], &mode, sizeof(mode_t));

	mrrc_update(pathname, size, false);

	fd = rsyscall(__lkl__NR_openat, p, size);
	update_max_fd(fd);
	return fd;
}

WRAP_CALL(select);
int select(int n, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *tv)
{
	long data[2] = { 0, _LKL_NSIG/8 };
	struct lkl_timespec ts;
	lkl_time_t extra_secs;
	const lkl_time_t max_time = ((1ULL<<8)*sizeof(time_t)-1)-1;
	long p[6] = { 0, 0, 0, 0, 0, 0};

	CHECK_CALL(select, n, rfds, wfds, efds, tv);

	/* copied from tools/lkl/include/lkl.h */
	if (tv) {
		if (tv->tv_sec < 0 || tv->tv_usec < 0) {
			errno = -EINVAL;
			return -1;
		}

		extra_secs = tv->tv_usec / 1000000;
		ts.tv_nsec = tv->tv_usec % 1000000 * 1000;
		ts.tv_sec = extra_secs > max_time - tv->tv_sec ?
			max_time : tv->tv_sec + extra_secs;
	}

	p[0] = n;
	p[1] = (uintptr_t)rfds;
	p[2] = (uintptr_t)wfds;
	p[3] = (uintptr_t)efds;
	p[4] = tv ? (uintptr_t)&ts : 0;
	p[5] = (uintptr_t)data;

	mrrc_update((void *)p[1], sizeof(fd_set), true);
	mrrc_update((void *)p[2], sizeof(fd_set), true);
	mrrc_update((void *)p[3], sizeof(fd_set), true);
	mrrc_update((void *)p[4], sizeof(ts), true);
	mrrc_update((void *)p[5], sizeof(data), true);

	return rsyscall(__lkl__NR_pselect6, p, 0);
}

WRAP_CALL(epoll_create);
int epoll_create(int size)
{
	return epoll_create1(0);	/* go to hijacked epoll_create1() */
}

/* In x86, epoll_event is attribute((__packed__)), but in aarch64, it
 * is not packed. Thus, padding due to non-packed currputs event.data.
 * Thus, we need to change packed event to non-packed event structure
 * when offloading to aarch64, such as BlueField.
 */
struct epoll_event_nopacked {
	uint32_t	events;
	epoll_data_t	data;
};

WRAP_CALL(epoll_ctl);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(epfd, epoll_ctl, fd, op, event);

	p[0] = epfd;
	p[1] = op;
	p[2] = fd;

	if (hijack.aarch64) {
		struct epoll_event_nopacked evnop;
		evnop.events = event->events;
		evnop.data = event->data;
		p[3] = (uintptr_t)&evnop;
		mrrc_update(&evnop, sizeof(evnop), false);
	} else {
		p[3] = (uintptr_t)event;
		mrrc_update(event, sizeof(*event), false);
	}

	return rsyscall(__lkl__NR_epoll_ctl, p, 0);
}

WRAP_CALL(epoll_pwait);
int epoll_pwait(int fd, struct epoll_event *events, int maxevents, int timeout,
		const sigset_t *sigmask)
{
	struct epoll_event_nopacked evnops[maxevents];
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	int ret, n;

	CHECK_CALL_WITH_FD(fd, epoll_pwait, fd, events, maxevents, timeout,
			   sigmask);

	p[0] = fd;

	if (hijack.aarch64) {
		p[1] = (uintptr_t)evnops;
		mrrc_update(evnops, sizeof(evnops), true);
	} else {
		p[1] = (uintptr_t)events;
		mrrc_update(events, sizeof(*events) * maxevents, true);
	}

	p[2] = maxevents;
	p[3] = timeout;
	p[4] = (uintptr_t)sigmask;

	mrrc_update(sigmask, sizeof(*sigmask), false);

	ret = rsyscall(__lkl__NR_epoll_pwait, p, 0);

	if (hijack.aarch64) {
		for (n = 0; n < ret; n++) {
			events[n].events = evnops[n].events;
			events[n].data = evnops[n].data;
		}
	}

	return ret;
}

WRAP_CALL(epoll_wait);
int epoll_wait(int fd, struct epoll_event *ev, int cnt, int to)
{
	/* goto hijacked epoll_pwait(). XXX: tools/lkl/include/lkl.h
	 * uses _LKL_NSIG/8 for sigmask.
	 */
	return epoll_pwait(fd, ev, cnt, to, 0);
}

WRAP_CALL(ppoll);
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
	  const sigset_t *sigmask)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	int lkl = 0;
	nfds_t n;

	for (n = 0; n < nfds; n++) {
		if (is_lklfd(fds[n].fd))
			lkl = 1;
	}

	if (!lkl) {
		CHECK_CALL(ppoll, fds, nfds, tmo_p, sigmask);
		return host_ppoll(fds, nfds, tmo_p, sigmask);
	}

	p[0] = (uintptr_t)fds;
	p[1] = nfds;
	p[2] = (uintptr_t)tmo_p;
	p[3] = (uintptr_t)sigmask;
	p[4] = _LKL_NSIG/8;

	mrrc_update(fds, sizeof(struct pollfd), true);
	mrrc_update(tmo_p, sizeof(struct timespec), false);
	mrrc_update(sigmask, sizeof(sigset_t), false);

	return rsyscall(__lkl__NR_ppoll, p, 0);
}


WRAP_CALL(poll);
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct timespec to;

	to.tv_sec = timeout / 1000;
	to.tv_nsec = timeout % 1000 * 1000000;

	return ppoll(fds, nfds, timeout >= 0 ? &to : NULL, NULL);
}

WRAP_CALL(ioctl);
int ioctl(int fd, unsigned long req, ...)
{
        long p[6] = { 0, 0, 0, 0, 0, 0};
        va_list vl;
        long arg;

        va_start(vl, req);
        arg = va_arg(vl, long);
        va_end(vl);

        CHECK_CALL_WITH_FD(fd, ioctl, fd, req, arg);

        p[0] = fd;
        p[1] = req;
        p[2] = arg;

	/* XXX: how to handle ioctl() with explicit memory registration... */
	mrrc_update((void *)arg, PAGE_SIZE, true);

	return rsyscall(__lkl__NR_ioctl, p, 0);
}

WRAP_CALL(setsockopt);
int setsockopt(int fd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(fd, setsockopt, fd, level, optname, optval, optlen);

	p[0] = fd;
	p[1] = lkl_solevel_xlate(level);
	p[2] = lkl_soname_xlate(optname);
	p[3] = (uintptr_t)optval;
	p[4] = optlen;

	mrrc_update(optval, optlen, false);

	return rsyscall(__lkl__NR_setsockopt, p, 0);
}

WRAP_CALL(getsockopt);
int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(fd, getsockopt, fd, level, optname, optval, optlen);

	p[0] = fd;
	p[1] = lkl_solevel_xlate(level);
	p[2] = lkl_soname_xlate(optname);
	p[3] = (uintptr_t)optval;
	p[4] = (uintptr_t)optlen;

	mrrc_update(optval, *optlen, true);
	mrrc_update(optlen, sizeof(socklen_t), true);

	return rsyscall(__lkl__NR_getsockopt, p, 0);
}

WRAP_CALL(getsockname);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, getsockname, addr, addrlen);

	p[0] = sockfd;
	p[1] = (uintptr_t)addr;
	p[2] = (uintptr_t)addrlen;

	mrrc_update(addr, *addrlen, true);
	mrrc_update(addrlen, sizeof(socklen_t), true);

	return rsyscall(__lkl__NR_getsockname, p, 0);
}

WRAP_CALL(getpeername);
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(sockfd, getpeername, addr, addrlen);

	p[0] = sockfd;
	p[1] = (uintptr_t)addr;
	p[2] = (uintptr_t)addrlen;

	mrrc_update(addr, *addrlen, true);
	mrrc_update(addrlen, sizeof(socklen_t), true);

	return rsyscall(__lkl__NR_getpeername, p, 0);
}

WRAP_CALL(send);
ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	return sendto(fd, buf, len, flags, 0, 0);
}

WRAP_CALL(recv);
ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	return recvfrom(fd, buf, len, flags, 0, 0);
}

WRAP_CALL(fcntl);
int fcntl(int fd, int cmd, ...)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	va_list vl;
	long arg;

	va_start(vl, cmd);
	arg = va_arg(vl, long);
	va_end(vl);

	CHECK_CALL_WITH_FD(fd, fcntl, fd, cmd, arg);

	p[0] = fd;
	p[1] = lkl_fcntl_cmd_xlate(cmd);
	p[2] = arg;

	return rsyscall(__lkl__NR_fcntl, p, 0);
}

HOOK_FD_CALL(dup);
HOOK_FD_CALL(dup3);

WRAP_CALL(dup2);
int dup2(int old, int new)
{
	int ret;

	/* copied from musl/src/unistd/dup2.c */
	if (old == new) {
		ret = fcntl(old, F_GETFD);
		if (ret >= 0)
			return old;
	}

	ret = dup3(old, new, 0);
	if (ret != -1)
		dupped_fd = ret;	/* XXX: workaround for busybox ping */

	return ret;
}


/* file I/O rated system calls */

WRAP_CALL(statfs);
int statfs(const char *pathname, struct statfs *buf)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	int size;

	CHECK_CALL(statfs, pathname, buf);
	if (check_exclude_path(pathname))
		return host_statfs(pathname, buf);

	p[0] = (uintptr_t)pathname;
	p[1] = (uintptr_t)buf;

	size = strlen(pathname) + 1;

	mrrc_update(pathname, size, false);
	mrrc_update(buf, sizeof(*buf), true);

	return rsyscall(__lkl__NR_statfs, p, strlen(pathname) + 1);
}

WRAP_CALL(fstatfs);
int fstatfs(int fd, struct statfs *buf)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	CHECK_CALL_WITH_FD(fd, fstatfs, fd, buf);

	p[0] = fd;
	p[1] = (uintptr_t)buf;

	mrrc_update(buf, sizeof(*buf), true);

	return rsyscall(__lkl__NR_fstatfs, p, 0);
}

/* wrapping syscalls for stat.
 *
 * XXX: struct stat depends on architectures, and lkl has its own one
 * that is not compiatible with libc compiled for other architectures
 * such as x86. Thus, we use struct stat for x86 in lkl based on this
 * commit https://github.com/thehajime/linux/commit/220284fe63fd3bdeb49b05361e4219b444cc15ae. The same change exists on lkl-usrcall.
 *
 * fstatat() can be hijacked in only musl libc. So, we use __fstatat()
 * as a private fstatat() in the hijack lib.
 */

/* musl-style fstat(). copied from musl/src/stat/fstatat.c */
static long __syscall_ret(unsigned long r)
{
	if (r > -4096UL) {
		errno = -r;
		return -1;
	}
	return r;
}

static int __fstatat_statx(int fd, const char *path, struct stat *st, int flag)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	struct statx stx;
	int ret, size;

	p[0] = fd;
	p[1] = (uintptr_t)path;
	p[2] = flag;
	p[3] = 0x8ff;
	p[4] = (uintptr_t)&stx;
	size = strlen(path) + 1;

	mrrc_update(path, size, false);
	mrrc_update(&stx, sizeof(stx), true);

	ret = rsyscall(__lkl__NR_statx, p, size);
	if (ret) return ret;

	*st = (struct stat) {
		.st_dev = makedev(stx.stx_dev_major, stx.stx_dev_minor),
		.st_ino = stx.stx_ino,
		.st_mode = stx.stx_mode,
		.st_nlink = stx.stx_nlink,
		.st_uid = stx.stx_uid,
		.st_gid = stx.stx_gid,
		.st_rdev = makedev(stx.stx_rdev_major, stx.stx_rdev_minor),
		.st_size = stx.stx_size,
		.st_blksize = stx.stx_blksize,
		.st_blocks = stx.stx_blocks,
		.st_atim.tv_sec = stx.stx_atime.tv_sec,
		.st_atim.tv_nsec = stx.stx_atime.tv_nsec,
		.st_mtim.tv_sec = stx.stx_mtime.tv_sec,
		.st_mtim.tv_nsec = stx.stx_mtime.tv_nsec,
		.st_ctim.tv_sec = stx.stx_ctime.tv_sec,
		.st_ctim.tv_nsec = stx.stx_ctime.tv_nsec,
#if _REDIR_TIME64
		.__st_atim32.tv_sec = stx.stx_atime.tv_sec,
		.__st_atim32.tv_nsec = stx.stx_atime.tv_nsec,
		.__st_mtim32.tv_sec = stx.stx_mtime.tv_sec,
		.__st_mtim32.tv_nsec = stx.stx_mtime.tv_nsec,
		.__st_ctim32.tv_sec = stx.stx_ctime.tv_sec,
		.__st_ctim32.tv_nsec = stx.stx_ctime.tv_nsec,
#endif
	};

	return 0;
}


static int __fstatat_kstat(int fd, const char *path, struct stat *st, int flag)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	int ret, size;

	p[0] = fd;
	p[1] = (uintptr_t)path;
	p[2] = (uintptr_t)st;
	p[3] = flag;
	size = strlen(path) + 1;

	mrrc_update(path, size, false);
	mrrc_update(st, sizeof(*st), true);

	ret = rsyscall(__lkl__NR3264_fstatat, p, size);
	if (ret) return ret;

	return 0;
}


static int __fstatat(int fd, const char *path, struct stat *st, int flag)
{
	int ret;

	if (!tls_hijack_enabled || !is_lklfd(fd))
		return fstatat(fd, path, st, flag);

	/* start musl-style fstatat */
	if (sizeof((struct stat){0}.st_atime) < sizeof(time_t)) {
		ret = __fstatat_statx(fd, path, st, flag);
		if (ret!=-ENOSYS) return __syscall_ret(ret);
	}
	ret = __fstatat_kstat(fd, path, st, flag);
	return __syscall_ret(ret);
}

/* here is glibc-dependent */
WRAP_CALL(__xstat);
int __xstat(int version, const char *pathname, struct stat *statbuf)
{
	return __fstatat(LKL_AT_FDCWD, pathname, statbuf, 0);
}

WRAP_CALL(__lxstat);
int __lxstat(int version, const char *pathname, struct stat *statbuf)
{
	return __fstatat(LKL_AT_FDCWD, pathname, statbuf,
			 LKL_AT_SYMLINK_NOFOLLOW);
}

/* cannot be hijacked on glibc */
//WRAP_CALL(xfstat);
int xfstat(int fd, struct stat *statbuf)
{
	return __fstatat(fd, "", statbuf, LKL_AT_EMPTY_PATH);
}

WRAP_CALL(__fxstat64);
int __fxstat64(int version, int fd, struct stat *statbuf)
{
	return lkl_sys_fstat(fd, (struct lkl_stat *)statbuf);
//	return __fstatat(fd, "", statbuf, LKL_AT_EMPTY_PATH);
}

HOOK_FD_CALL(lseek);


WRAP_CALL(truncate);
int truncate(const char *path, off_t length)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	int size;

	CHECK_CALL(truncate, path, length);
	if (check_exclude_path(path))
		return host_truncate(path, length);

	p[0] = (uintptr_t)path;
	p[1] = length;
	size = strlen(path) + 1;

	mrrc_update(path, size, false);

	return rsyscall(__lkl__NR_truncate, p, size);
}

HOOK_FD_CALL(ftruncate);

WRAP_CALL(getxattr);
ssize_t getxattr(const char *path, const char *name, void *value, size_t size)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	int pathsize;

	CHECK_CALL(getxattr, path, name, value, size);
	if (check_exclude_path(path))
		return host_getxattr(path, name, value, size);

	p[0] = (uintptr_t)path;
	p[1] = (uintptr_t)name;
	p[2] = (uintptr_t)value;
	p[3] = size;

	pathsize = strlen(path) + 1;

	mrrc_update(path, pathsize, false);
	mrrc_update(name, 1, false);	/* 1 PAGE */
	mrrc_update(value, size, true);

	return rsyscall(__lkl__NR_getxattr, p, pathsize);
}

WRAP_CALL(lgetxattr);
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	int pathsize;

	CHECK_CALL(lgetxattr, path, name, value, size);
	if (check_exclude_path(path))
		return host_lgetxattr(path, name, value, size);

	p[0] = (uintptr_t)path;
	p[1] = (uintptr_t)name;
	p[2] = (uintptr_t)value;
	p[3] = size;

	pathsize = strlen(path) + 1;

	mrrc_update(path, pathsize, false);
	mrrc_update(name, 1, false);	/* 1 PAGE */
	mrrc_update(value, size, true);

	return rsyscall(__lkl__NR_lgetxattr, p, pathsize);
}

/* directory related system calls. copied and modified from
 * tools/lkl/lib/fs.c and tools/lkl/include/lkl.h */

/* the instance of opaque type 'DIR'. The only difference of
 * __dirstram from lkl_dir is 'magic'. magic is used to determine this
 * DIR is for LKL or not.
 */
struct __dirstream {
	unsigned int magic;
	int fd;
	char buf[1024];
	char *pos;
	int len;
};

#define DIR_MAGIC       0x1234ABCD
#define is_hijacked_dir(dir) (dir->magic == DIR_MAGIC)

static DIR *alloc_dir()
{
	DIR *dir;

	dir = malloc(sizeof(DIR));
	if (!dir)
		return NULL;

	memset(dir, 0, sizeof(DIR));
	dir->magic = DIR_MAGIC; /* mark this dir is hijacked */
	return dir;
}

WRAP_VOIDP_CALL(opendir);
WRAP_VOIDP_CALL(fdopendir);

DIR *opendir(const char *path)
{
	DIR *dir;
	int fd;

	CHECK_CALL(opendir, path);
	if (check_exclude_path(path))
		return host_opendir(path);

	/* go to hijacked open() */
	fd = open(path, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		return NULL;

	if (!is_lklfd(fd)) {
		CHECK_CALL(fdopendir, path);
		return host_fdopendir(fd);
	}

	dir = alloc_dir();
	if (!dir) {
		close(fd);
		return NULL;
	}
	dir->fd = fd;

	return dir;
}

DIR *fdopendir(int fd)
{
	DIR *dir;

	CHECK_CALL_WITH_FD(fd, fdopendir, fd);

	dir = malloc(sizeof(DIR));
	if (!dir)
		return NULL;
	dir->fd = fd;

	return dir;
}

WRAP_VOID_CALL(rewinddir);
void rewinddir(DIR *dir)
{
	CHECK_CALL(rewinddir, dir);
	if (!is_hijacked_dir(dir)) {
		host_rewinddir(dir);
		return;
	}

	/* goto hijacked lseek */
	lseek(dir->fd, 0, LKL_SEEK_SET);
	dir->len = 0;
	dir->pos = NULL;
}

WRAP_CALL(closedir);
int closedir(DIR *dir)
{
	int ret;

	CHECK_CALL(closedir, dir);
	if (!is_hijacked_dir(dir))
		return host_closedir(dir);

	/* go to hijacked close */
	ret = close(dir->fd);
	free(dir);
	return ret;
}

static int __getdents64(int fd, struct lkl_linux_dirent64 *de,
			unsigned int count)
{
	long p[6] = { 0, 0, 0, 0, 0 };

	p[0] = fd;
	p[1] = (uintptr_t)de;
	p[2] = count;

	mrrc_update(de, sizeof(*de), true);

	return rsyscall(__lkl__NR_getdents64, p, 0);
}

WRAP_VOIDP_CALL(readdir);
struct dirent *readdir(DIR *dir)
{
	struct lkl_linux_dirent64 *de;

	/* XXX: based on tools/lkl/lib/fs.c. it is very different from
	 * musl/src/dirent/readdir.c */

	CHECK_CALL(readdir, dir);
	if (!is_hijacked_dir(dir))
		return host_readdir(dir);

	if (dir->len < 0)
		return NULL;

	if (!dir->pos || dir->pos - dir->buf >= dir->len)
		goto read_buf;

return_de:
	de = (struct lkl_linux_dirent64 *)dir->pos;
	dir->pos += de->d_reclen;

	return (struct dirent *)de;

read_buf:
	dir->pos = NULL;
	de = (struct lkl_linux_dirent64 *)dir->buf;
	dir->len = __getdents64(dir->fd, de, sizeof(dir->buf));
	if (dir-> len <= 0)
		return NULL;

	dir->pos = dir->buf;
	goto return_de;
}

WRAP_CALL(chdir);
int chdir(const char *path)
{
	long p[6] = { 0, 0, 0, 0, 0 };
	int size;

	CHECK_CALL(chdir, path);
	if (check_exclude_path(path))
		return host_chdir(path);

	p[0] = (uintptr_t)path;
	size = strlen(path) + 1;

	mrrc_update(path, size, false);

	return rsyscall(__lkl__NR_chdir, p, size);
}

HOOK_FD_CALL(fchdir);

WRAP_VOIDP_CALL(getcwd);
char *getcwd(char *buf, size_t size)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	long ret;

	CHECK_CALL(getcwd, buf, size);

	/* copied from musl */
	char tmp[buf ? 1 : PATH_MAX];
	if (!buf) {
		buf = tmp;
		size = sizeof tmp;
	} else if (!size) {
		errno = EINVAL;
		return 0;
	}

	p[0] = (uintptr_t)buf;
	p[1] = size;
	mrrc_update(buf, size, true);

	ret = rsyscall(__lkl__NR_getcwd, p, 0);
	if (ret < 0)
		return 0;
	if (ret == 0 || buf[0] != '/') {
		errno = ENOENT;
		return 0;
	}
	return buf == tmp ? strdup(buf) : buf;
}

WRAP_CALL(mkdirat);
int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	int size;

	CHECK_CALL_WITH_FD(dirfd, mkdirat, dirfd, pathname, mode);;
	if (check_exclude_path(pathname))
		return host_mkdirat(dirfd, pathname, mode);

	p[0] = dirfd;
	p[1] = (uintptr_t)pathname;
	p[2] = mode;
	size = strlen(pathname) + 1;

	return rsyscall(__lkl__NR_mkdirat, p, size);
}

WRAP_CALL(mkdir);
int mkdir(const char *pathname, mode_t mode)
{
	CHECK_CALL(mkdir, pathname, mode);
	if (check_exclude_path(pathname))
		host_mkdir(pathname, mode);

	/* go to hijacked mkdirat */
	return mkdirat(LKL_AT_FDCWD, pathname, mode);
}

WRAP_CALL(linkat);
int linkat(int oldfd, const char *oldpath,
	   int newfd, const char *newpath, int flags)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };

	/* XXX: link at involves two paths that have variable length.
	 * but current rkc_args has just one 'size' paramter. This
	 * copies PATH_MAX via RDMA read.
	 */

	CHECK_CALL(linkat, oldfd, oldpath, newfd, newpath, flags);

	if ((oldfd != AT_FDCWD && !is_lklfd(oldfd)) ||
	    (newfd != AT_FDCWD && !is_lklfd(newfd)))
		return host_linkat(oldfd, oldpath, newfd, newpath, flags);

	p[0] = oldfd;
	p[1] = (uintptr_t)oldpath;
	p[2] = newfd;
	p[3] = (uintptr_t)newpath;
	p[4] = lkl_link_flag_xlate(flags);

	mrrc_update(oldpath, strlen(oldpath) + 1, false);
	mrrc_update(newpath, strlen(newpath) + 1, false);

	return rsyscall(__lkl__NR_linkat, p, 0);
}

WRAP_CALL(link);
int link(const char *oldpath, const char *newpath)
{
	/* goto hijacked linkat */
	return linkat(LKL_AT_FDCWD, oldpath, LKL_AT_FDCWD, newpath, 0);
}


WRAP_CALL(unlinkat);
int unlinkat(int dirfd, const char *path, int flags)
{
	long p[6] = { 0, 0, 0, 0, 0, 0 };
	int size;

	CHECK_CALL_WITH_FD(dirfd, unlinkat, dirfd, path, flags);
	if (check_exclude_path(path))
		return host_unlinkat(dirfd, path, flags);

	p[0] = dirfd;
	p[1] = (uintptr_t)path;
	p[2] = flags ? LKL_AT_REMOVEDIR : 0;
	size = strlen(path) + 1;

	mrrc_update(path, size, false);

	return rsyscall(__lkl__NR_unlinkat, p, size);
}

WRAP_CALL(unlink);
int unlink(const char *path)
{
	/* goto hijacked unlinkat */
	return unlinkat(LKL_AT_FDCWD, path, 0);
}

/* mkostemps: copied from musl/src/temp/__randname.c and mkostemps.c
 *
 * XXX: open(2) in __mkostemps() cannot be hijacked. so I
 * re-implemnted them again here.
 */

static char *__randname(char *template)
{
	int i;
	struct timespec ts;
	unsigned long r;

	clock_gettime(CLOCK_REALTIME, &ts);
	r = ts.tv_nsec*65537 ^ ((uintptr_t)&ts / 16 + (uintptr_t)template);
	for (i=0; i<6; i++, r>>=5)
		template[i] = 'A'+(r&15)+(r&16)*2;

	return template;
}

WRAP_CALL(mkostemps);
int mkostemps(char *template, int len, int flags)
{
	CHECK_CALL(mkostemps, template, len, flags);
	if (check_exclude_path(template))
		return host_mkostemps(template, len, flags);

	int l = strlen(template);
	if (l < 6 || len > l - 6 ||
	    memcmp(template + l - len - 6, "XXXXXX", 6)) {
		errno = EINVAL;
		return -1;
	}

	flags = lkl_open_flag_xlate(flags);
	flags -= flags & LKL_O_ACCMODE;

	int fd, retries = 100;
	do {
		__randname(template + l - len - 6);
		/* goto hijacked open() */
		if ((fd = open(template,
			       flags | LKL_O_RDWR | LKL_O_CREAT | LKL_O_EXCL,
			       0600)) >= 0)
			return fd;
	} while (--retries && errno == EEXIST);

	memcpy(template + l - len - 6, "XXXXXX", 6);
	return -1;
}

WRAP_CALL(mkstemp);
int mkstemp(char *template)
{
	/* goto hijacked mkostemps() */
	return mkostemps(template, 0, 0);
}

/* copied from glibc code */
struct _local_IO_jump_t
{
	size_t dummy0;
	size_t dummy1;
	void *functions[12];
	void *__read;
	void *__write;
	void *__seek;
	void *__close;
	void *__stat;
	void *__showmanyc;
	void *__imbue;
};

struct _local_IO_FILE_plus
{
	_IO_FILE file;
	struct _local_IO_jump_t *vtable;
};

static ssize_t _l_read(_IO_FILE *file, void *buffer, ssize_t size)
{
	return lkl_sys_read(file->_fileno, buffer, size);
}

static ssize_t _l_write(_IO_FILE *file, const void *buffer, ssize_t size)
{
	ssize_t data_written = lkl_sys_write(file->_fileno, buffer, size);
	if (data_written == -1)
		return data_written;

	if (file->_offset >= 0)
		file->_offset += data_written;

	return data_written;
}

static off_t _l_seek(_IO_FILE *file, off_t where, int whence)
{
	return lkl_sys_lseek(file->_fileno, where, whence);
}

static int _l_close(_IO_FILE *file)
{
	return lkl_sys_close(file->_fileno);
}

static int _l_stat(_IO_FILE *file, void *buf)
{
	return lkl_sys_fstat(file->_fileno, (struct lkl_stat *)buf);
}

void _IO_init (_IO_FILE *fp, int flags);
FILE *fdopen(int fd, const char *mode)
{
	FILE* (*host_fopen)(const char *, const char *) = resolve_sym("fopen");
	FILE* (*host_fdopen)(int, const char *) = resolve_sym("fdopen");

	if (!is_lklfd(fd))
		return host_fdopen(fd, mode);

	/* open dummy file to allocate struct FILE */
	FILE *file = host_fopen ("/dev/null", mode);
	if (!file)
		return 0;

	/*
	 * XXX: not sure if this is a right way but it
	 * works to disable vtable validation
	 */
	_IO_init(file, 0);

	struct _local_IO_FILE_plus *fp = (struct _local_IO_FILE_plus *)file;
	static struct _local_IO_jump_t vtable;
	memcpy (&vtable, fp->vtable, sizeof(struct _local_IO_jump_t));

	vtable.__read = (void*)_l_read;
	vtable.__write = (void*)_l_write;
	vtable.__seek = (void*)_l_seek;
	vtable.__close = (void*)_l_close;
	vtable.__stat = (void*)_l_stat;
	fp->vtable = &vtable;

	close (file->_fileno);
	file->_fileno = fd;

	fseek(file, lkl_sys_lseek(fd, 0, SEEK_CUR), SEEK_SET);

	return file;
}

int mode_posix_flags (const char *mode)
{
	int mode_flag = 0;
	int posix_flags = 0;
	switch (*mode)
	{
	case 'r':
		mode_flag |= O_RDONLY;
		break;
	case 'w':
		mode_flag |= O_WRONLY;
		posix_flags |= O_CREAT | O_TRUNC;
		break;
	case 'a':
		mode_flag |= O_WRONLY;
		posix_flags |= O_CREAT | O_APPEND;
		break;
	}
	mode++;
	while (*mode != 0)
	{
		if (*mode == '+')
		{
			mode_flag = O_RDWR;
		}
		mode++;
	}
	posix_flags |= mode_flag;
	return posix_flags;
}

FILE *fopen64(const char *path, const char *mode)
{
	int fd = open(path, mode_posix_flags(mode));
	if (fd == -1)
		return 0;

	FILE *file = fdopen(fd, mode);
	if (file == 0)
		return 0;

	if (*mode != 'a') {
		lkl_sys_lseek(fd, 0, SEEK_SET);
		fseek(file, 0, SEEK_SET);
	}
	else {
		lkl_sys_lseek(fd, 0, SEEK_END);
		fseek(file, 0, SEEK_END);
	}

	return file;
}

int eventfd(unsigned int initval, int flags)
{
	return lkl_sys_eventfd2(initval, flags);
}

ssize_t sendfile64(int out_fd, int in_fd, off_t *offset, size_t count)
{
	return sendfile(out_fd, in_fd, offset, count);
}

WRAP_CALL(uname);
int uname(struct utsname *buf)
{
	return lkl_sys_uname((struct lkl_old_utsname *)buf);
}
