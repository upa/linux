#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>

static void print(const char *str, int len)
{
	printk("%s", str, len);
}

struct lkl_mutex {
	struct mutex mutex;
};

struct lkl_sem {
	struct semaphore sem;
};


struct lkl_tls_key_ctx {
	int idx;
	void (*destructor)(void *);
};

#define LKL_TLS_MAX_KEYS	128
struct lkl_tls_key_ctx ctxs[LKL_TLS_MAX_KEYS] = {
	{ 0, 0 };
};



struct lkl_tls_key {
	int index;
};


static lkl_sem *sem_alloc(int count)
{
	return NULL;
}

static void sem_free(struct lkl_sem *sem)
{
	return;
}

static void sem_up(struct lkl_sem *sem)
{
	return;
}

static void sem_down(struct lkl_sem *sem)
{
	return;
}

static struct lkl_mutex *mutex_alloc(int recursive)
{
	return NULL;
}

static void mutex_lock(struct lkl_mutex *mutex)
{
	return;
}

static void mutex_unlock(struct lkl_mutex *mutex)
{
	return;
}

static void mutex_free(struct lkl_mutex *mutex)
{
	return;
}

static lkl_thread_t thread_create(void (*fn)(void *), void *arg)
{
	return 0;
}

static void thread_detach(void)
{
	return;
}

static void thread_exit(void)
{
	return;
}

static int thread_join(lkl_thread_t tid)
{
	return 0;
}

static lkl_thread_t thread_self(void)
{
	return 0;
}

static int thread_equal(lkl_thread_t a, lkl_thread_t b)
{
	return 0;
}

static struct lkl_tls_key *tls_alloc(void (*destructor)(void *))
{
	return NULL;
}

static void tls_free(struct lkl_tls_key *key)
{
	return;
}

static int tls_set(struct lkl_tls_key *key, void *data)
{
	return 0;
}

static unsigned long long time_ns(void)
{
	return 0;
}

static void *timer_alloc(void (*fn)(void *), void *arg)
{
	return NULL;
}

static int timer_set_oneshot(void *timer, unsigned long ns)
{
	return 0;
}

static void timer_free(void *timer)
{
	return;
}

static void panic(void)
{
	assert(0);
}

static long _gettid(void)
{
	return 0;
}


static void *mem_alloc(size_t size)
{
	return kmalloc(size, GFP_ATOMIC);
}

static void mem_free(void *mem)
{
	kfree(mem);
}

struct lkl_host_operations lkl_host_ops = {
	.panic = panic,
	.thread_create = thread_create,
	.thread_detach = thread_detach,
	.thread_exit = thread_exit,
	.thread_join = thread_join,
	.thread_self = thread_self,
	.thread_equal = thread_equal,
	.sem_alloc = sem_alloc,
	.sem_free = sem_free,
	.sem_up = sem_up,
	.sem_down = sem_down,
	.mutex_alloc = mutex_alloc,
	.mutex_free = mutex_free,
	.mutex_lock = mutex_lock,
	.mutex_unlock = mutex_unlock,
	.tls_alloc = tls_alloc,
	.tls_free = tls_free,
	.tls_set = tls_set,
	.tls_get = tls_get,
	.time = time_ns,
	.timer_alloc = timer_alloc,
	.timer_set_oneshot = timer_set_oneshot,
	.timer_free = timer_free,
	.print = print,
	.mem_alloc = mem_alloc,
	.mem_free = mem_free,
	.jmp_buf_set = jmp_buf_set,
	.jmp_buf_longjmp = jmp_buf_longjmp,
	.memcpy = memcpy,
};


static int blk_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
	return 0;
}

static int blk_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
	return 0;
}

struct lkl_dev_blk_ops lkl_dev_blk_ops = {
	.get_capacity = blk_get_capacity,
	.request = blk_request,
};
