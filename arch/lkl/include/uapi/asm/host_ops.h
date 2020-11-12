#ifndef _ASM_UAPI_LKL_HOST_OPS_H
#define _ASM_UAPI_LKL_HOST_OPS_H

/* Defined in {posix,nt}-host.c */
struct lkl_mutex;
struct lkl_sem;
struct lkl_tls_key;
typedef unsigned long lkl_thread_t;
struct lkl_jmp_buf {
	unsigned long buf[128];
};
struct lkl_pci_dev;

/**
 * lkl_dev_pci_ops - PCI host operations
 *
 * These operations would be a wrapper of userspace PCI drvier and
 * must be provided by a host library or by the application.
 *
 * @add - add a new PCI device; returns a handler or NULL if fails
 * @remove - release resources
 * @init_irq - allocate resources for interrupts
 * @read - read the PCI Configuration Space
 * @write - write the PCI Configuration Space
 * @resource_alloc - map BARx and return the mapped address. x is resource_index
 *
 * @map_page - return the DMA address of pages; vaddr might not be page-aligned
 * @unmap_page - cleanup DMA region if needed
 *
 * @get_irq - get an irq associating this device
 */
struct lkl_dev_pci_ops {
	struct lkl_pci_dev *(*add)(const char *name, void *kernel_ram,
				   unsigned long ram_size);
	void (*remove)(struct lkl_pci_dev *dev);
	int (*irq_init)(struct lkl_pci_dev *dev, int irq);
	int (*read)(struct lkl_pci_dev *dev, int where, int size, void *val);
	int (*write)(struct lkl_pci_dev *dev, int where, int size, void *val);
	void *(*resource_alloc)(struct lkl_pci_dev *dev,
				unsigned long resource_size,
				int resource_index);
	unsigned long long (*map_page)(struct lkl_pci_dev *dev, void *vaddr,
				       unsigned long size);
	void (*unmap_page)(struct lkl_pci_dev *dev,
			   unsigned long long dma_handle, unsigned long size);
	int (*get_irq)(struct lkl_pci_dev *dev);
};

enum lkl_prot {
	LKL_PROT_NONE = 0,
	LKL_PROT_READ = 1,
	LKL_PROT_WRITE = 2,
	LKL_PROT_EXEC = 4,
};

/* dpdkio */
struct lkl_dpdkio_slot;	/* defined in dpdkio.h */

struct lkl_dpdkio_ops {

	/* preparation */

	void *(*malloc)(int size);	/* used to alloc bootmem */

	void (*free)(void *addr);	/* used to free bootmem */

	int (*init_port)(int portid);	/* initialize a dpdkio port */

	int (*add_rx_page)(int portid, unsigned long addr);
	/* pass a 4096-byte memory region for rx buffer. the region is
	 * added used as rx packet buffer by dpdk extmem */

	int (*init_rx_irq)(int portid, int *irq, int *irq_ack_fd);
	/* an irq number and its eventfd associating the rx on this
	 * port are passed through `*irq` and `*iqr_ack_fd` */

	int (*setup)(int portid, int *nb_rx_desc, int *nb_tx_desc);
	/* setup a dpdkio device */

	int (*start)(int portid); /* start dpdkio port */
	int (*stop)(int portid);	/* stop dpdkio port */


	/* RX path */

	int (*rx)(int portid, struct lkl_dpdkio_slot **slots, int nb_pkts);
	/* receive upto `nb_pkts` packets from the ring to `pkts`
	 * array. It retruns number of packets received. */

	void (*ack_rx_interrupt)(int irq_ack_fd);
	void (*enable_rx_interrupt)(int portid);
	void (*disable_rx_interrupt)(int portid);
	/* polling is mapped to napi */

	void (*mbuf_free)(int portid, void *mbuf);
	/* this is actually rte_pktmbuf_free() to release
	 * dpdkio_slot->mbuf in the RX path. It is called to release
	 * mbuf when corresponding skb is consumed at the end of RX
	 * path. */


	/* TX path */

	int (*tx)(int portid, struct lkl_dpdkio_slot **slots, int nb_pkts);
	/* transmit upto `nb_pkts` packets in `pkts` array to a
	 * underlaying ethernet device. It returns number of packets
	 * transmitted. */

	void (*free_skb)(int portid, void *skb);
	/* this is actually kfree_skb to release dpdkio_slot->skb in
	 * the TX path. It is called to release skb when the
	 * corresponding mbuf is released at the end of TX path.
	 *
	 * NOTE: only this function is set by the lkl kernel-side
	 * (arch/lkl/kernel/dpdkio.c) 'before' dpdkio_start() is
	 * called, unlike other functions are set by lib/dpdkio.c.
	 */


	/* misc */

	void (*get_macaddr)(int portid, char *mac);
	/* copy MAC address of underlaying ethernet device to `mac`. */

	int (*get_link_status)(int portid);
	/* get link status of underlaying ethernet device */

	/* XXX: may need feature negotiation for, e.g., offloading
	 * capability. */

	void *(*rte_pktmbuf_alloc)(uint16_t port_id);
	char *(*rte_pktmbuf_append)(void *rm, uint16_t len);
	void (*rte_pktmbuf_free)(void *rm);
	uint16_t (*rte_eth_tx_prepare)(uint16_t port_id, uint16_t queue_id,
				       void **tx_pkts, uint16_t nb_pkts);
	uint16_t (*rte_eth_tx_burst)(uint16_t port_id, uint16_t queue_id,
				     void **tx_pkts, uint16_t nb_pkts);
	void (*rte_pktmbuf_attach_extbuf)(void *rm, void *buf_addr,
					  uint16_t buf_len, uint16_t pkt_len,
					  void (*free_skb_cb)(void *addr, void *skb_ptr),
					  void *userdata);
	void (*tx_prep)(void *rm, uint16_t protocol, uint16_t ip_protocol,
			uint64_t l2_len, uint64_t l3_len, uint64_t l4_len,
			uint64_t tso_segsz, int gso);

};

/**
 * lkl_host_operations - host operations used by the Linux kernel
 *
 * These operations must be provided by a host library or by the application
 * itself.
 *
 * @virtio_devices - string containg the list of virtio devices in virtio mmio
 * command line format. This string is appended to the kernel command line and
 * is provided here for convenience to be implemented by the host library.
 *
 * @print - optional operation that receives console messages
 *
 * @panic - called during a kernel panic
 *
 * @sem_alloc - allocate a host semaphore an initialize it to count
 * @sem_free - free a host semaphore
 * @sem_up - perform an up operation on the semaphore
 * @sem_down - perform a down operation on the semaphore
 *
 * @mutex_alloc - allocate and initialize a host mutex; the recursive parameter
 * determines if the mutex is recursive or not
 * @mutex_free - free a host mutex
 * @mutex_lock - acquire the mutex
 * @mutex_unlock - release the mutex
 *
 * @thread_create - create a new thread and run f(arg) in its context; returns a
 * thread handle or 0 if the thread could not be created
 * @thread_detach - on POSIX systems, free up resources held by
 * pthreads. Noop on Win32.
 * @thread_exit - terminates the current thread
 * @thread_join - wait for the given thread to terminate. Returns 0
 * for success, -1 otherwise
 * @thread_stack - get the thread stack base and size of the current thread
 *
 * @tls_alloc - allocate a thread local storage key; returns 0 if successful; if
 * destructor is not NULL it will be called when a thread terminates with its
 * argument set to the current thread local storage value
 * @tls_free - frees a thread local storage key; returns 0 if succesful
 * @tls_set - associate data to the thread local storage key; returns 0 if
 * successful
 * @tls_get - return data associated with the thread local storage key or NULL
 * on error
 *
 * @mem_alloc - allocate memory
 * @mem_free - free memory
 * @page_alloc - allocate page aligned memory
 * @page_free - free memory allocated by page_alloc
 *
 * @timer_create - allocate a host timer that runs fn(arg) when the timer
 * fires.
 * @timer_free - disarms and free the timer
 * @timer_set_oneshot - arm the timer to fire once, after delta ns.
 *
 * @ioremap - searches for an I/O memory region identified by addr and size and
 * returns a pointer to the start of the address range that can be used by
 * iomem_access
 * @iomem_acess - reads or writes to and I/O memory region; addr must be in the
 * range returned by ioremap
 *
 * @gettid - returns the host thread id of the caller, which need not
 * be the same as the handle returned by thread_create
 *
 * @jmp_buf_set - runs the give function and setups a jump back point by saving
 * the context in the jump buffer; jmp_buf_longjmp can be called from the give
 * function or any callee in that function to return back to the jump back
 * point
 *
 * NOTE: we can't return from jmp_buf_set before calling jmp_buf_longjmp or
 * otherwise the saved context (stack) is not going to be valid, so we must pass
 * the function that will eventually call longjmp here
 *
 * @jmp_buf_longjmp - perform a jump back to the saved jump buffer
 *
 * @memcpy - copy memory
 * @memset - set memory
 *
 * @mmap - map anonymous memory at the given address with the given size and
 * protection
 * @munmap - unmap previously mapped memory
 *
 * @pci_ops - pointer to PCI host operations
 */
struct lkl_host_operations {
	const char *virtio_devices;

	void (*print)(const char *str, int len);
	void (*panic)(void);

	struct lkl_sem* (*sem_alloc)(int count);
	void (*sem_free)(struct lkl_sem *sem);
	void (*sem_up)(struct lkl_sem *sem);
	void (*sem_down)(struct lkl_sem *sem);

	struct lkl_mutex *(*mutex_alloc)(int recursive);
	void (*mutex_free)(struct lkl_mutex *mutex);
	void (*mutex_lock)(struct lkl_mutex *mutex);
	void (*mutex_unlock)(struct lkl_mutex *mutex);

	lkl_thread_t (*thread_create)(void (*f)(void *), void *arg);
	void (*thread_detach)(void);
	void (*thread_exit)(void);
	int (*thread_join)(lkl_thread_t tid);
	lkl_thread_t (*thread_self)(void);
	int (*thread_equal)(lkl_thread_t a, lkl_thread_t b);
	void *(*thread_stack)(unsigned long *size);

	struct lkl_tls_key *(*tls_alloc)(void (*destructor)(void *));
	void (*tls_free)(struct lkl_tls_key *key);
	int (*tls_set)(struct lkl_tls_key *key, void *data);
	void *(*tls_get)(struct lkl_tls_key *key);

	void* (*mem_alloc)(unsigned long);
	void (*mem_free)(void *);
	void* (*page_alloc)(unsigned long size);
	void (*page_free)(void *addr, unsigned long size);

	unsigned long long (*time)(void);

	void* (*timer_alloc)(void (*fn)(void *), void *arg);
	int (*timer_set_oneshot)(void *timer, unsigned long delta);
	void (*timer_free)(void *timer);

	void* (*ioremap)(long addr, int size);
	int (*iomem_access)(const volatile void *addr, void *val, int size,
			    int write);

	long (*gettid)(void);

	void (*jmp_buf_set)(struct lkl_jmp_buf *jmpb, void (*f)(void));
	void (*jmp_buf_longjmp)(struct lkl_jmp_buf *jmpb, int val);

	void* (*memcpy)(void *dest, const void *src, unsigned long count);
	void* (*memset)(void *s, int c, unsigned long count);

	void* (*mmap)(void *addr, unsigned long size, enum lkl_prot prot);
	int (*munmap)(void *addr, unsigned long size);

	struct lkl_dev_pci_ops *pci_ops;
	struct lkl_dpdkio_ops *dpdkio_ops;

	unsigned long memory_start, memory_size;
};

/**
 * lkl_init - initializes LKL
 *
 * This function needs to be called this before any other LKL function.
 *
 * @lkl_ops - pointer to host operations
 */
int lkl_init(struct lkl_host_operations *lkl_ops);

/**
 * lkl_start_kernel - starts the kernel
 *
 * @cmd_line - format for command line string that is going to be used to
 * generate the Linux kernel command line
 */
int lkl_start_kernel(const char *cmd_line, ...);

/**
 * lkl_cleanup - cleanup LKL
 *
 * To be called after lkl_sys_shutdown. Once this function is called no more LKL
 * calls can be made unless @lkl_init is called again.
 */
void lkl_cleanup(void);

/**
 * lkl_is_running - returns 1 if the kernel is currently running
 */
int lkl_is_running(void);

int lkl_printf(const char *, ...);
void lkl_bug(const char *, ...);

#endif
