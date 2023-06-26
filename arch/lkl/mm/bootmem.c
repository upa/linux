// SPDX-License-Identifier: GPL-2.0
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/swap.h>

unsigned long memory_start, memory_end;
static unsigned long _memory_start, mem_size;

void *empty_zero_page;

void __init bootmem_init(unsigned long mem_sz)
{
	unsigned long zones_max_pfn[MAX_NR_ZONES] = {0, };

	mem_size = mem_sz;

	if (lkl_ops->page_alloc) {
		mem_size = PAGE_ALIGN(mem_size);
		_memory_start = (unsigned long)lkl_ops->page_alloc(mem_size);
	} else {
		_memory_start = (unsigned long)lkl_ops->mem_alloc(mem_size);
	}

	memory_start = _memory_start;
	BUG_ON(!memory_start);
	memory_end = memory_start + mem_size;

	lkl_ops->memory_start = memory_start;
	lkl_ops->memory_size = mem_size;

	if (PAGE_ALIGN(memory_start) != memory_start) {
		mem_size -= PAGE_ALIGN(memory_start) - memory_start;
		memory_start = PAGE_ALIGN(memory_start);
		mem_size = (mem_size / PAGE_SIZE) * PAGE_SIZE;
	}
	pr_info("memblock address range: 0x%lx - 0x%lx\n", memory_start,
		memory_start+mem_size);
	/*
	 * Give all the memory to the bootmap allocator, tell it to put the
	 * boot mem_map at the start of memory.
	 */
	max_low_pfn = virt_to_pfn(memory_end);
	min_low_pfn = virt_to_pfn(memory_start);
	memblock_add(memory_start, mem_size);

	empty_zero_page = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	memset((void *)empty_zero_page, 0, PAGE_SIZE);

	zones_max_pfn[ZONE_NORMAL] = max_low_pfn;
	free_area_init(zones_max_pfn);
}

void __init mem_init(void)
{
	memblock_free_all();
	max_low_pfn = totalram_pages();
	max_pfn = max_low_pfn;
	max_mapnr = max_pfn;
}

/*
 * In our case __init memory is not part of the page allocator so there is
 * nothing to free.
 */
void free_initmem(void)
{
}

void free_mem(void)
{
	if (lkl_ops->page_free)
		lkl_ops->page_free((void *)_memory_start, mem_size);
	else
		lkl_ops->mem_free((void *)_memory_start);
}


/* For RDMA */
void obtain_bootmem(unsigned long *start, unsigned long *size)
{
	*start = memory_start;
	*size = mem_size;
}
