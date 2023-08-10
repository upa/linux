#ifndef _LKL_PGTABLE_H
#define _LKL_PGTABLE_H

/*
 * (C) Copyright 2000-2002, Greg Ungerer <gerg@snapgear.com>
 */

#include <asm/page.h>
#include <asm-generic/pgtable-nopud.h>
#include <asm/processor.h>
#include <asm/io.h>

#define pgd_present(pgd)	(1)
#define pgd_none(pgd)		(0)
#define pgd_bad(pgd)		(0)
#define pgd_clear(pgdp)
#define kern_addr_valid(addr)	(1)
#define	pmd_offset(a, b)	((void *)0)

#define PAGE_NONE		__pgprot(0)
#define PAGE_SHARED		__pgprot(0)
#define PAGE_COPY		__pgprot(0)
#define PAGE_READONLY		__pgprot(0)
#define PAGE_KERNEL		__pgprot(0)

void paging_init(void);
#define swapper_pg_dir		((pgd_t *)0)

#define __swp_type(x)		(0)
#define __swp_offset(x)		(0)
#define __swp_entry(typ, off)	((swp_entry_t) { ((typ) | ((off) << 7)) })
#define __pte_to_swp_entry(pte)	((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(x)	((pte_t) { (x).val })

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern void *empty_zero_page;
#define ZERO_PAGE(vaddr)	(virt_to_page(empty_zero_page))


#ifndef pgprot_noncached
#define pgprot_noncached(prot)  (prot)
#endif

#ifndef pgprot_writecombine
#define pgprot_writecombine pgprot_noncached
#endif

#ifndef pgprot_writethrough
#define pgprot_writethrough pgprot_noncached
#endif

#ifndef pgprot_device
#define pgprot_device pgprot_noncached
#endif


/*
 * All 32bit addresses are effectively valid for vmalloc...
 * Sort of meaningless for non-VM targets.
 */
#define	VMALLOC_START		0
#define	VMALLOC_END		0xffffffff
#define	KMAP_START		0
#define	KMAP_END		0xffffffff

#define PTRS_PER_PTE 0
#define PTRS_PER_PMD 0

#endif
