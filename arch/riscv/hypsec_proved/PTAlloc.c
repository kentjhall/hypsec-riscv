#include "hypsec.h"

/*
 * PTAlloc
 */

u64 alloc_s2pt_pgd(u32 vmid)
{
	u64 next, end;

	next = get_pgd_next(vmid);
	end = pgd_pool_end(vmid);

	if (next + PAGE_SIZE <= end)
	{
		set_pgd_next(vmid, next + PAGE_SIZE);
	}
	else
	{
		panic("\rwe used all s2 pgd pages: 0x%x\n", vmid);
	}
	return check64(next);
}

/* No PUD used in RISCV with Sv39x4 paging */
u64 alloc_s2pt_pud(u32 vmid)
{
	return alloc_s2pt_pgd(vmid);
}

u64 alloc_s2pt_pmd(u32 vmid)
{
	u64 next, end;

	next = get_pmd_next(vmid);
	end = pmd_pool_end(vmid);

	if (next + PAGE_SIZE <= end)
	{
		set_pmd_next(vmid, next + PAGE_SIZE);
	}
	else
	{
		panic("\rwe used all s2 pmd pages: 0x%x\n", vmid);
	}

	return next;
}
