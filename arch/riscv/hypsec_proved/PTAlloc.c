#include "hypsec.h"

/*
 * PTAlloc
 */

u64 alloc_s2pt_pgd(u32 vmid)
{
	/* TODO: Is there a dealloc function? need to update that for 16 KiB PGD */
	u64 next, end;

	next = get_pgd_next(vmid);
	end = pgd_pool_end(vmid);

	/* Need 5 pages so that we can ensure we have a 16 KiB aligned PGD */
	if (next + PAGE_SIZE * 5 <= end)
	{
		/* Align PGD to 16KiB boundary */
		next = (next + PAGE_SIZE * 5) & ~(PAGE_SIZE * 4 - 1);
		set_pgd_next(vmid, next + PAGE_SIZE);
	}
	else
	{
	        print_string("\rwe used all s2 pgd pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return check64(next);
}

u64 alloc_s2pt_pud(u32 vmid)
{
	u64 next, end;

	next = get_pud_next(vmid);
	end = pud_pool_end(vmid);

	if (next + PAGE_SIZE <= end)
	{
		set_pud_next(vmid, next + PAGE_SIZE);
	}
	else
	{
	        print_string("\rwe used all s2 pud pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return check64(next);
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
	        print_string("\rwe used all s2 pmd pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return next;
}
