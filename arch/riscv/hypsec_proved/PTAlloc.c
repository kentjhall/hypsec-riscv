#include "hypsec.h"

/*
 * PTAlloc
 */
#if 0
/* TODO: This function actually allocates the PGD, not a pmd (pgd entry) */
u64 alloc_s2pt_hgatp(u32 vmid)
{
	/* TODO: Is there a dealloc function? need to update that for 16 KiB PGD */
	u64 next, end;

	next = get_pgd_next(vmid);
	end = pgd_pool_end(vmid);

	/* TODO: We could save some space (on avg) if we do this iteratively */
	/* Need an extra 3 pages so that we can ensure we have a 16 KiB aligned PGD */
	if (next + PAGE_SIZE * (4+3) <= end)
	{
		/* Align PGD to 16KiB boundary */
		next = (next + PAGE_SIZE * (4+3)) & ~(PAGE_SIZE * 4 - 1);
		set_pgd_next(vmid, next);
	}
	else
	{
		print_string("\rwe used all s2 pgd pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return check64(next);
}
#endif

u64 alloc_s2pt_pgd(u32 vmid)
{
	u64 next, end;

	next = get_pgd_next(vmid);
	end = pgd_pool_end(vmid);

	if (next + PAGE_SIZE <= end)
	{
		set_pgd_next(vmid, next);
	}
	else
	{
		print_string("\rwe used all s2 pgd pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return check64(next);
}

/* No PUD used in RISCV with Sv39x4 paging */
u64 alloc_s2pt_pud(u32 vmid)
{
	return alloc_s2pt_pgd(vmid);
#if 0
/* No PUD used in RISCV with Sv39x4 paging so we fold into PGD*/
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
#endif
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
