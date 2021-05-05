#include "hypsec.h"
#include <asm/hypsec_constant.h>
/*
 * NPTWalk
 */

u32 get_npt_level(u32 vmid, u64 addr)
{
	u64 hgatp, pgd, pud, pmd;u32 ret;

	hgatp = get_pt_hgatp(vmid);
	pgd = walk_pgd(vmid, hgatp, addr, 0U);
	pud = pgd;
	pmd = walk_pmd(vmid, pud, addr, 0U);

	if ((pmd & pgprot_val(PAGE_LEAF)) != 0U)
	{
		u64 pte = walk_pte(vmid, pmd, addr);
		if (phys_page(pte) == 0UL)
		{
			ret = 0U;
		}
		else
		{
			ret = 3U;
		}
	}
	else
	{
		if (phys_page(pmd) == 0UL)
		{
			ret = 0U;
		}
		else
		{
			ret = 2U;
		}
	}

	return check(ret);
}

u64 walk_npt(u32 vmid, u64 addr)
{
	u64 hgatp, pgd, pud, pmd, ret, pte;

	hgatp = get_pt_hgatp(vmid);
	pgd = walk_pgd(vmid, hgatp, addr, 0U);
	pud = pgd;
	pmd = walk_pmd(vmid, pud, addr, 0U);

	if ((pmd & pgprot_val(PAGE_LEAF)) == 0U)
	{
		pte = walk_pte(vmid, pmd, addr);
		ret = pte;
	}
	else
	{
		ret = pmd;
	}

	return check64(ret);
}

void set_npt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	u64 hgatp, pgd, pud, pmd;

	hgatp = get_pt_hgatp(vmid);
	pgd = walk_pgd(vmid, hgatp, addr, 1U);
	pud = pgd;

	if (level == 2U)
	{
		pmd = walk_pmd(vmid, pud, addr, 0U);
		//TODO: Xupeng, why we don't check this in the verified code
		if ((pmd & pgprot_val(PAGE_TABLE)) == 1U)
		{
			print_string("PANIC: set existing npt: pmd\n");
			hyp_panic();
		}
		else
		{
			v_set_pmd(vmid, pud, addr, pte);
		}
	}
	else
	{
		pmd = walk_pmd(vmid, pud, addr, 1U);
		if ((pmd & pgprot_val(PAGE_LEAF)) == 0U)
		{
			v_set_pte(vmid, pmd, addr, pte);
		}
		else
		{
			print_string("PANIC: set existing npt: pte\n");
			hyp_panic();
		}
	}
}

void mem_load_ref(u64 gfn, u32 reg)
{
	mem_load_raw(gfn, reg);
}

void mem_store_ref(u64 gfn, u32 reg)
{
	mem_store_raw(gfn, reg);
}
