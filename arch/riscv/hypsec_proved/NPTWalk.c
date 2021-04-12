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
#if 0
	/* No PUD w/ Sv39x4 paging */
	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 0U);
	}
	else
	{
		pud = pgd;
	}
#endif
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
#if 0
	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 0U);
	}
	else
	{
		pud = pgd;
	}
#endif
	pud = pgd;
	pmd = walk_pmd(vmid, pud, addr, 0U);

	if ((pmd & pgprot_val(PAGE_LEAF)) != 0U)
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
	printk("[set_npt] level: %d\n", level);

	printk("[set_npt OK %c]\n", 'a');
	hgatp = get_pt_hgatp(vmid);
	printk("[set_npt OK %c]\n", 'b');
	printk("[calling walk_pgd from set_npt]\n");
	pgd = walk_pgd(vmid, hgatp, addr, 1U);
	printk("[set_npt OK %c]\n", 'c');
	pud = pgd;
	printk("[set_npt OK %d]\n", 1);
#if 0
	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 1U);
	}
	else
	{
		pud = pgd;
	}
#endif
	if (level == 2U)
	{
		printk("[set_npt OK %d]\n", 2);
		pmd = walk_pmd(vmid, pud, addr, 0U);
		//TODO: Xupeng, why we don't check this in the verified code
		if ((pmd & pgprot_val(PAGE_LEAF)) == 0U)
		{
			panic("\rset existing npt: pmd\n");
		}
		else
		{
			printk("[set_npt OK %d]\n", 3);
			v_set_pmd(vmid, pud, addr, pte);
		}
	}
	else
	{
		printk("[set_npt OK %d]\n", 4);
		pmd = walk_pmd(vmid, pud, addr, 1U);
		printk("pmd value 0x%llx\n", pmd);
		printk("leaf mask 0x%lx\n", pgprot_val(PAGE_LEAF));
		if ((pmd & pgprot_val(PAGE_LEAF)) == 0U)
		{
			v_set_pte(vmid, pmd, addr, pte);
		}
		else
		{
			panic("\rset existing npt: pte\n");
		}
	}
	printk("[return from set_npt]\n");
}

void mem_load_ref(u64 gfn, u32 reg)
{
	mem_load_raw(gfn, reg);
}

void mem_store_ref(u64 gfn, u32 reg)
{
	mem_store_raw(gfn, reg);
}
