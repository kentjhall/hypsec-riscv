#include "hypsec.h"
#include "MmioOps.h"

/*
 * PTWalk
 */

u64 walk_pgd(u32 vmid, u64 hgatp, u64 addr, u32 alloc)
{
	u64 hgatp_pa, ret, pgd_idx, pgd, pgd_pa;

	ret = 0UL;
	hgatp_pa = phys_page(hgatp & HGATP_PPN);
	printk("hgatp:    0x%lx\n", (unsigned long) hgatp);
	printk("hgatp_pa: 0x%lx\n", (unsigned long) hgatp_pa);
	printk("<[hgatp va]> 0x%lx\n", (unsigned long) __va(hgatp_pa));
	printk("[walk_pgd %c]\n", 'a');
	if (vmid == COREVISOR)
	{
		printk("[walk_pgd %c]\n", 'b');
		pgd_idx = pgd_index(addr);
	}
	else
	{
		printk("[walk_pgd %c]\n", 'c');
		pgd_idx = pgd_idx(addr);
	}

	printk("[pgd_idx]: 0x%0lx\n", (unsigned long) pgd_idx);
	printk("[walk_pgd %c]\n", 'd');
	printk("<[pgd va]> 0x%lx\n", (unsigned long) __va(hgatp_pa|(pgd_idx * 8UL)));
	pgd = pt_load(vmid, hgatp_pa | (pgd_idx * 8UL));
	if (pgd == 0UL && alloc == 1U)
	{
		printk("[walk_pgd %c]\n", 'e');
		pgd_pa = alloc_s2pt_pgd(vmid);
		pgd = (PFN_DOWN(pgd_pa) << _PAGE_PFN_SHIFT) | pgprot_val(PAGE_TABLE);
		pt_store(vmid, hgatp_pa | (pgd_idx * 8UL), pgd);
	}
	printk("[walk_pgd %c]\n", 'f');
	ret = pgd;
	printk("[walk_pgd] pgd retval: 0x%llx\n", pgd);
	return check64(ret);
}

#if 0
/* No PUD used with RISCV Sv39x4 paging so we fold PUD into PGD */
u64 walk_pud(u32 vmid, u64 pgd, u64 addr, u32 alloc)
{
	u64 pgd_pa, ret, pud_idx, pud, pud_pa;

	ret = 0UL;

	if (pgd != 0UL)
	{
		pgd_pa = phys_page(pgd);
		pud_idx = pud_idx(addr);
		pud = pt_load(vmid, pgd_pa | (pud_idx * 8UL));
		if (pud == 0UL && alloc == 1U)
		{
			pud_pa = alloc_s2pt_pud(vmid);
			pud = pud_pa | pgprot_val(PAGE_TABLE);
			pt_store(vmid, pgd_pa | (pud_idx * 8UL), pud);
		}
		ret = pud;
	}
	return check64(ret);
}
#endif

u64 walk_pmd(u32 vmid, u64 pud, u64 addr, u32 alloc)
{
	u64 pud_pa, ret, pmd_idx, pmd, pmd_pa;
	printk("[in walk_pmd]\n");
	ret = 0UL;
	if (pud != 0UL)
	{
//		pud_pa = phys_page(pud);
		pud_pa = (pud >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;
		pmd_idx = pmd_idx(addr);
		printk("pud:    0x%lx\n", (unsigned long) pud);
		printk("pud_pa: 0x%lx\n", (unsigned long) pud_pa);
		printk("[pmd_idx]: 0x%0lx\n", (unsigned long) pmd_idx);

		printk("<[pmd va]> 0x%lx\n", (unsigned long) __va(pud_pa|(pmd_idx * 8UL)));
		pmd = pt_load(vmid, pud_pa | (pmd_idx * 8));

		if (pmd == 0UL && alloc == 1U)
		{
			pmd_pa = alloc_s2pt_pmd(vmid);
			pmd = (PFN_DOWN(pmd_pa) << _PAGE_PFN_SHIFT) | pgprot_val(PAGE_TABLE);
			pt_store(vmid, pud_pa | (pmd_idx * 8UL), pmd);
		}
		ret = pmd;
	}
	return check64(ret);
}

u64 walk_pte(u32 vmid, u64 pmd, u64 addr)
{
	u64 pmd_pa, ret, pte_idx;

	ret = 0UL;
	if (pmd != 0UL)
	{
//		pmd_pa = phys_page(pmd);
		pmd_pa = (pmd >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;
		pte_idx = pte_idx(addr);
		ret = pt_load(vmid, pmd_pa | (pte_idx * 8UL));
	}
	return check64(ret);
}

/* TODO (etm): these bits are reserved by the ISA, but free for us to use */
#define PMD_MARK 1UL << 55
#define PTE_MARK 1UL << 56

void v_set_pmd(u32 vmid, u64 pud, u64 addr, u64 pmd)
{
	u64 pud_pa, pmd_idx;

//	pud_pa = phys_page(pud);
	pud_pa = (pud >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;
	pmd_idx = pmd_idx(addr);
	//TODO: this is for grant/revoke OPT
	// If we turn this on we need to clear this bit before using the PPN
	// in each PTE
//	pmd |= PMD_MARK;
	pt_store(vmid, pud_pa | (pmd_idx * 8UL), pmd);
}

void v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte)
{
	u64 pmd_pa, pte_idx;
	printk("[v_set_pte]\n");
//	pmd_pa = phys_page(pmd);
	pmd_pa = (pmd >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;
	pte_idx = pte_idx(addr);
	//TODO: this is for grant/revoke OPT
	// If we turn this on we need to clear this bit before using the PPN
	// in each PTE
//	pte |= PTE_MARK;

	printk("<[pte va]> 0x%lx\n", (unsigned long) __va(pmd_pa | (pte_idx * 8UL)));
	pt_store(vmid, pmd_pa | (pte_idx * 8UL), pte);
}