#include "hypsec.h"

/*
 * MmioSPTWalk
 */

void clear_iommu_pt(u32 cbndx, u32 index) 
{
	iommu_pt_clear(cbndx, index);
}

u64 walk_iommu_pt(u32 cbndx, u32 num, u64 addr)
{
	u64 ttbr, pgd, pmd, ret;

	ttbr = get_iommu_cfg_hw_ttbr(cbndx, num);
	pgd = walk_iommu_pgd(ttbr, addr, 0U);
	pmd = walk_iommu_pmd(pgd, addr, 0U);
	ret = walk_iommu_pte(pmd, addr);
	return ret;
}

void set_iommu_pt(u32 cbndx, u32 num, u64 addr, u64 pte)
{
	u64 ttbr, pgd, pmd;

	ttbr = get_iommu_cfg_hw_ttbr(cbndx, num);
	if (ttbr == 0UL)
	{
		print_string("\rset iommu pt: vttbr = 0\n");
		v_panic();
	}
	else 
	{
		pgd = walk_iommu_pgd(ttbr, addr, 1U);
		pmd = walk_iommu_pmd(pgd, addr, 1U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
		{
			set_iommu_pte(pmd, addr, pte);
		}
		else
		{
			v_panic();
		}
	}
}

//TODO: this is not in here in Xupeng's code
/*u64 unmap_iommu_pt(u32 cbndx, u32 index, u64 addr) 
{
	u64 ttbr, pgd, pmd, pte;

	ttbr = get_iommu_cfg_hw_ttbr(cbndx, index);
	pgd = walk_iommu_pgd(ttbr, addr, 0U);
	pmd = walk_iommu_pmd(pgd, addr, 0U);
	pte = walk_iommu_pte(pmd, addr);
	if (pte != 0UL)
	{
		set_iommu_pte(pmd, addr, 0UL);
	}
	return pte;
}*/

//Xupeng has dev_load_ref, dev_store_ref
