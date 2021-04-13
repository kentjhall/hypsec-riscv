#include "hypsec.h"

/*
 * MmioPTAlloc
 */

//TODO: To Xupeng, please sync the code to use end
u64 alloc_iommu_pgd_page(void)
{
	u64 next, end;

	next = get_iommu_pgd_next();
	end = iommu_pgd_end();
	if (next + PAGE_SIZE <= end)
	{
		set_iommu_pgd_next(next + PAGE_SIZE);
	}
	else
	{
	        print_string("\rwe used all iommu pgd pages\n");
		v_panic();
	}
	return next;
}

u64 alloc_iommu_pmd_page(void)
{
	u64 next, end;

	next = get_iommu_pmd_next();
	end = iommu_pmd_end();

	if (next + PAGE_SIZE <= end)
	{
		set_iommu_pmd_next(next + PAGE_SIZE);
	}
	else
	{
	        print_string("\rwe used all iommu pmd pages\n");
		v_panic();
	}
	return next;
}
