#include "hypsec.h"

/*
 * BootAux
 */

void unmap_and_load_vm_image(u32 vmid, u64 target_addr, u64 remap_addr, u64 num)
{
	u64 gfn, pte, pa, pfn, start, end, mb_num;

	start = target_addr / PAGE_SIZE * PAGE_SIZE;
	end = target_addr + num * PAGE_SIZE;
	mb_num = (end - start + (PAGE_SIZE - 1)) / PAGE_SIZE;

	while (mb_num > 0UL)
	{
		pte = walk_s2pt(COREVISOR, remap_addr);
		pa = phys_page(pte);
		pfn = pa >> PAGE_SHIFT;
		gfn = start / PAGE_SIZE;
		if (pfn == 0UL)
		{
			v_panic();
		}
		else
		{
			prot_and_map_vm_s2pt(vmid, gfn * PAGE_SIZE, pfn << _PAGE_PFN_SHIFT, 3U);
		}
		start += PAGE_SIZE;
		remap_addr = remap_addr + (start - target_addr);
		target_addr = start;
		mb_num--;
	}
}
