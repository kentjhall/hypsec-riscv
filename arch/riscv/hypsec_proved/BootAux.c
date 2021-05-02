#include "hypsec.h"

/*
 * BootAux
 */

void unmap_and_load_vm_image(u32 vmid, u64 target_addr, u64 remap_addr, u64 num)
{
	u64 pte, start, end, mb_num;

	start = target_addr;
	end = target_addr + num * PAGE_SIZE;
	mb_num = (end - start + (PMD_SIZE - 1)) / PMD_SIZE;

	while (mb_num > 0UL)
	{
		pte = walk_s2pt(COREVISOR, remap_addr);
		if (phys_page(pte) >> PAGE_SHIFT == 0UL)
		{
			/* PFN is zero */
			v_panic();
		}
		else
		{
			/*
			 * Insert a PTE mapping the guest phys addr start to the real
			 * phys memory backing the guest VM image at start
			 *
			 * Note: we're mapping the image using 2MB huge pages, so the
			 * backing physical memory needs to be 2MB page aligned, or else.
			 * We enforce this in the KVM_RISCV_SET_BOOT_INFO ioctl in vm.c
			 */
			prot_and_map_vm_s2pt(vmid, start, pte, 2U);
		}
		start += PMD_SIZE;
		remap_addr = remap_addr + (start - target_addr);
		target_addr = start;
		mb_num--;
	}
}
