#include "hypsec.h"

void hs_clear_vm_stage2_range(u32 vmid, u64 start, u64 size)
{
	u32 power;

	power = get_vm_poweron(vmid);
	if (power == 0UL)
	{
		clear_vm_range(vmid, start / PAGE_SIZE, size / PAGE_SIZE);
	}
}

void __hs_riscv_lpae_map(u64 iova, u64 paddr, u64 prot, u32 cbndx, u32 index)
{
	u64 pfn, gfn, pte;

	pfn = paddr / PAGE_SIZE;
	gfn = iova / PAGE_SIZE;
	pte = iommu_init_pte(prot, paddr);
	iommu_assign_page(cbndx, index, pfn, gfn);
	iommu_map_page(cbndx, index, iova, pte);
}

void hs_kvm_phys_addr_ioremap(u32 vmid, u64 gpa, u64 pa, u64 size)
{
	u64 n;

	n = (size + (PAGE_SIZE - 1)) / PAGE_SIZE;
	while (n > 0)
	{
		map_io(vmid, gpa, pa);
		gpa += PAGE_SIZE;
		pa += PAGE_SIZE;
		n -= 1;
	}
}
