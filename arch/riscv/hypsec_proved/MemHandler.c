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
