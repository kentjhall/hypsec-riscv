#include "hypsec.h"

/*
 * MemManager
 */

void map_page_host(u64 addr)
{
	u64 pfn, new_pte, perm;
	u32 owner, count;

	pfn = addr / PAGE_SIZE;
	new_pte = 0UL;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	/*
	 * There's nothing special to do for device memory in RV64 so
	 * we merge the INVALID_MEM (mmio hole), and guest shared mem
	 * cases into one block.
	 *
	 * TODO: could count > 0 but page is only SPA merged, not shared?
	 */
	if (owner == INVALID_MEM || (owner == HOSTVISOR || count > 0U))
	{
		// protect kernel text section (read-only)
		if (addr >= (unsigned long)__pa_symbol(_start) && addr < (unsigned long)__pa_symbol(__init_text_begin))
			perm = pgprot_val(PAGE_READ_EXEC);
		else
			perm = pgprot_val(PAGE_WRITE_EXEC);
		new_pte = (pfn << _PAGE_PFN_SHIFT) | perm;
		/* VA_BITS config option must be set to 39 for 3 level paging */
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
	}
	else
	{
		/* Time to freak out */
		panic("\rfaults on host\n");
	}
	release_lock_s2page();
}
#if 0
void clear_vm_page(u32 vmid, u64 pfn)
{
	u32 owner;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	if (owner == vmid)
	{
		clear_pfn_host(pfn);
		set_pfn_owner(pfn, HOSTVISOR);
		set_pfn_count(pfn, 0U);
		set_pfn_map(pfn, 0UL);
		clear_phys_page(pfn);
		__flush_dcache_area(__hs_va(pfn << PAGE_SHIFT), PAGE_SIZE);
	}
	release_lock_s2page();
}

void assign_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn)
{
	u64 map;
	u32 owner, count;

	acquire_lock_s2page();

	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == HOSTVISOR)
	{
		if (count == 0U)
		{
			set_pfn_owner(pfn, vmid);
			clear_pfn_host(pfn);
			set_pfn_map(pfn, gfn);
			fetch_from_doracle(vmid, pfn, 1UL);
		}
		else
		{
			//pfn is mapped to a hostvisor IOMMU table
			print_string("\rassign pfn used by host iommu device\n");
			v_panic();
		}
	} 
	else if (owner == vmid)
	{
		map = get_pfn_map(pfn);
		/* the page was mapped to another gfn already! */
		// if gfn == map, it means someone in my VM has mapped it
		if (gfn == map || map == INVALID64)
		{
 			if (count == INVALID_MEM)
			{
				set_pfn_count(pfn, 0U);
			}

			if (map == INVALID64)
			{
				set_pfn_map(pfn, gfn);
			}
		}
		else
		{
			print_string("\rmap != gfn || count != INVALID_MEM\n");
			v_panic();
		}
	}
	else
	{
		v_panic();
	}
	__flush_dcache_area(__hs_va(pfn << PAGE_SHIFT), PAGE_SIZE);
	release_lock_s2page();
}

void map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 paddr, perm;

	paddr = phys_page(pte);
	/* We give the VM RWX permission now. */
	perm = pgprot_val(PAGE_S2_KERNEL);

	if (level == 2U)
	{
		pte = paddr | perm;
		pte &= ~PMD_TABLE_BIT;
		mmap_s2pt(vmid, addr, 2U, pte);
	}
	else if (level == 3U)
	{
		pte = paddr | perm;
		mmap_s2pt(vmid, addr, 3U, pte);
	}
}

void map_vm_io(u32 vmid, u64 gpa, u64 pa)
{
	u64 pte, pfn;
	u32 owner;

	pfn = pa / PAGE_SIZE;
	pte = pa + (pgprot_val(PAGE_S2_DEVICE) | S2_RDWR);

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	// check if pfn is truly within an I/O area
	if (owner == INVALID_MEM)
	{ 
		mmap_s2pt(vmid, gpa, 3U, pte);
	}
	release_lock_s2page();
}

void grant_vm_page(u32 vmid, u64 pfn)
{
	u32 owner, count;
	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == vmid && count < MAX_SHARE_COUNT)
	{
		set_pfn_count(pfn, count + 1U);
	}
	release_lock_s2page();
}

void revoke_vm_page(u32 vmid, u64 pfn)
{
	u32 owner, count;
	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == vmid && count > 0U)
	{
		set_pfn_count(pfn, count - 1U);
		if (count == 1U)
		{
			clear_pfn_host(pfn);
			fetch_from_doracle(vmid, pfn, 1UL);
		}
	}
	release_lock_s2page();
}
#endif

void assign_pfn_to_iommu(u32 vmid, u64 gfn, u64 pfn)
{
	/* No IOMMU in RV64 */

//	u64 map;
//	u32 owner, count;
//
//	acquire_lock_s2page();
//	owner = get_pfn_owner(pfn);
//	count = get_pfn_count(pfn);
//	map = get_pfn_map(pfn);
//
//	if (owner == HOSTVISOR)
//	{
//		if (count == 0)
//		{
//			clear_pfn_host(pfn);
//			set_pfn_owner(pfn, vmid);
//			set_pfn_map(pfn, gfn);
//			set_pfn_count(pfn, INVALID_MEM);
//		}
//		else {
//			print_string("\r\assign_to_smmu: host pfn count\n");
//			v_panic();
//		}
//	}
//	//TODO: LXP checks owner != vmid, why? this does not work
//	else if (owner != INVALID_MEM)
//	{
//		print_string("\rvmid\n");
//		printhex_ul(vmid);
//		print_string("\rowner\n");
//		printhex_ul(owner);
//		print_string("\rpfn\n");
//		printhex_ul(pfn);
//		print_string("\rassign_to_smmu: owner unknown\n");
//		v_panic();
//	}
//	release_lock_s2page();
}

void update_iommu_page(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte)
{
	/* No IOMMU in RV64 */

//	u64 pfn, gfn;
//	u32 owner, count, map;
//
//	acquire_lock_s2page();
//	pfn = phys_page(pte) / PAGE_SIZE;
//	gfn = iova / PAGE_SIZE;
//	owner = get_pfn_owner(pfn);
//	map = get_pfn_map(pfn);
//	//TODO: sync with LXP, we map the page in two cases
//	//1. if the pfn is a device IO (owner is INVALID) or
//	//2. vmid == owner && gfn == map
//	if ((owner == INVALID_MEM) || (vmid == owner && gfn == map))
//	{
//		map_spt(cbndx, index, iova, pte);
//		if (owner == HOSTVISOR)
//		{
//			count = get_pfn_count(pfn);
//			if (count < HS_SMMU_CFG_SIZE)
//			{
//				set_pfn_count(pfn, count + 1U);
//			}
//		}
//	}
//	else
//	{
//		v_panic();
//		print_string("\rbug in update_smmu_page\n");
//		print_string("\rvmid\n");
//		printhex_ul(vmid);
//		print_string("\rowner\n");
//		printhex_ul(owner);
//		print_string("\rgfn\n");
//		printhex_ul(gfn);
//		print_string("\rmap\n");
//		printhex_ul(map);
//	}
//	release_lock_s2page();
}

void unmap_iommu_page(u32 cbndx, u32 index, u64 iova)
{
	/* No IOMMU in RV64 */

//	u64 pte, pfn;
//	u32 owner, count;
//
//	acquire_lock_s2page();
//	pte = unmap_spt(cbndx, index, iova);
//	pfn = phys_page(pte) / PAGE_SIZE;
//	owner = get_pfn_owner(pfn);
//	if (owner == HOSTVISOR)
//	{
//		count = get_pfn_count(pfn);
//		if (count > 0U)
//		{
//			set_pfn_count(pfn, count - 1U);
//		}
//	}
//	release_lock_s2page();
}
