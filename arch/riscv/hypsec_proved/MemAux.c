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
		/* protect hypsec text section (read-only) */
		if (addr >= (unsigned long)__pa_symbol(__hyp_text_start) &&
		    addr < (unsigned long)__pa_symbol(__hyp_text_end))
			perm = pgprot_val(PAGE_READ);
		else
			perm = pgprot_val(PAGE_WRITE_EXEC);
		new_pte = (pfn << _PAGE_PFN_SHIFT) | perm;
		/* VA_BITS config option must be set to 39 for 3 level paging */
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
	}
	else
	{
		/* Time to freak out */
		print_string("faults on host\n");
		print_string("pfn:\n");
		printhex_ul(pfn);
		print_string("owner:\n");
		printhex_ul(owner);
		v_panic();
	}
	release_lock_s2page();
}

/* TODO: I yanked this from AbstractMachine.c */
void clear_phys_page(unsigned long pfn)
{
	u64 addr = (u64)__va(pfn << PAGE_SHIFT);
	hs_memset((void *)addr, 0, PAGE_SIZE);
}

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
		__flush_dcache_area(__va(pfn << PAGE_SHIFT), PAGE_SIZE);
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
		print_string("pfn:\n");
		printhex_ul(pfn);
		print_string("owner:\n");
		printhex_ul(owner);
		v_panic();
	}

	__flush_dcache_area(__va(pfn << PAGE_SHIFT), PAGE_SIZE);
	release_lock_s2page();
}

void map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 paddr, perm;

	paddr = phys_page(pte);	
	/* protect hypsec text section (read-only) */
	if (paddr >= (unsigned long)__pa_symbol(__hyp_text_start) &&
	    paddr < (unsigned long)__pa_symbol(__hyp_text_end))
		perm = pgprot_val(PAGE_READ);
	/* We give the VM RWX permission now. */
	else 
		perm = pgprot_val(PAGE_WRITE_EXEC);

	if (level == 2U)
	{
		pte = pte | perm;
		/*
		 * TODO(etm): I think on ARM this is setting a huge page.
		 * 	On RISCV there's nothing special to do.
		 */
		/* ARM: pte &= ~PMD_TABLE_BIT; */
		mmap_s2pt(vmid, addr, 2U, pte);
	}
	else if (level == 3U)
	{
		pte = pte | perm;
		mmap_s2pt(vmid, addr, 3U, pte);
	}
}

void map_vm_io(u32 vmid, u64 gpa, u64 pa)
{
	u64 pte, pfn;
	u32 owner;

	pfn = pa / PAGE_SIZE;
	pte = pa + pgprot_val(PAGE_WRITE);

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
