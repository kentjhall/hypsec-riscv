#include "hypsec.h"
#include "MmioOps.h"


u32 handle_iommu_global_access(u32 hsr, u64 offset, u32 iommu_index)
{
	u32 ret;
	u64 data, iommu_enable, n, vmid, type, t_vmid;

	/* We don't care if it's read accesses */
	data = host_get_mmio_data(hsr);

	/* GR0 */
	if (offset >= 0 && offset < ARM_IOMMU_GR1_BASE)
	{
		if (offset == ARM_IOMMU_GR0_sCR0)
		{
			/* Check if the host tries to bypass IOMMU */
			iommu_enable = (data >> sCR0_SMCFCFG_SHIFT) & 1U;
			if (iommu_enable == 0UL)
			{
				ret = 0U;
			} else {
				ret = 1U;
			}
		}
		else if (offset == ARM_IOMMU_GR0_sCR2)
		{
			/*
			 * Check if the host tries to bypass VMID by
			 * writing the BPVMID[0:7] bits.
			 */
			if ((data & 0xff) == 0)
			{
				ret = 1U;
			}
			else
			{
				ret = 0U;
			}
		}
		else
			ret = 1U;
		/* GR1 */
	}
	else if (offset >= ARM_IOMMU_GR1_BASE && offset < ARM_IOMMU_GR1_END)
	{
		/* GR1 CBAR for the specific Context Bank Index */
		n = (offset - ARM_IOMMU_GR1_BASE) / 4U;
		vmid = get_iommu_cfg_vmid(n, iommu_index);
		type = data >> CBAR_TYPE_SHIFT;
		t_vmid = data & CBAR_VMID_MASK;
		if (vmid == 0U)
		{
			ret = 1U;
		}
		else
		{
			if (type == CBAR_TYPE_S2_TRANS && (vmid == (t_vmid)))
			{
				ret = 1U;
			}
			else
			{
				ret = 0U;
			}
		}
	}
	else {
		ret = 1U;
	}
	return check(ret);
}

/* FIXME: we have a pointer here */
u32 handle_iommu_cb_access(u64 offset)
{
	u64 cb_offset;
	u32 ret;

	offset -= ARM_IOMMU_GLOBAL_BASE;
	cb_offset = offset & ARM_IOMMU_PGSHIFT_MASK;

	if (cb_offset == ARM_IOMMU_CB_TTBR0)
	{
		/* We write hw_ttbr to CB_TTBR0 */
		ret = 2U;
	}
	else if (cb_offset == ARM_IOMMU_CB_CONTEXTIDR)
	{
		ret = 0U;
	}
	else if (cb_offset == ARM_IOMMU_CB_TTBCR)
	{
		//TODO: this case is not implemented in the verified code, can we remove it?
		ret = 3U;
	}
	else
	{
		/* let accesses to other registers and TLB flushes just
		 * happen since they don't affect our guarantees.
		 */
		ret = 1U;
	}
	
	return check(ret);
}

//FIXME: do we need to use MMIO in the following?
void __handle_iommu_write(u32 hsr, u64 fault_ipa, u32 len, u64 val, u32 write_val)
{
	void __iomem *base = (void*)fault_ipa;
	u64 data;

	if (len == 8U)
	{
		if (write_val == 0U)
		{
			data = host_get_mmio_data(hsr);
			writeq_relaxed(data, base);
		}
		else
		{
			writeq_relaxed(val, base);
		}
	}
	else if(len == 4)
	{
		data = host_get_mmio_data(hsr);
		writel_relaxed((u32)data, base);
	}
	else
	{
		print_string("\rhandle iommu write panic\n");
		printhex_ul(len);
		v_panic();
	}
}

void __handle_iommu_read(u32 hsr, u64 fault_ipa, u32 len)
{
	//TODO: We do not use vcpuid here
	u32 rt;
	u64 data;

	rt = host_dabt_get_rd(hsr);
	if (len == 8)
	{
		data = readq_relaxed((void *)fault_ipa);
		set_host_regs(rt, data);
	}
	else if (len == 4)
	{
		data = (u64)readl_relaxed((void *)fault_ipa);
		set_host_regs(rt, data);
	}
	else
	{
		/* We don't handle cases which len is smaller than 4 bytes */
		print_string("\rhandle iommu read panic\n");
		printhex_ul(len);
		v_panic();
	}
}
