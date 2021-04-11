#include "hypsec.h"
#include "MmioOps.h"

void handle_iommu_write(u32 hsr, u64 fault_ipa, u32 len, u32 index)
{
	u64 offset, val, cbndx;
	u32 ret, write_val;

	offset = read_sysreg_hs(far) & ARM_IOMMU_OFFSET_MASK;
	write_val = 0U;

	if (offset < ARM_IOMMU_GLOBAL_BASE)
	{
		ret = handle_iommu_global_access(hsr, offset, index);
		if (ret == 0U)
		{
			print_string("\riommu invalid write: global access\n");
			v_panic();
		}
		else
		{
			__handle_iommu_write(hsr, fault_ipa, len, 0UL, write_val);
		}
	}
	else {
		ret = handle_iommu_cb_access(offset);
		if (ret == 0U)
		{
			print_string("\riommu invalid write: cb access\n");
			v_panic();	
		}
		else
		{
			if (ret == 2)
			{
				cbndx = iommu_get_cbndx(offset);
				val = get_iommu_cfg_hw_ttbr(cbndx, index);
				write_val = 1U;
				__handle_iommu_write(hsr, fault_ipa, len, val, write_val);
				/*print_string("\rwrite TTBR0\n");
				print_string("\roffset\n");
				printhex_ul(offset);
				print_string("\rcbndx\n");
				printhex_ul(cbndx);
				print_string("\rindex\n");
				printhex_ul(index);
				print_string("\rTTBR0\n");
				printhex_ul(val);
				u64 data = host_get_mmio_data(hsr);
				print_string("\rHOST TTBR0\n");
				printhex_ul(data);*/
			}
			//else if (ret == 3)
			//{
			//	u64 data = host_get_mmio_data(hsr);
			//	print_string("\rHOST TTBCR\n");
			//	printhex_ul(data);
			//	__handle_iommu_write(hsr, fault_ipa, len, 0UL, write_val);
			//}
			else
			{
				__handle_iommu_write(hsr, fault_ipa, len, 0UL, write_val);
			}
		}
	}
}

void handle_iommu_read(u32 hsr, u64 fault_ipa, u32 len)
{
	u64 offset;

	offset = fault_ipa & ARM_IOMMU_OFFSET_MASK;
	if (offset < ARM_IOMMU_GLOBAL_BASE)
	{
		__handle_iommu_read(hsr, fault_ipa, len);
	}
	else
	{
		__handle_iommu_read(hsr, fault_ipa, len);
	}	
}
