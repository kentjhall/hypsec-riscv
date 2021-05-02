#include "hypsec.h"
#include "MmioOps.h"

void __handle_plic_write(u64 fault_ipa, u32 len, unsigned long insn)
{
	void __iomem *base = __va(fault_ipa);
	u64 data;

	if(len == 4)
	{
		data = host_get_mmio_data(insn);
		writel_relaxed((u32)data, base);
	}
	else
	{
		print_string("\rhandle plic write panic\n");
		printhex_ul(len);
		v_panic();
	}
}

void __handle_plic_read(u64 fault_ipa, u32 len, unsigned long insn)
{
	u32 rt;
	u64 data;
	int shift;

	rt = insn_decode_rd(insn, false);
	shift = host_dabt_get_shift(insn, len);
	if (len == 4)
	{
		data = (u64)readl_relaxed(__va(fault_ipa));
		set_host_regs(rt, (ulong)data << shift >> shift);
	}
	else
	{
		/* We don't handle cases which len is not 4 bytes */
		print_string("\rhandle plic read panic\n");
		printhex_ul(len);
		v_panic();
	}
}
