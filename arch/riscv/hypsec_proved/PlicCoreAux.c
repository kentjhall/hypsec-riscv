#include "hypsec.h"
#include "MmioOps.h"

void __handle_plic_write(u64 fault_ipa, u32 len)
{
	void __iomem *base = __va(fault_ipa);
	u64 data;
	/* int i; */
	/* for (i = 0; i < 32; ++i) */
	/* 	printhex_ul(get_host_regs(i)); */

	if(len == 4)
	{
		data = host_get_mmio_data();
		print_string("write data\n");
		printhex_ul(data);
		/* print_string("base\n"); */
		/* printhex_ul((unsigned long long)base); */
		writel_relaxed((u32)data, base);
		/* writel_relaxed((u32)data, base); */
		print_string("write done\n");
	}
	else
	{
		print_string("\rhandle plic write panic\n");
		printhex_ul(len);
		v_panic();
	}
}

void __handle_plic_read(u64 fault_ipa, u32 len)
{
	u32 rt;
	u64 data;

	rt = host_dabt_get_rd();
	if (len == 4)
	{
		data = (u64)readl_relaxed(__va(fault_ipa));
		set_host_regs(rt, data);
	}
	else
	{
		/* We don't handle cases which len is not 4 bytes */
		print_string("\rhandle plic read panic\n");
		printhex_ul(len);
		v_panic();
	}
}
