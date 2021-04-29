#include "hypsec.h"
#include "MmioOps.h"

u32 is_plic_range(u64 addr)
{
	u32 res;
	u64 base, size;

	res = V_INVALID;

	base = get_plic_base();
	size = get_plic_size();
	if ((base <= addr) && (addr < base + size))
	{
		res = 0;
	}
	return res;
}

void handle_host_mmio(void)
{
	u64 base_addr;
	u64 fault_ipa;
	u32 is_write, len;
	unsigned long insn = host_read_insn();

	base_addr = get_plic_hyp_base();
	fault_ipa = host_get_fault_ipa(); 
	len = host_dabt_get_as(insn);
	is_write = host_dabt_is_write();

	if (is_write == 0U)
	{
		handle_plic_read(fault_ipa, len, insn);
		host_skip_instr(insn);
	}
	else
	{
		handle_plic_write(fault_ipa, len, insn);
		host_skip_instr(insn);
	}

	if (csr_read(CSR_SIP) & (1UL << IRQ_S_EXT))
		csr_set(CSR_HVIP, 1UL << IRQ_VS_EXT);
	else {
		csr_clear(CSR_HVIP, 1UL << IRQ_VS_EXT);
		csr_set(CSR_SIE, IE_EIE);
	}
}
