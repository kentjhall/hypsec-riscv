#include "hypsec.h"
#include "MmioOps.h"

void handle_plic_write(u64 fault_ipa, u32 len, unsigned long insn)
{
	__handle_plic_write(fault_ipa, len, insn);
}

void handle_plic_read(u64 fault_ipa, u32 len, unsigned long insn)
{
	__handle_plic_read(fault_ipa, len, insn);
}
