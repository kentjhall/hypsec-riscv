#include "hypsec.h"
#include "MmioOps.h"

u64 host_get_mmio_data(unsigned long insn)
{
	int rt;

	rt = insn_decode_rd(insn, true);
	return get_host_regs(rt);
}
