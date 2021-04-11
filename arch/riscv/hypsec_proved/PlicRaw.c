#include "hypsec.h"
#include "MmioOps.h"

u64 host_get_mmio_data()
{
	int rt;

	rt = host_dabt_get_rd();
	return get_host_regs(rt);
}
