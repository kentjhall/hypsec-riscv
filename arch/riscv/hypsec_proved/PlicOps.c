#include "hypsec.h"
#include "MmioOps.h"

//TODO: update to deal with u32 in ret here
u32 emulate_mmio(u64 addr)
{
	u32 ret;

	acquire_lock_plic();
	ret = is_plic_range(addr);
	if (ret != V_INVALID)
	{
		handle_host_mmio();
	}
	release_lock_plic();
	return ret;
}
