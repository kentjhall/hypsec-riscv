#include <linux/types.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/hypsec_pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>
#include <kvm/pvops.h>

#include "hypsec.h"

#if 0 // TEMPORARY
u32 handle_pvops(u32 vmid, u32 vcpuid)
{
	u32 ret;
	u64 call_num, addr, size;

	call_num  = get_shadow_ctxt(vmid, vcpuid, 0);
	addr = get_shadow_ctxt(vmid, vcpuid, 1);
	size = get_shadow_ctxt(vmid, vcpuid, 2);
	ret = 1U;

	if (HOSTVISOR < vmid && vmid < COREVISOR)
	{
		if (call_num == KVM_SET_DESC_PFN)
		{
			grant_stage2_sg_gpa(vmid, addr, size);
		}
		else if (call_num == KVM_UNSET_DESC_PFN)
		{
			revoke_stage2_sg_gpa(vmid, addr, size);
		}
		else
		{
			ret = 0U;
		}
	}
	else
	{
		v_panic();
	}

	return check(ret);
}
#endif

void handle_host_stage2_fault(struct s2_host_regs *host_regs)
{
	u32 ret;
	u64 addr;

	addr = (csr_read(CSR_HTVAL) << 2) | (csr_read(CSR_STVAL) & 0x3);
	set_per_cpu_host_regs((u64)host_regs);

	pr_alert("handle_host_stage2_fault: TODO");
#if 0 // TEMPORARY
	ret = emulate_mmio(addr, csr_read(CSR_HTINST));
	if (ret == V_INVALID)
	{
		map_page_host(addr);
	}
#endif
}
