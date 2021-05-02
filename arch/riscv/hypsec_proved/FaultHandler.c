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

u32 handle_pvops(u32 vmid, u32 vcpuid)
{
	u32 ret;
	u64 sbi_num, call_num, addr, size, pc;

	sbi_num = get_shadow_ctxt(vmid, vcpuid, 17U); // a7
	call_num  = get_shadow_ctxt(vmid, vcpuid, 10U); // a0
	addr = get_shadow_ctxt(vmid, vcpuid, 11U); // a1
	size = get_shadow_ctxt(vmid, vcpuid, 12U); // a2
	ret = 1U;

	if (HOSTVISOR < vmid && vmid < COREVISOR)
	{
		if (sbi_num != SBI_EXT_HYPSEC_HVC)
		{
			ret = 0U;
		}
		else if (call_num == KVM_SET_DESC_PFN)
		{
			grant_stage2_sg_gpa(vmid, addr, size);
			pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
			set_shadow_ctxt(vmid, vcpuid, V_PC, pc + 4);
		}
		else if (call_num == KVM_UNSET_DESC_PFN)
		{
			revoke_stage2_sg_gpa(vmid, addr, size);
			pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
			set_shadow_ctxt(vmid, vcpuid, V_PC, pc + 4);
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

void handle_host_stage2_fault(struct s2_host_regs *host_regs)
{
	u32 ret;
	u64 addr;

	addr = (csr_read(CSR_HTVAL) << 2) | (csr_read(CSR_STVAL) & 0x3);
	set_per_cpu_host_regs((u64)host_regs);

	ret = emulate_mmio(addr);
	if (ret == V_INVALID)
	{
		map_page_host(addr);
	}
}
