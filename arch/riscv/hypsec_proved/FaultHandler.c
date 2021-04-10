#include <linux/types.h>
//#include <asm/kvm_asm.h>
//#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
//#include <asm/kvm_arm.h>
//#include <asm/kvm_mmu.h>
//#include <asm/kvm_mmio.h>
//#include <asm/kvm_emulate.h>
//#include <asm/virt.h>
//#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>
#include <kvm/pvops.h>

#include "hypsec.h"

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

void handle_host_stage2_fault(unsigned long host_lr,
					 struct kvm_cpu_context *host_regs)
{
	u32 ret;
	u64 addr;
	addr = (csr_read(CSR_HTVAL) << 2) | (csr_read(CSR_STVAL) & 0x3);

	/* TODO (etm): Do we actually need to do this?
	set_per_cpu_host_regs((u64)host_regs);
	*/

//	TODO (etm): Merge in code to emulate mmio. For now, just assume we have
//     a normal HvPA fault.
//	ret = emulate_mmio(addr, read_sysreg(esr_hs));
	ret = V_INVALID;
	if (ret == V_INVALID)
	{
		map_page_host(addr);
	}
}
