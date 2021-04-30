#include "hypsec.h"

/*
 * VCPUOps
 */

void save_shadow_kvm_regs()
{
	u64 scause;
	u32 vmid, vcpuid;

	vmid = get_cur_vmid();
	vcpuid = get_cur_vcpu_id();
	scause = get_shadow_ctxt(vmid, vcpuid, V_EC);

	if (!(scause & CAUSE_IRQ_FLAG))
	{
		if (scause == EXC_VIRTUAL_INST_FAULT)
		{
			prep_wfx(vmid, vcpuid);
		}
		else if (scause == EXC_SUPERVISOR_SYSCALL)
		{
			prep_hvc(vmid, vcpuid);
		}
		else if (scause == EXC_INST_GUEST_PAGE_FAULT ||
		         scause == EXC_LOAD_GUEST_PAGE_FAULT ||
		         scause == EXC_STORE_GUEST_PAGE_FAULT)
		{
			prep_abort(vmid, vcpuid);
		}
		else
		{
			print_string("unknown exception\n");
			v_panic();
		}
	}
}

//TODO: Xupeng, please sync
void restore_shadow_kvm_regs()
{
	u64 dirty, scause, pc, addr;
	u32 vmid, vcpuid;

	vmid = get_cur_vmid();
	vcpuid = get_cur_vcpu_id();
	dirty = get_shadow_ctxt(vmid, vcpuid, V_DIRTY);

	if (dirty == INVALID64)
	{
        	//TODO: fill in for management hvc call
		if (vm_is_inc_exe(vmid) == 0U)
		{
			reset_gp_regs(vmid, vcpuid);
			reset_sys_regs(vmid, vcpuid);
		}

		set_shadow_dirty_bit(vmid, vcpuid, 0UL);
    	}
	else
	{
	        scause = get_shadow_ctxt(vmid, vcpuid, V_EC);
		if (!(scause & CAUSE_IRQ_FLAG) && dirty)
		{
			sync_dirty_to_shadow(vmid, vcpuid);
		}

		if (dirty & PENDING_EXCEPT_INJECT_FLAG)
		{
			v_update_exception_gp_regs(vmid, vcpuid);

		}

		if (dirty & DIRTY_PC_FLAG)
		{
			pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
			set_shadow_ctxt(vmid, vcpuid, V_PC, pc + get_shadow_skip_len(vmid, vcpuid));
		}

		set_shadow_dirty_bit(vmid, vcpuid, 0UL);
		set_shadow_skip_len(vmid, vcpuid, 0UL);
		addr = get_vm_fault_addr(vmid, vcpuid);

		//TODO: Xupeng did not do exactly the same here...
		// https://github.com/VeriGu/certikos_columbia/blob/master/hypsec/code/VCPUOps.c
		if (get_shadow_ctxt(vmid, vcpuid, V_FLAGS) & PENDING_FSC_FAULT)
		{
			post_handle_shadow_s2pt_fault(vmid, vcpuid, addr);
		}

		set_shadow_ctxt(vmid, vcpuid, V_FLAGS, 0UL);
	}
}
