#include "hypsec.h"
#include "MmioOps.h"
#include <asm/sbi.h>

/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 vmid, u32 vcpuid)
{
	u64 pc, hstatus, sstatus, load_addr;

	pc = get_int_pc(vmid, vcpuid);
	load_addr = search_load_info(vmid, pc);

	if (load_addr == 0UL)
	{
		print_string("\reset gp reg\n");
		v_panic();
	}
	else
	{
		clear_shadow_gp_regs(vmid, vcpuid);
		hstatus = get_int_hstatus(vmid, vcpuid);
		sstatus = get_int_sstatus(vmid, vcpuid);
		set_shadow_ctxt(vmid, vcpuid, V_HSTATUS, hstatus);
		set_shadow_ctxt(vmid, vcpuid, V_SSTATUS, sstatus);
		set_shadow_ctxt(vmid, vcpuid, V_PC, pc);
		reset_fp_regs(vmid, vcpuid);
    	}
}

void reset_fp_regs(u32 vmid, int vcpu_id)
{
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	struct kvm_vcpu *vcpu = vcpu;
	struct kvm_cpu_context *kvm_cpu_context;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	kvm_cpu_context = &vcpu->arch.guest_context;
	hs_memcpy(&shadow_ctxt->ctxt.fp, &kvm_cpu_context->fp,
					sizeof(union __riscv_fp_state));
}

void reset_sys_regs(u32 vmid, u32 vcpuid)
{
	u64 val;
	u32 i = 0U;
	while (i < SHADOW_SYS_REGS_SIZE)
	{
		//TODO:this will not work, we need to pass vmid and vcpuid
		val = get_sys_reg_desc_val(i);
		set_shadow_ctxt(vmid, vcpuid, i + CSRS_START, val);
		i += 1U;
	}
}

void sync_dirty_to_shadow(u32 vmid, u32 vcpuid)
{
	u32 i = 0U;
	u64 dirty = get_shadow_dirty_bit(vmid, vcpuid);
	while (i <= GP_REG_END)
	{
		if (dirty & (1U << i))
		{
			u64 reg = get_int_gpr(vmid, vcpuid, i);
			set_shadow_ctxt(vmid, vcpuid, i, reg);
		}
		i += 1U;
	}
}

//make sure we only use get_int_ctxt to access general purposes regs
void clear_shadow_gp_regs(u32 vmid, u32 vcpuid) {
	struct hs_data *hs_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	hs_memset(&hs_data->shadow_vcpu_ctxt[offset].ctxt, 0, sizeof(struct kvm_cpu_context));
}

void prep_wfx(u32 vmid, u32 vcpuid)
{
	unsigned long insn = vm_read_insn(vmid, vcpuid);
	if (insn == -1) // let KVM handle it if failed to read instruction
		return;
	set_shadow_skip_len(vmid, vcpuid, INSN_LEN(insn));
	set_shadow_dirty_bit(vmid, vcpuid, DIRTY_PC_FLAG);
}

void prep_hvc(u32 vmid, u32 vcpuid)
{
	u64 sbi_num, a0;

	sbi_num = get_shadow_ctxt(vmid, vcpuid, 17U); // a7
	a0 = get_shadow_ctxt(vmid, vcpuid, 10U);

	set_int_gpr(vmid, vcpuid, 10U, a0);
	set_int_gpr(vmid, vcpuid, 11U, get_shadow_ctxt(vmid, vcpuid, 11U));
	set_int_gpr(vmid, vcpuid, 12U, get_shadow_ctxt(vmid, vcpuid, 12U));
	set_int_gpr(vmid, vcpuid, 13U, get_shadow_ctxt(vmid, vcpuid, 13U));
	set_int_gpr(vmid, vcpuid, 14U, get_shadow_ctxt(vmid, vcpuid, 14U));
	set_int_gpr(vmid, vcpuid, 15U, get_shadow_ctxt(vmid, vcpuid, 15U));
	set_int_gpr(vmid, vcpuid, 16U, get_shadow_ctxt(vmid, vcpuid, 16U));
	set_int_gpr(vmid, vcpuid, 17U, sbi_num);

	if (sbi_num == SBI_EXT_0_1_SEND_IPI ||
	    sbi_num == SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID)
	{
		(void)vm_read(vmid, vcpuid, false, a0); // handled by KVM
	}
	else if (sbi_num == SBI_EXT_0_1_SHUTDOWN)
	{
		set_vm_poweroff(vmid);
	}
}

//synchronized
void prep_abort(u32 vmid, u32 vcpuid)
{
	u64 fault_ipa, reg;
	u32 Rd;
	u64 scause;
	unsigned long insn;

	fault_ipa = get_vm_fault_addr(vmid, vcpuid);

	//TODO: sync with verified code to support QEMU 3.0
	if (fault_ipa < MAX_MMIO_ADDR)
	{
		insn = vm_read_insn(vmid, vcpuid);
		if (insn == -1) // let KVM handle it if failed to read instruction
			return;

		scause = get_shadow_ctxt(vmid, vcpuid, V_EC);
		Rd = insn_decode_rd(insn, scause == EXC_STORE_GUEST_PAGE_FAULT);

		set_shadow_skip_len(vmid, vcpuid, INSN_LEN(insn));
		set_shadow_dirty_bit(vmid, vcpuid, DIRTY_PC_FLAG);

		if (scause != EXC_STORE_GUEST_PAGE_FAULT)
		{
			set_shadow_dirty_bit(vmid, vcpuid, 1 << Rd);
		}
		else
		{
			reg = get_shadow_ctxt(vmid, vcpuid, Rd);
			set_int_gpr(vmid, vcpuid, Rd, reg);
		}
	}
}

void v_update_exception_gp_regs(u32 vmid, u32 vcpuid)
{
	u64 vsstatus, scause, stval, pc, new_pc;

	vsstatus = get_shadow_ctxt(vmid, vcpuid, V_VSSTATUS);

	/* Change Guest SSTATUS.SPP bit */
	vsstatus &= ~SR_SPP;
	if (get_shadow_ctxt(vmid, vcpuid, V_SSTATUS) & SR_SPP)
		vsstatus |= SR_SPP;

	/* Change Guest SSTATUS.SPIE bit */
	vsstatus &= ~SR_SPIE;
	if (vsstatus & SR_SIE)
		vsstatus |= SR_SPIE;

	/* Clear Guest SSTATUS.SIE bit */
	vsstatus &= ~SR_SIE;

	/* Update Guest SSTATUS */
	set_shadow_ctxt(vmid, vcpuid, V_VSSTATUS, vsstatus);

	/* Update Guest SCAUSE, STVAL, and SEPC */
	scause = get_shadow_ctxt(vmid, vcpuid, V_EC);
	stval = get_shadow_ctxt(vmid, vcpuid, V_STVAL);
	pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
	set_shadow_ctxt(vmid, vcpuid, V_VSEPC, pc);
	set_shadow_ctxt(vmid, vcpuid, V_VSCAUSE, scause);
	set_shadow_ctxt(vmid, vcpuid, V_VSTVAL, stval);

	/* Set Guest PC to Guest exception vector */
	new_pc = get_shadow_ctxt(vmid, vcpuid, V_VSTVEC);
	set_shadow_ctxt(vmid, vcpuid, V_PC, new_pc);
}

//TODO: API is a bit different, why is level not 32 bit?
void post_handle_shadow_s2pt_fault(u32 vmid, u32 vcpuid, u64 addr)
{
	u64 pte;
	u32 level;
	pte = get_int_new_pte(vmid, vcpuid);
	level = get_int_new_level(vmid, vcpuid);
	prot_and_map_vm_s2pt(vmid, addr, pte, level);
}

//TODO: where is this in the proof?
void v_hypsec_inject_undef(u32 vmid, u32 vcpuid)
{
	set_shadow_dirty_bit(vmid, vcpuid, PENDING_UNDEF_INJECT);
}


