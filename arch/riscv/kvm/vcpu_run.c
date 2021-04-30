#include <asm/csr.h>
#include <asm/hwcap.h>
#include <asm/kvm_host.h>
#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

static void __activate_traps(struct kvm_vcpu *vcpu)
{
	csr_write(CSR_HEDELEG, HEDELEG_GUEST_FLAGS);
	csr_write(CSR_HIDELEG, HIDELEG_GUEST_FLAGS);
}

static void __load_guest_stage2(u64 vmid)
{
	csr_write(CSR_HGATP, get_pt_hgatp((u32)vmid));
}

static inline void __populate_fault_info(struct kvm_vcpu *vcpu, u64 scause,
		                         struct shadow_vcpu_context *shadow_ctxt)
{
	u64 htval = shadow_ctxt->trap.htval, stval = shadow_ctxt->trap.stval;

	/*
	 * Here we'd like to avoid calling handle_shadow_s2pt_fault
	 * twice if it's GPA belongs to MMIO region. Since no mapping
	 * should be built anyway.
	 */
	if (!is_mmio_gpa((htval << 2) | (stval & 0x3))) {
		hs_memset(&vcpu->arch.walk_result, 0, sizeof(struct s2_trans));
		shadow_ctxt->flags |= PENDING_FSC_FAULT;
	}
}

/*
 * Return true when we were able to fixup the guest exit and should return to
 * the guest, false when we should restore the host state and return to the
 * main run loop.
 */
static inline bool fixup_guest_exit(struct kvm_vcpu *vcpu, u64 scause, u32 vmid, u32 vcpuid)
{
	struct shadow_vcpu_context *shadow_ctxt;

	vcpu->arch.guest_trap.sepc = vcpu->arch.guest_context.sepc;
	vcpu->arch.guest_trap.scause = scause;
	vcpu->arch.guest_trap.stval = csr_read(CSR_STVAL);
	vcpu->arch.guest_trap.htval = csr_read(CSR_HTVAL);
	vcpu->arch.guest_trap.htinst = csr_read(CSR_HTINST);

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpuid);
	if (!(scause & CAUSE_IRQ_FLAG))
		shadow_ctxt->trap = vcpu->arch.guest_trap;
	else
		goto exit;

	if (scause == EXC_SUPERVISOR_SYSCALL) {
		if (handle_pvops(vmid, vcpuid) > 0)
			goto guest;
		else
			goto exit;
	} else if (scause == EXC_INST_GUEST_PAGE_FAULT ||
	           scause == EXC_LOAD_GUEST_PAGE_FAULT ||
		   scause == EXC_STORE_GUEST_PAGE_FAULT)
		__populate_fault_info(vcpu, scause, shadow_ctxt);

exit:
	/* Return to the host kernel and handle the exit */
	return false;

guest:
	/* Re-enter the guest */
	return true;
}

static void __host_hs_restore_state(struct hs_data *hs_data)
{
	csr_write(CSR_HGATP, get_pt_hgatp(hs_data->host_hgatp));
	csr_write(CSR_HEDELEG, HEDELEG_HOST_FLAGS);
	csr_write(CSR_HIDELEG, HIDELEG_HOST_FLAGS);

#ifdef CONFIG_64BIT
	csr_write(CSR_HTIMEDELTA, 0);
#else
	csr_write(CSR_HTIMEDELTA, 0);
	csr_write(CSR_HTIMEDELTAH, 0);
#endif
}

static void kvm_riscv_vcpu_fp_clean(struct kvm_cpu_context *cntx)
{
	cntx->sstatus &= ~SR_FS;
	cntx->sstatus |= SR_FS_CLEAN;
}

static void kvm_riscv_vcpu_guest_fp_save(struct kvm_cpu_context *cntx,
					 unsigned long isa)
{
	if ((cntx->sstatus & SR_FS) == SR_FS_DIRTY) {
		if (riscv_isa_extension_available(&isa, d))
			__kvm_riscv_fp_d_save(cntx);
		else if (riscv_isa_extension_available(&isa, f))
			__kvm_riscv_fp_f_save(cntx);
		kvm_riscv_vcpu_fp_clean(cntx);
	}
}

static void kvm_riscv_vcpu_guest_fp_restore(struct kvm_cpu_context *cntx,
					    unsigned long isa)
{
	if ((cntx->sstatus & SR_FS) != SR_FS_OFF) {
		if (riscv_isa_extension_available(&isa, d))
			__kvm_riscv_fp_d_restore(cntx);
		else if (riscv_isa_extension_available(&isa, f))
			__kvm_riscv_fp_f_restore(cntx);
		kvm_riscv_vcpu_fp_clean(cntx);
	}
}

static void kvm_riscv_vcpu_host_fp_save(struct kvm_cpu_context *cntx)
{
	/* No need to check host sstatus as it can be modified outside */
	if (riscv_isa_extension_available(NULL, d))
		__kvm_riscv_fp_d_save(cntx);
	else if (riscv_isa_extension_available(NULL, f))
		__kvm_riscv_fp_f_save(cntx);
}

static void kvm_riscv_vcpu_host_fp_restore(struct kvm_cpu_context *cntx)
{
	if (riscv_isa_extension_available(NULL, d))
		__kvm_riscv_fp_d_restore(cntx);
	else if (riscv_isa_extension_available(NULL, f))
		__kvm_riscv_fp_f_restore(cntx);
}

/* Switch to the guest with hypsec */
void __kvm_vcpu_run(u32 vmid, int vcpu_id)
{
	unsigned long scause;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_vcpu_csr host_csr;
	struct hs_data *hs_data;
	struct kvm_vcpu *vcpu;
	struct shadow_vcpu_context *prot_ctxt;
	struct hypsec_switch_context switch_ctxt;

	/* check if vm is verified and vcpu is already active. */
	hypsec_set_vcpu_active(vmid, vcpu_id);
	set_per_cpu(vmid, vcpu_id);

	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	prot_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);

	hs_data = kern_hyp_va((void *)&hs_data_start);
	host_ctxt = &vcpu->arch.host_context;
	switch_ctxt.arch = &vcpu->arch;
	switch_ctxt.shadow_ctxt = prot_ctxt;

	__csr_save_state(&host_csr);

	restore_shadow_kvm_regs();

	__activate_traps(vcpu);
	__load_guest_stage2(vmid & 0xff);
	if (vcpu->arch.was_preempted) {
		hypsec_tlb_flush_local_vmid();
		vcpu->arch.was_preempted = false;
	}

	kvm_riscv_vcpu_timer_restore(vcpu);

	__vm_csr_restore_state_opt(prot_ctxt);	
	vcpu->arch.guest_csr.hvip = prot_ctxt->csr.hvip;
	vcpu->arch.guest_csr.hie = prot_ctxt->csr.hie;

	kvm_riscv_vcpu_host_fp_save(&vcpu->arch.host_context);
	kvm_riscv_vcpu_guest_fp_restore(&prot_ctxt->ctxt, vcpu->arch.isa);

	do {
		/* Jump in the fire! */
		__kvm_riscv_switch_to(&switch_ctxt);

		/* And we're baaack! */

		scause = csr_read(CSR_SCAUSE);
	} while (fixup_guest_exit(vcpu, scause, vmid, vcpu_id));

	__vm_csr_save_state_opt(prot_ctxt);

	__host_hs_restore_state(hs_data);

	__csr_restore_state(&host_csr);

	kvm_riscv_vcpu_guest_fp_save(&prot_ctxt->ctxt, vcpu->arch.isa);
	kvm_riscv_vcpu_host_fp_restore(&vcpu->arch.host_context);

	set_shadow_ctxt(vmid, vcpu_id, V_EC, scause);
	save_shadow_kvm_regs();

	set_per_cpu(0, current_hs_thread_info()->cpu);
	hypsec_set_vcpu_state(vmid, vcpu_id, READY);
}
