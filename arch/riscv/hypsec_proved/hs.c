#include <linux/types.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/hypsec_virt.h>
#include <asm/hypsec_pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include "hypsec.h"

/*static void self_test(void)
{
	int vmid, i = 0;

	print_string("\rregister kvm\n");
	vmid = register_kvm();
	do {
		print_string("\rregister vcpu\n");
		printhex_ul((unsigned long)i);
		register_vcpu(vmid, i++);
	} while (i < 4);
}*/

//added by shih-wei
void hypsec_set_vcpu_active(u32 vmid, int vcpu_id)
{
	u32 state, first_run, vcpu_state;

	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	if (state != VERIFIED)
	{
		v_panic();
	}
	else
	{
		first_run = get_vcpu_first_run(vmid, vcpu_id);
		if (first_run == 0U)
		{
			set_vcpu_first_run(vmid, vcpu_id, 1U);
		}

		vcpu_state = get_vcpu_state(vmid, vcpu_id);
		if (vcpu_state == READY)
		{
			set_vcpu_state(vmid, vcpu_id, ACTIVE);
		}
		else
		{
			v_panic();
		}
	}
	release_lock_vm(vmid);
}

void hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state)
{
	acquire_lock_vm(vmid);
	set_vcpu_state(vmid, vcpu_id, state);
	release_lock_vm(vmid);
}

struct kvm_vcpu* hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id)
{
	struct kvm_vcpu *vcpu = NULL;
	int offset;
	struct shared_data *shared_data;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	offset = VCPU_IDX(vmid, vcpu_id);
	vcpu = &shared_data->vcpu_pool[offset];
	if (!vcpu)
		__hyp_panic();
	else
		return vcpu;
}

struct kvm* hypsec_vmid_to_kvm(u32 vmid)
{
	struct kvm *kvm = NULL;
	struct shared_data *shared_data;

	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	kvm = &shared_data->kvm_pool[vmid];
	if (!kvm)
		__hyp_panic();
	else
		return kvm;
}

struct shadow_vcpu_context* hypsec_vcpu_id_to_shadow_ctxt(
	u32 vmid, int vcpu_id)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	int index;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	index = VCPU_IDX(vmid, vcpu_id);
	shadow_ctxt = &hs_data->shadow_vcpu_ctxt[index];
	if (!shadow_ctxt)
		__hyp_panic();
	else
		return shadow_ctxt;
}

static u64 stage2_get_exception_vector(void)
{
	return csr_read(CSR_VSTVEC);
}

/* Currently, we do not handle lower level fault from 32bit host */
void stage2_inject_el1_fault(unsigned long addr)
{
	unsigned long vsstatus = csr_read(CSR_VSSTATUS);

	csr_write(CSR_VSEPC, csr_read(CSR_SEPC));
	csr_write(CSR_SEPC, stage2_get_exception_vector());

	/* Change Guest SSTATUS.SPP bit */
	vsstatus &= ~SR_SPP;
	if (csr_read(CSR_SSTATUS) & SR_SPP)
		vsstatus |= SR_SPP;

	/* Change Guest SSTATUS.SPIE bit */
	vsstatus &= ~SR_SPIE;
	if (vsstatus & SR_SIE)
		vsstatus |= SR_SPIE;

	/* Clear Guest SSTATUS.SIE bit */
	vsstatus &= ~SR_SIE;

	csr_write(CSR_VSTVAL, addr);
	csr_write(CSR_VSSTATUS, vsstatus);

	csr_write(CSR_VSCAUSE, csr_read(CSR_SCAUSE));
}

void reject_invalid_mem_access(phys_addr_t addr)
{
	printk("invalid access of guest memory\n\r");
	printk("pc: %lx\n", csr_read(CSR_SEPC));
	printk("pa: %llx\n", addr);
	stage2_inject_el1_fault(addr);
}
