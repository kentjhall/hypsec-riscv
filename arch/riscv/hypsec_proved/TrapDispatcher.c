#include <linux/types.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/hypsec_virt.h>
#include <asm/hypsec_pgtable.h>
#include <asm/hypsec_asm.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include "hypsec.h"

/*
 * TrapDispatcher 
 */

/*
 * Since HS page tables were allocated in HS, here we need to protect
 * them by setting the ownership of the pages to HYPSEC_VMID. This allows
 * the core to reject any following accesses from the host.
 */
static void protect_hs_mem(void)
{
#if 0
	unsigned long addr, end, index;
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));

	/* Protect stage2 data and page pool. */
	addr = hs_data->core_start;
	end =  hs_data->core_end;
	do {
		index = get_s2_page_index(addr);
		set_s2_page_vmid(index, COREVISOR);
		addr += PAGE_SIZE;
	} while (addr < end);
#endif
}

void hvc_enable_s2_trans(void)
{
	struct hs_data *hs_data;

	acquire_lock_core();
	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));

	if (!hs_data->installed) {
		protect_hs_mem();
		hs_data->installed = true;
	}

#if 0 // TEMPORARY
	csr_write(CSR_HGATP, hs_data->host_hgatp);
#endif
	__kvm_flush_vm_context();

	release_lock_core();
}

static void handle_host_hvc(struct kvm_cpu_context *hctxt)
{
	u32 ret;
	u64 callno, arg1, arg2, arg3, arg4, arg5, ret64;

	//vmid = get_cur_vmid();
	//vcpuid = get_cur_vcpuid();
#if 0 // TEMPORARY
	set_per_cpu_host_regs((u64)hr);
#endif
	arg1 = hctxt->a1;
	arg2 = hctxt->a2;
	arg3 = hctxt->a3;
	arg4 = hctxt->a4;
	arg5 = hctxt->a5;

	ret = 0;
	ret64 = 0;
	callno = hctxt->a0;

	if (callno == HVC_ENABLE_S2_TRANS)
	{
		hvc_enable_s2_trans();
	}
#if 0 // TEMPORARY
	else if (callno == HVC_VCPU_RUN)
	{
		ret = (u64)__kvm_vcpu_run_nvhe((u32)arg1, (int)arg2);
		set_host_regs(0, ret);
	}
	else if (callno == HVC_TIMER_SET_CNTVOFF)
	{
		__kvm_timer_set_cntvoff((u32)arg1, (u32)arg2);
	}
	else if (callno == HVC_CLEAR_VM_S2_RANGE)
	{
		hs_clear_vm_stage2_range((u32)arg1, arg2, arg3);
	}
	else if (callno == HVC_SET_BOOT_INFO)
	{
		ret = set_boot_info((u32)arg1, arg2, arg3);
		set_host_regs(0, ret);
	}
	else if (callno == HVC_REMAP_VM_IMAGE)
	{
		remap_vm_image((u32)arg1, arg2, (u32)arg3);
	}
	else if (callno == HVC_VERIFY_VM_IMAGES)
	{
		verify_and_load_images((u32)arg1);
		set_host_regs(0, 1);
	}
	else if (callno == HVC_SMMU_FREE_PGD)
	{
		__hs_free_smmu_pgd((u32)arg1, (u32)arg2);
	}
	else if (callno == HVC_SMMU_ALLOC_PGD)
	{
		__hs_alloc_smmu_pgd((u32)arg1, (u32)arg2, (u32)arg3);
	}
	else if (callno == HVC_SMMU_LPAE_MAP)
	{
		__hs_arm_lpae_map(arg1, arg2, arg3, (u32)arg4, (u32)arg5);
	}
	else if (callno == HVC_SMMU_LPAE_IOVA_TO_PHYS)
	{
		ret64 = __hs_arm_lpae_iova_to_phys(arg1, (u32)arg2, (u32)arg3);
		set_host_regs(0, ret64);
	}
	else if (callno == HVC_SMMU_CLEAR)
	{
		__hs_arm_lpae_clear(arg1, (u32)arg2, (u32)arg3);
	}
	else if (callno == HVC_ENCRYPT_BUF)
	{
		__hs_encrypt_buf((u32)arg1, arg2, arg3);
	}
	else if (callno == HVC_DECRYPT_BUF)
	{
		//TODO: FIXME
		__hs_decrypt_buf((u32)arg1, (void*)arg2, (uint32_t)arg3);
	}
	else if (callno == HVC_SAVE_CRYPT_VCPU)
	{
		__save_encrypted_vcpu((u32)arg1, (u32)arg2);
	}
	else if (callno == HVC_LOAD_CRYPT_VCPU)
	{
		__load_encrypted_vcpu((u32)arg1, (u32)arg2);
	}
	else if (callno == HVC_REGISTER_KVM)
	{
		ret = register_kvm();
		set_host_regs(0, ret);
	}
	else if (callno == HVC_REGISTER_VCPU)
	{
		register_vcpu((u32)arg1, (u32)arg2);
		set_host_regs(0, ret);
	}
	else if (callno == HVC_PHYS_ADDR_IOREMAP)
	{
		hs_kvm_phys_addr_ioremap((u32)arg1, arg2, arg3, arg4);
	}
	else
	{
		print_string("\rno support hvc:\n");
		printhex_ul(callno);
		v_panic();
	}
#endif
}

void handle_host_hs_trap(struct kvm_cpu_context *hctxt)
{
	unsigned long scause = csr_read(CSR_SCAUSE);
	switch (scause) {
	case EXC_SUPERVISOR_SYSCALL:
	{
		if (hctxt->a7 != SBI_EXT_HYPSEC_HVC) {
			// passthrough to M mode
			struct sbiret sr = sbi_ecall(hctxt->a7, hctxt->a6,
				                     hctxt->a0, hctxt->a1, hctxt->a2,
				                     hctxt->a3, hctxt->a4, hctxt->a5);
			hctxt->a0 = sr.error;
			hctxt->a1 = sr.value;
		} else
			handle_host_hvc(hctxt);
		csr_write(CSR_SEPC, csr_read(CSR_SEPC) + 4);
		break;
	}
	default:
		pr_info("Unknown scause: %ld\n", scause);
	}
	pr_alert("trap handled, going back to: %lx\n", csr_read(CSR_SEPC));
}
