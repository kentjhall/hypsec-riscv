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

	/* csr_write(CSR_HGATP, hs_data->host_hgatp); */
	__kvm_riscv_hfence_gvma_all();

	release_lock_core();
}

static void handle_host_hvc(struct kvm_cpu_context *hr)
{
	u32 ret;
	u64 callno, arg1, arg2, arg3, arg4, arg5, ret64;

	//vmid = get_cur_vmid();
	//vcpuid = get_cur_vcpuid();
	set_per_cpu_host_regs((u64)hr);
	arg1 = hr->a1;
	arg2 = hr->a2;
	arg3 = hr->a3;
	arg4 = hr->a4;
	arg5 = hr->a5;

	ret = 0;
	ret64 = 0;
	callno = hr->a0;

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

void handle_host_hs_trap(struct kvm_cpu_context *hregs)
{
	unsigned long scause = csr_read(CSR_SCAUSE);
	unsigned long vsatp = csr_read(CSR_VSATP);

	if (csr_read(CSR_SATP) != vsatp) {
		csr_write(CSR_SATP, vsatp);
		local_flush_tlb_all();
	}

	if (scause & CAUSE_IRQ_FLAG) {
		unsigned long cause = scause & ~CAUSE_IRQ_FLAG;

		if (cause == IRQ_S_TIMER) {
			csr_clear(CSR_SIE, IE_TIE);
			csr_set(CSR_HVIP, (1UL << IRQ_S_TIMER) << VSIP_TO_HVIP_SHIFT);
		}
		else if (cause == IRQ_S_SOFT) {
			csr_clear(CSR_SIP, 1UL << IRQ_S_SOFT);
			csr_set(CSR_HVIP, (1UL << IRQ_S_SOFT) << VSIP_TO_HVIP_SHIFT);
		}
		else {
			char *c;
			for (c = "CANT HANDLE EXTERNAL INTERRUPTS; just gonna pend forever now..."; *c; ++c)
				sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, *c, 0, 0, 0, 0, 0);
			sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, '\n', 0, 0, 0, 0, 0);
			csr_clear(CSR_SIE, 1UL << IRQ_S_EXT);
		}

		return;
	}

	switch (scause) {
	case EXC_SUPERVISOR_SYSCALL:
	{
		if (hregs->a7 != SBI_EXT_HYPSEC_HVC) {
			// passthrough to M mode
			struct sbiret sr;
			if (hregs->a7 == SBI_EXT_RFENCE) {
				if (hregs->a6 == SBI_EXT_RFENCE_REMOTE_SFENCE_VMA)
					hregs->a6 = SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA;
				else if (hregs->a6 == SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID)
					hregs->a6 = SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID;
			}
			else if (hregs->a7 == SBI_EXT_TIME) {
				csr_clear(CSR_HVIP, 1UL << IRQ_VS_TIMER);
				csr_set(CSR_SIE, IE_TIE);
			}
			sr = sbi_ecall(hregs->a7, hregs->a6,
				       hregs->a0, hregs->a1, hregs->a2,
				       hregs->a3, hregs->a4, hregs->a5);
			hregs->a0 = sr.error;
			hregs->a1 = sr.value;
		} else
			handle_host_hvc(hregs);

		csr_write(CSR_SEPC, csr_read(CSR_SEPC) + 4);
		break;
	}
	case EXC_INST_GUEST_PAGE_FAULT:
	case EXC_LOAD_GUEST_PAGE_FAULT:
	case EXC_STORE_GUEST_PAGE_FAULT:
		handle_host_stage2_fault((struct s2_host_regs *)hregs);
		break;
	case EXC_VIRTUAL_INST_FAULT:
		csr_write(CSR_SEPC, csr_read(CSR_SEPC) + 4);
		break;
	default:
		pr_info("Unknown scause: %ld, hedeleg: %lx, spv: %lx, spp: %lx, sepc: %lx\n", scause, csr_read(CSR_HEDELEG), csr_read(CSR_HSTATUS) & HSTATUS_SPV, csr_read(CSR_SSTATUS) & SR_SPP, csr_read(CSR_SEPC));
		break;
	}
}
