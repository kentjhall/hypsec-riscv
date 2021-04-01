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
#include <asm/sbi.h>
#include <linux/serial_reg.h>

#include "hypsec.h"

/*
 * TrapDispatcher 
 */

/*
 * Since EL2 page tables were allocated in EL2, here we need to protect
 * them by setting the ownership of the pages to HYPSEC_VMID. This allows
 * the core to reject any following accesses from the host.
 */
static void protect_el2_mem(void)
{
#if 0
	unsigned long addr, end, index;
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	/* Protect stage2 data and page pool. */
	addr = el2_data->core_start;
	end =  el2_data->core_end;
	do {
		index = get_s2_page_index(addr);
		set_s2_page_vmid(index, COREVISOR);
		addr += PAGE_SIZE;
	} while (addr < end);
#endif
}

void hvc_enable_s2_trans(void)
{
	struct el2_data *el2_data;
	struct cpumask hmask;
	extern void (*__kvm_riscv_host_switch)(void);

	acquire_lock_core();
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	if (!el2_data->installed) {
		protect_el2_mem();
		el2_data->installed = true;
	}

#if 0
	csr_write(CSR_HGATP, el2_data->host_hgatp);
#endif
	csr_write(CSR_HGATP, HGATP_MODE_OFF); // TEMPORARY
	csr_write(CSR_HEDELEG, HEDELEG_HOST_FLAGS);
	csr_write(CSR_HIDELEG, HIDELEG_HOST_FLAGS);
	csr_write(CSR_HCOUNTEREN, -1UL);
	csr_write(CSR_HVIP, 0);
	csr_write(CSR_HSTATUS, HSTATUS_SPVP | HSTATUS_SPV);
	csr_write(CSR_STVEC, __kvm_riscv_host_switch);
	csr_write(CSR_SEPC, __builtin_return_address(0));

	riscv_cpuid_to_hartid_mask(cpu_online_mask, &hmask);
	sbi_remote_hfence_gvma(cpumask_bits(&hmask), 0, 0);

	release_lock_core();
	__asm__("sret");
}

void handle_host_hvc(struct s2_host_regs *hr)
{
#if 0
	u32 ret;
	u64 callno, arg1, arg2, arg3, arg4, arg5, ret64;

	//vmid = get_cur_vmid();
	//vcpuid = get_cur_vcpuid();
	set_per_cpu_host_regs((u64)hr);
	arg1 = hr->regs[1];
	arg2 = hr->regs[2];
	arg3 = hr->regs[3];
	arg4 = hr->regs[4];
	arg5 = hr->regs[5];

	ret = 0;
	ret64 = 0;
	callno = hr->regs[0];

	if (callno == HVC_VCPU_RUN)
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
		el2_clear_vm_stage2_range((u32)arg1, arg2, arg3);
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
		__el2_free_smmu_pgd((u32)arg1, (u32)arg2);
	}
	else if (callno == HVC_SMMU_ALLOC_PGD)
	{
		__el2_alloc_smmu_pgd((u32)arg1, (u32)arg2, (u32)arg3);
	}
	else if (callno == HVC_SMMU_LPAE_MAP)
	{
		__el2_arm_lpae_map(arg1, arg2, arg3, (u32)arg4, (u32)arg5);
	}
	else if (callno == HVC_SMMU_LPAE_IOVA_TO_PHYS)
	{
		ret64 = __el2_arm_lpae_iova_to_phys(arg1, (u32)arg2, (u32)arg3);
		set_host_regs(0, ret64);
	}
	else if (callno == HVC_SMMU_CLEAR)
	{
		__el2_arm_lpae_clear(arg1, (u32)arg2, (u32)arg3);
	}
	else if (callno == HVC_ENCRYPT_BUF)
	{
		__el2_encrypt_buf((u32)arg1, arg2, arg3);
	}
	else if (callno == HVC_DECRYPT_BUF)
	{
		//TODO: FIXME
		__el2_decrypt_buf((u32)arg1, (void*)arg2, (uint32_t)arg3);
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
		el2_kvm_phys_addr_ioremap((u32)arg1, arg2, arg3, arg4);
	}
	else
	{
		print_string("\rno support hvc:\n");
		printhex_ul(callno);
		v_panic();
	}
#endif
}

void handle_host_hs_trap(struct kvm_cpu_context *host_context)
{
	/* TODO */
}
