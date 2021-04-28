// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/hwcap.h>
#include <asm/sbi.h>
#ifdef CONFIG_VERIFIED_KVM
#include <asm/hypsec_virt.h>
#include <asm/hypsec_host.h>
#endif

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
}

#ifdef CONFIG_VERIFIED_KVM
static inline void enter_vs_mode(void)
{
	extern void __kvm_riscv_host_trap(void);
	struct hs_data *hs_data = (void *)hs_data_start;

	csr_write(CSR_VSSTATUS, csr_read(CSR_SSTATUS));
	csr_write(CSR_HIE, csr_read(CSR_SIE) << VSIP_TO_HVIP_SHIFT);
	csr_write(CSR_HVIP, csr_read(CSR_SIP) << VSIP_TO_HVIP_SHIFT);
	csr_write(CSR_VSTVEC, csr_read(CSR_STVEC));
	csr_write(CSR_VSSCRATCH, csr_read(CSR_SSCRATCH));
	csr_write(CSR_VSEPC, csr_read(CSR_SEPC));
	csr_write(CSR_VSCAUSE, csr_read(CSR_SCAUSE));
	csr_write(CSR_VSTVAL, csr_read(CSR_STVAL));
	csr_write(CSR_VSATP, csr_read(CSR_SATP));

	csr_write(CSR_HGATP, HGATP_MODE_OFF);
	csr_write(CSR_HEDELEG, HEDELEG_HOST_FLAGS);
	csr_write(CSR_HIDELEG, HIDELEG_HOST_FLAGS);
	csr_write(CSR_HCOUNTEREN, -1UL);
	csr_set(CSR_HSTATUS, HSTATUS_SPV);
	csr_set(CSR_SSTATUS, SR_SPP | SR_SPIE | SR_FS_INITIAL);
	csr_write(CSR_SIE, -1UL);
	csr_write(CSR_SSCRATCH, &hs_data->thread_info[smp_processor_id()]);
	csr_write(CSR_STVEC, __kvm_riscv_host_trap);
	csr_write(CSR_SATP, PFN_DOWN(__pa(hyp_pg_dir)) | SATP_MODE);
	local_flush_tlb_all();

	__kvm_riscv_hfence_gvma_all();

	__kvm_riscv_host_switch();
}

static void install_hs_runtime(void *discard)
{
	enter_vs_mode();
	kvm_call_core(HVC_ENABLE_S2_TRANS);
}
#endif

int kvm_arch_hardware_setup(void *opaque)
{
#ifdef CONFIG_VERIFIED_KVM
	on_each_cpu(install_hs_runtime, NULL, 1);
	printk("HypSec HS runtime is installed\n");
#endif
	return 0;
}

int kvm_arch_hardware_enable(void)
{
#ifndef CONFIG_VERIFIED_KVM
	unsigned long hideleg, hedeleg;

	hedeleg = 0;
	hedeleg |= (1UL << EXC_INST_MISALIGNED);
	hedeleg |= (1UL << EXC_BREAKPOINT);
	hedeleg |= (1UL << EXC_SYSCALL);
	hedeleg |= (1UL << EXC_INST_PAGE_FAULT);
	hedeleg |= (1UL << EXC_LOAD_PAGE_FAULT);
	hedeleg |= (1UL << EXC_STORE_PAGE_FAULT);
	csr_write(CSR_HEDELEG, hedeleg);

	hideleg = 0;
	hideleg |= (1UL << IRQ_VS_SOFT);
	hideleg |= (1UL << IRQ_VS_TIMER);
	hideleg |= (1UL << IRQ_VS_EXT);
	csr_write(CSR_HIDELEG, hideleg);

	csr_write(CSR_HCOUNTEREN, -1UL);

	csr_write(CSR_HVIP, 0);
#endif

	return 0;
}

void kvm_arch_hardware_disable(void)
{
	csr_write(CSR_HEDELEG, 0);
	csr_write(CSR_HIDELEG, 0);
}

int kvm_arch_init(void *opaque)
{
#ifndef CONFIG_VERIFIED_KVM
	const char *str;
#else
	int cpu;
#endif

	if (!riscv_isa_extension_available(NULL, h)) {
		kvm_info("hypervisor extension not available\n");
		return -ENODEV;
	}

	if (sbi_spec_is_0_1()) {
		kvm_info("require SBI v0.2 or higher\n");
		return -ENODEV;
	}

	if (sbi_probe_extension(SBI_EXT_RFENCE) <= 0) {
		kvm_info("require SBI RFENCE extension\n");
		return -ENODEV;
	}

#ifndef CONFIG_VERIFIED_KVM
	kvm_riscv_stage2_mode_detect();

	kvm_riscv_stage2_vmid_detect();

	kvm_info("hypervisor extension available\n");

	switch (kvm_riscv_stage2_mode()) {
	case HGATP_MODE_SV32X4:
		str = "Sv32x4";
		break;
	case HGATP_MODE_SV39X4:
		str = "Sv39x4";
		break;
	case HGATP_MODE_SV48X4:
		str = "Sv48x4";
		break;
	default:
		return -ENODEV;
	}
	kvm_info("using %s G-stage page table format\n", str);

	kvm_info("VMID %ld bits available\n", kvm_riscv_stage2_vmid_bits());
#else
	init_hs_data_page();
	setup_vm_hyp();

	/*
	 * Allocate stack pages for Hypervisor-mode
	 */
	for_each_possible_cpu(cpu) {
		unsigned long stack_page;
		struct hs_data *hs_data = (void *)hs_data_start;

		stack_page = (unsigned long)phys_to_virt(host_alloc_stage2_page(PAGE_SIZE * 2));
		if (!stack_page)
			return -ENOMEM;

		
		hs_data->thread_info[cpu].hs_sp = stack_page;
		hs_data->thread_info[cpu].cpu = cpu;
	}

	init_hypsec_io();
#endif

	return 0;
}

void kvm_arch_exit(void)
{
}

static int riscv_kvm_init(void)
{
	return kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);
}
module_init(riscv_kvm_init);
