#ifndef __RISCV_STAGE2_ASM__
#define __RISCV_STAGE2_ASM__

#include <asm/sbi.h>
#include <asm/smp.h>

static inline void __kvm_flush_vm_context(void)
{
	struct cpumask hmask;
	riscv_cpuid_to_hartid_mask(cpu_online_mask, &hmask);
	sbi_remote_hfence_gvma(cpumask_bits(&hmask), 0, 0);
}

#endif /* __RISCV_STAGE2_ASM__ */
