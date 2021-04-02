#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>

	.text
	.altmacro
	.option norelax

ENTRY(__kvm_riscv_host_trap)
	/* Save Host GPRs (except T0-T6) */
	move t0, sp
	addi sp, sp, -(KVM_CPU_CONTEXT_SIZE_ON_STACK)
	REG_S	ra, (KVM_ARCH_HOST_RA)(sp)
	REG_S	gp, (KVM_CPU_CONTEXT_GP)(sp)
	REG_S	tp, (KVM_CPU_CONTEXT_TP)(sp)
	REG_S	s0, (KVM_CPU_CONTEXT_S0)(sp)
	REG_S	s1, (KVM_CPU_CONTEXT_S1)(sp)
	REG_S	a0, (KVM_CPU_CONTEXT_A0)(sp)
	REG_S	a1, (KVM_CPU_CONTEXT_A1)(sp)
	REG_S	a2, (KVM_CPU_CONTEXT_A2)(sp)
	REG_S	a3, (KVM_CPU_CONTEXT_A3)(sp)
	REG_S	a4, (KVM_CPU_CONTEXT_A4)(sp)
	REG_S	a5, (KVM_CPU_CONTEXT_A5)(sp)
	REG_S	a6, (KVM_CPU_CONTEXT_A6)(sp)
	REG_S	a7, (KVM_CPU_CONTEXT_A7)(sp)
	REG_S	s2, (KVM_CPU_CONTEXT_S2)(sp)
	REG_S	s3, (KVM_CPU_CONTEXT_S3)(sp)
	REG_S	s4, (KVM_CPU_CONTEXT_S4)(sp)
	REG_S	s5, (KVM_CPU_CONTEXT_S5)(sp)
	REG_S	s6, (KVM_CPU_CONTEXT_S6)(sp)
	REG_S	s7, (KVM_CPU_CONTEXT_S7)(sp)
	REG_S	s8, (KVM_CPU_CONTEXT_S8)(sp)
	REG_S	s9, (KVM_CPU_CONTEXT_S9)(sp)
	REG_S	s10, (KVM_CPU_CONTEXT_S10)(sp)
	REG_S	s11, (KVM_CPU_CONTEXT_S11)(sp)
	REG_S	t0, (KVM_ARCH_HOST_SP)(sp)

	/* Handle the trap */
	move a0, sp /* kvm_cpu_context */
	la a1, handle_host_hs_trap
	jr a1

	/* Restore Host GPRs (except T0-T6) */
	REG_L	ra, (KVM_CPU_CONTEXT_RA)(sp)
	REG_L	gp, (KVM_CPU_CONTEXT_GP)(sp)
	REG_L	tp, (KVM_CPU_CONTEXT_TP)(sp)
	REG_L	s0, (KVM_CPU_CONTEXT_S0)(sp)
	REG_L	s1, (KVM_CPU_CONTEXT_S1)(sp)
	REG_L	a0, (KVM_CPU_CONTEXT_A0)(sp)
	REG_L	a1, (KVM_CPU_CONTEXT_A1)(sp)
	REG_L	a2, (KVM_CPU_CONTEXT_A2)(sp)
	REG_L	a3, (KVM_CPU_CONTEXT_A3)(sp)
	REG_L	a4, (KVM_CPU_CONTEXT_A4)(sp)
	REG_L	a5, (KVM_CPU_CONTEXT_A5)(sp)
	REG_L	a6, (KVM_CPU_CONTEXT_A6)(sp)
	REG_L	a7, (KVM_CPU_CONTEXT_A7)(sp)
	REG_L	s2, (KVM_CPU_CONTEXT_S2)(sp)
	REG_L	s3, (KVM_CPU_CONTEXT_S3)(sp)
	REG_L	s4, (KVM_CPU_CONTEXT_S4)(sp)
	REG_L	s5, (KVM_CPU_CONTEXT_S5)(sp)
	REG_L	s6, (KVM_CPU_CONTEXT_S6)(sp)
	REG_L	s7, (KVM_CPU_CONTEXT_S7)(sp)
	REG_L	s8, (KVM_CPU_CONTEXT_S8)(sp)
	REG_L	s9, (KVM_CPU_CONTEXT_S9)(sp)
	REG_L	s10, (KVM_ARCH_HOST_S10)(sp)
	REG_L	s11, (KVM_ARCH_HOST_S11)(sp)
	REG_L	sp, (KVM_CPU_CONTEXT_SP)(sp)

	/* Return to VS mode */
	sret
ENDPROC(__kvm_riscv_host_trap)

ENTRY(__kvm_riscv_host_switch)
	/* Set SEPC to return path */
	la	t4, __kvm_switch_return
	csrw	CSR_SEPC, t4

	/* Switch mode */
	sret

	/* We're back */
	.align 2
__kvm_switch_return:
	/* Return to C code */
	ret
ENDPROC(__kvm_riscv_host_switch)
