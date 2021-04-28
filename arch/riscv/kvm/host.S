#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>

	.text
	.altmacro
	.option norelax

	.align 2
ENTRY(__kvm_riscv_host_trap)
	/* Swap host for HS tp */
	csrrw tp, CSR_SCRATCH, tp

	/* Save host sp, restore HS sp */
	REG_S sp, HS_THREAD_INFO_PREV_SP(tp)
	REG_L sp, HS_THREAD_INFO_HS_SP(tp)

	/* Save Host GPRs */
	addi sp, sp, -(KVM_CPU_CONTEXT_SIZE_ON_STACK)
	REG_S	ra, (KVM_CPU_CONTEXT_RA)(sp)
	REG_S	gp, (KVM_CPU_CONTEXT_GP)(sp)
	REG_S	t0, (KVM_CPU_CONTEXT_T0)(sp)
	REG_S	t1, (KVM_CPU_CONTEXT_T1)(sp)
	REG_S	t2, (KVM_CPU_CONTEXT_T2)(sp)
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
	REG_S	t3, (KVM_CPU_CONTEXT_T3)(sp)
	REG_S	t4, (KVM_CPU_CONTEXT_T4)(sp)
	REG_S	t5, (KVM_CPU_CONTEXT_T5)(sp)
	REG_S	t6, (KVM_CPU_CONTEXT_T6)(sp)

	/* Handle the trap */
	move a0, sp /* kvm_cpu_context */
	jal handle_host_hs_trap

	/* Restore Host GPRs */
	REG_L	ra, (KVM_CPU_CONTEXT_RA)(sp)
	REG_L	gp, (KVM_CPU_CONTEXT_GP)(sp)
	REG_L	t0, (KVM_CPU_CONTEXT_T0)(sp)
	REG_L	t1, (KVM_CPU_CONTEXT_T1)(sp)
	REG_L	t2, (KVM_CPU_CONTEXT_T2)(sp)
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
	REG_L	s10, (KVM_CPU_CONTEXT_S10)(sp)
	REG_L	s11, (KVM_CPU_CONTEXT_S11)(sp)
	REG_L	t3, (KVM_CPU_CONTEXT_T3)(sp)
	REG_L	t4, (KVM_CPU_CONTEXT_T4)(sp)
	REG_L	t5, (KVM_CPU_CONTEXT_T5)(sp)
	REG_L	t6, (KVM_CPU_CONTEXT_T6)(sp)
	addi sp, sp, KVM_CPU_CONTEXT_SIZE_ON_STACK

	/* Restore host sp */
	REG_L sp, HS_THREAD_INFO_PREV_SP(tp)

	/* Swap HS for host tp */
	csrrw tp, CSR_SCRATCH, tp

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
__kvm_switch_return:
	/* Return to C code */
	ret
ENDPROC(__kvm_riscv_host_switch)
