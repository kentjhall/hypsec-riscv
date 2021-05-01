#ifndef __RISCV_VERIFIED_MMIO__
#define __RISCV_VERIFIED_MMIO__

#define INSN_OPCODE_MASK	0x007c
#define INSN_OPCODE_SHIFT	2
#define INSN_OPCODE_SYSTEM	28

#define INSN_MASK_WFI		0xffffff00
#define INSN_MATCH_WFI		0x10500000

#define INSN_MATCH_LB		0x3
#define INSN_MASK_LB		0x707f
#define INSN_MATCH_LH		0x1003
#define INSN_MASK_LH		0x707f
#define INSN_MATCH_LW		0x2003
#define INSN_MASK_LW		0x707f
#define INSN_MATCH_LD		0x3003
#define INSN_MASK_LD		0x707f
#define INSN_MATCH_LBU		0x4003
#define INSN_MASK_LBU		0x707f
#define INSN_MATCH_LHU		0x5003
#define INSN_MASK_LHU		0x707f
#define INSN_MATCH_LWU		0x6003
#define INSN_MASK_LWU		0x707f
#define INSN_MATCH_SB		0x23
#define INSN_MASK_SB		0x707f
#define INSN_MATCH_SH		0x1023
#define INSN_MASK_SH		0x707f
#define INSN_MATCH_SW		0x2023
#define INSN_MASK_SW		0x707f
#define INSN_MATCH_SD		0x3023
#define INSN_MASK_SD		0x707f

#define INSN_MATCH_C_LD		0x6000
#define INSN_MASK_C_LD		0xe003
#define INSN_MATCH_C_SD		0xe000
#define INSN_MASK_C_SD		0xe003
#define INSN_MATCH_C_LW		0x4000
#define INSN_MASK_C_LW		0xe003
#define INSN_MATCH_C_SW		0xc000
#define INSN_MASK_C_SW		0xe003
#define INSN_MATCH_C_LDSP	0x6002
#define INSN_MASK_C_LDSP	0xe003
#define INSN_MATCH_C_SDSP	0xe002
#define INSN_MASK_C_SDSP	0xe003
#define INSN_MATCH_C_LWSP	0x4002
#define INSN_MASK_C_LWSP	0xe003
#define INSN_MATCH_C_SWSP	0xc002
#define INSN_MASK_C_SWSP	0xe003

#define INSN_16BIT_MASK		0x3

#define INSN_IS_16BIT(insn)	(((insn) & INSN_16BIT_MASK) != INSN_16BIT_MASK)

#define INSN_LEN(insn)		(INSN_IS_16BIT(insn) ? 2 : 4)

#ifdef CONFIG_64BIT
#define LOG_REGBYTES		3
#else
#define LOG_REGBYTES		2
#endif
#define REGBYTES		(1 << LOG_REGBYTES)

#define SH_RD			7
#define SH_RS1			15
#define SH_RS2			20
#define SH_RS2C			2

#define RV_X(x, s, n)		(((x) >> (s)) & ((1 << (n)) - 1))
#define RVC_LW_IMM(x)		((RV_X(x, 6, 1) << 2) | \
				 (RV_X(x, 10, 3) << 3) | \
				 (RV_X(x, 5, 1) << 6))
#define RVC_LD_IMM(x)		((RV_X(x, 10, 3) << 3) | \
				 (RV_X(x, 5, 2) << 6))
#define RVC_LWSP_IMM(x)		((RV_X(x, 4, 3) << 2) | \
				 (RV_X(x, 12, 1) << 5) | \
				 (RV_X(x, 2, 2) << 6))
#define RVC_LDSP_IMM(x)		((RV_X(x, 5, 2) << 3) | \
				 (RV_X(x, 12, 1) << 5) | \
				 (RV_X(x, 2, 3) << 6))
#define RVC_SWSP_IMM(x)		((RV_X(x, 9, 4) << 2) | \
				 (RV_X(x, 7, 2) << 6))
#define RVC_SDSP_IMM(x)		((RV_X(x, 10, 3) << 3) | \
				 (RV_X(x, 7, 3) << 6))
#define RVC_RS1S(insn)		(8 + RV_X(insn, SH_RD, 3))
#define RVC_RS2S(insn)		(8 + RV_X(insn, SH_RS2C, 3))
#define RVC_RS2(insn)		RV_X(insn, SH_RS2C, 5)

#define SHIFT_RIGHT(x, y)		\
	((y) < 0 ? ((x) << -(y)) : ((x) >> (y)))

#define REG_MASK			\
	((1 << (5 + LOG_REGBYTES)) - (1 << LOG_REGBYTES))

#define REG_OFFSET(insn, pos)		\
	(SHIFT_RIGHT((insn), (pos) - LOG_REGBYTES) & REG_MASK)

#define REG_PTR(insn, pos, regs)	\
	(ulong *)((ulong)(regs) + REG_OFFSET(insn, pos))

#define GET_RM(insn)		(((insn) >> 12) & 7)

#define GET_RS1(insn, regs)	(*REG_PTR(insn, SH_RS1, regs))
#define GET_RS2(insn, regs)	(*REG_PTR(insn, SH_RS2, regs))
#define GET_RS1S(insn, regs)	(*REG_PTR(RVC_RS1S(insn), 0, regs))
#define GET_RS2S(insn, regs)	(*REG_PTR(RVC_RS2S(insn), 0, regs))
#define GET_RS2C(insn, regs)	(*REG_PTR(insn, SH_RS2C, regs))
#define GET_SP(regs)		(*REG_PTR(2, 0, regs))
#define SET_RD(insn, regs, val)	(*REG_PTR(insn, SH_RD, regs) = (val))
#define IMM_I(insn)		((s32)(insn) >> 20)
#define IMM_S(insn)		(((s32)(insn) >> 25 << 5) | \
				 (s32)(((insn) >> 7) & 0x1f))
#define MASK_FUNCT3		0x7000

static inline unsigned long unpriv_read(bool read_insn, unsigned long vaddr,
					struct kvm_cpu_trap *trap)
{
	register unsigned long taddr asm("a0") = (unsigned long)trap;
	register unsigned long ttmp asm("a1");
	register unsigned long val asm("t0");
	register unsigned long tmp asm("t1");
	register unsigned long addr asm("t2") = vaddr;

	if (read_insn) {
		/*
		 * HLVX.HU instruction
		 * 0110010 00011 rs1 100 rd 1110011
		 */
		asm volatile ("\n"
			".option push\n"
			".option norvc\n"
			"add %[ttmp], %[taddr], 0\n"
			/*
			 * HLVX.HU %[val], (%[addr])
			 * HLVX.HU t0, (t2)
			 * 0110010 00011 00111 100 00101 1110011
			 */
			".word 0x6433c2f3\n"
			"andi %[tmp], %[val], 3\n"
			"addi %[tmp], %[tmp], -3\n"
			"bne %[tmp], zero, 2f\n"
			"addi %[addr], %[addr], 2\n"
			/*
			 * HLVX.HU %[tmp], (%[addr])
			 * HLVX.HU t1, (t2)
			 * 0110010 00011 00111 100 00110 1110011
			 */
			".word 0x6433c373\n"
			"sll %[tmp], %[tmp], 16\n"
			"add %[val], %[val], %[tmp]\n"
			"2:\n"
			".option pop"
		: [val] "=&r" (val), [tmp] "=&r" (tmp),
		  [taddr] "+&r" (taddr), [ttmp] "+&r" (ttmp),
		  [addr] "+&r" (addr) : : "memory");

		if (trap->scause == EXC_LOAD_PAGE_FAULT)
			trap->scause = EXC_INST_PAGE_FAULT;
	} else {
		/*
		 * HLV.D instruction
		 * 0110110 00000 rs1 100 rd 1110011
		 *
		 * HLV.W instruction
		 * 0110100 00000 rs1 100 rd 1110011
		 */
		asm volatile ("\n"
			".option push\n"
			".option norvc\n"
			"add %[ttmp], %[taddr], 0\n"
#ifdef CONFIG_64BIT
			/*
			 * HLV.D %[val], (%[addr])
			 * HLV.D t0, (t2)
			 * 0110110 00000 00111 100 00101 1110011
			 */
			".word 0x6c03c2f3\n"
#else
			/*
			 * HLV.W %[val], (%[addr])
			 * HLV.W t0, (t2)
			 * 0110100 00000 00111 100 00101 1110011
			 */
			".word 0x6803c2f3\n"
#endif
			".option pop"
		: [val] "=&r" (val),
		  [taddr] "+&r" (taddr), [ttmp] "+&r" (ttmp)
		: [addr] "r" (addr) : "memory");
	}

	return val;
}

static inline unsigned long vm_read(u32 vmid, u32 vcpuid,
                                    bool read_insn, unsigned long vaddr)
{
	unsigned long val;
	unsigned long old_stvec, old_hstatus;
	struct kvm_vcpu *vcpu;

	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpuid);
	old_hstatus = csr_swap(CSR_HSTATUS, get_int_hstatus(vmid, vcpuid));
	old_stvec = csr_swap(CSR_STVEC, (ulong)&__kvm_riscv_unpriv_trap);

	val = unpriv_read(read_insn, vaddr, &vcpu->arch.unpriv_read_trap);

	csr_write(CSR_STVEC, old_stvec);
	csr_write(CSR_HSTATUS, old_hstatus);

	set_int_unpriv_read_val(vmid, vcpuid, val);

	if (vcpu->arch.unpriv_read_trap.scause)
		return -1;
	return val;
}

#define vm_read_insn(vmid, vcpuid) \
	vm_read(vmid, vcpuid, true, get_shadow_ctxt(vmid, vcpuid, V_PC))

static inline int insn_decode_rd(unsigned long insn, bool is_write)
{
	int rd = REG_OFFSET(insn, SH_RS2);

	if (is_write) {
		if ((insn & INSN_MASK_SW) == INSN_MATCH_SW) {
			;
		} else if ((insn & INSN_MASK_SB) == INSN_MATCH_SB) {
			;
#ifdef CONFIG_64BIT
		} else if ((insn & INSN_MASK_SD) == INSN_MATCH_SD) {
			;
#endif
		} else if ((insn & INSN_MASK_SH) == INSN_MATCH_SH) {
			;
#ifdef CONFIG_64BIT
		} else if ((insn & INSN_MASK_C_SD) == INSN_MATCH_C_SD) {
			rd = REG_OFFSET(RVC_RS2S(insn), 0);
		} else if ((insn & INSN_MASK_C_SDSP) == INSN_MATCH_C_SDSP &&
			   ((insn >> SH_RD) & 0x1f)) {
			rd = REG_OFFSET(insn, SH_RS2C);
#endif
		} else if ((insn & INSN_MASK_C_SW) == INSN_MATCH_C_SW) {
			rd = REG_OFFSET(RVC_RS2S(insn), 0);
		} else if ((insn & INSN_MASK_C_SWSP) == INSN_MATCH_C_SWSP &&
			   ((insn >> SH_RD) & 0x1f)) {
			rd = REG_OFFSET(insn, SH_RS2C);
		} else {
			// Can't decode
			print_string("Can't decode instruction:\n");
			printhex_ul(insn);
			hyp_panic();
		}
	} else
		rd = REG_OFFSET(insn, SH_RD);

	return rd / sizeof(unsigned long);
}

static inline unsigned long host_read_insn(void)
{
	struct kvm_cpu_trap dummy;
	return unpriv_read(true, csr_read(CSR_SEPC), &dummy);

}

static inline u32 host_dabt_get_as(unsigned long insn)
{
	u32 len;

	if ((insn & INSN_MASK_SW) == INSN_MATCH_SW) {
		len = 4;
	} else if ((insn & INSN_MASK_SB) == INSN_MATCH_SB) {
		len = 1;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_SD) == INSN_MATCH_SD) {
		len = 8;
#endif
	} else if ((insn & INSN_MASK_SH) == INSN_MATCH_SH) {
		len = 2;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_SD) == INSN_MATCH_C_SD) {
		len = 8;
	} else if ((insn & INSN_MASK_C_SDSP) == INSN_MATCH_C_SDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 8;
#endif
	} else if ((insn & INSN_MASK_C_SW) == INSN_MATCH_C_SW) {
		len = 4;
	} else if ((insn & INSN_MASK_C_SWSP) == INSN_MATCH_C_SWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 4;
	} else if ((insn & INSN_MASK_LW) == INSN_MATCH_LW) {
		len = 4;
	} else if ((insn & INSN_MASK_LB) == INSN_MATCH_LB) {
		len = 1;
	} else if ((insn & INSN_MASK_LBU) == INSN_MATCH_LBU) {
		len = 1;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_LD) == INSN_MATCH_LD) {
		len = 8;
	} else if ((insn & INSN_MASK_LWU) == INSN_MATCH_LWU) {
		len = 4;
#endif
	} else if ((insn & INSN_MASK_LH) == INSN_MATCH_LH) {
		len = 2;
	} else if ((insn & INSN_MASK_LHU) == INSN_MATCH_LHU) {
		len = 2;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_LD) == INSN_MATCH_C_LD) {
		len = 8;
	} else if ((insn & INSN_MASK_C_LDSP) == INSN_MATCH_C_LDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 8;
#endif
	} else if ((insn & INSN_MASK_C_LW) == INSN_MATCH_C_LW) {
		len = 4;
	} else if ((insn & INSN_MASK_C_LWSP) == INSN_MATCH_C_LWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		len = 4;
	} else {
		// Can't decode
		hyp_panic();
	}

	return len;
}

static inline int host_dabt_get_shift(unsigned long insn, u32 len)
{
	int shift; 

	if ((insn & INSN_MASK_LW) == INSN_MATCH_LW) {
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_LB) == INSN_MATCH_LB) {
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_LBU) == INSN_MATCH_LBU) {
		shift = 8 * (sizeof(ulong) - len);
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_LD) == INSN_MATCH_LD) {
		shift = 8 * (sizeof(ulong) - len);
#endif
	} else if ((insn & INSN_MASK_LH) == INSN_MATCH_LH) {
		shift = 8 * (sizeof(ulong) - len);
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_LD) == INSN_MATCH_C_LD) {
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_C_LDSP) == INSN_MATCH_C_LDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		shift = 8 * (sizeof(ulong) - len);
#endif
	} else if ((insn & INSN_MASK_C_LW) == INSN_MATCH_C_LW) {
		shift = 8 * (sizeof(ulong) - len);
	} else if ((insn & INSN_MASK_C_LWSP) == INSN_MATCH_C_LWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		shift = 8 * (sizeof(ulong) - len);
	} else {
		// Can't decode
		hyp_panic();
	}

	return shift;
}

static inline bool host_dabt_is_write(void)
{
	return csr_read(CSR_SCAUSE) == EXC_STORE_GUEST_PAGE_FAULT;
}

static inline u64 host_get_fault_ipa(void)
{
	return ((csr_read(CSR_HTVAL) << 2) | (csr_read(CSR_STVAL) & 0x3));
}

static inline void host_skip_instr(unsigned long insn)
{
	u64 val = csr_read(CSR_SEPC);
	csr_write(CSR_SEPC, val + INSN_LEN(insn));
}

#endif /* __RISCV_VERIFIED_MMIO__ */
