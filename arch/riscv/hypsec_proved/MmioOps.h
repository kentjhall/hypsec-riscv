#ifndef __RISCV_VERIFIED_MMIO__
#define __RISCV_VERIFIED_MMIO__

typedef u64 arm_lpae_iopte;

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

#define SH_RD				7

static inline u32 host_dabt_get_as(u32 htinst)
{
	unsigned long insn;
	int len = 0;

	/* Determine trapped instruction */
	if (htinst & 0x1) {
		/*
		 * Bit[0] == 1 implies trapped instruction value is
		 * transformed instruction or custom instruction.
		 */
		insn = htinst | INSN_16BIT_MASK;
	} else {
		// Not sure how to handle this case,
		// hopefully we don't get here
		__hyp_panic();
	}

	/* Decode length of MMIO */
	if ((insn & INSN_MASK_LW) == INSN_MATCH_LW) {
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
		__hyp_panic();
	}
	return len;
}

static inline bool host_dabt_is_write(void)
{
	return csr_read(CSR_SCAUSE) == EXC_STORE_GUEST_PAGE_FAULT;
}

static inline u64 host_get_fault_ipa(phys_addr_t addr)
{
	//return (addr | (read_sysreg_hs(far) & ((1 << 12) - 1)));
	// Not 100% sure this is right
	return (addr | (csr_read(CSR_STVAL) & 0x3));
}

static inline int host_dabt_get_rd(void)
{
	return SH_RD;
}

static inline void host_skip_instr(void)
{
	u64 val = csr_read(CSR_SEPC);
	csr_write(CSR_SEPC, val + 4);
}

#endif /* __RISCV_VERIFIED_MMIO__ */
