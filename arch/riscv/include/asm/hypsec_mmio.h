#ifndef __RISCV_STAGE2_MMIO__
#define __RISCV_STAGE2_MMIO__


struct hs_riscv_plic_device {
	u64				phys_base;
	u64				size;

	unsigned long			hyp_base;
};

#endif /* __RISCV_STAGE2_MMIO__ */
