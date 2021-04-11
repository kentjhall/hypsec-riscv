#ifndef __RISCV_STAGE2_MMIO__
#define __RISCV_STAGE2_MMIO__

/* We map a iommu_cfg to each context bank on the hardware.
 * We hardcode the value here since we have 8 ctxtbnk on Seattle.
 */

#define IOMMU_NUM_CTXT_BANKS	8
#define IOMMU_NUM		2
#define HS_IOMMU_CFG_SIZE	IOMMU_NUM_CTXT_BANKS * IOMMU_NUM

/* FIXME: Hardcoded IOMMU addresses now.. */
#define IOMMU_BASE(iommu)		iommu.phys_base
#define IOMMU_SIZE(iommu)		iommu.size

/* Maximum number of context banks per IOMMU */
#define ARM_IOMMU_MAX_CBS		128

struct hs_iommu_cfg {
	u32 vmid;
	u64 hw_ttbr;
};


struct hs_riscv_iommu_device {
	u64				phys_base;
	u64				size;
	unsigned long			pgshift;

	#define ARM_IOMMU_FEAT_COHERENT_WALK	(1 << 0)
	#define ARM_IOMMU_FEAT_STREAM_MATCH	(1 << 1)
	#define ARM_IOMMU_FEAT_TRANS_S1		(1 << 2)
	#define ARM_IOMMU_FEAT_TRANS_S2		(1 << 3)
	#define ARM_IOMMU_FEAT_TRANS_NESTED	(1 << 4)

	u32				features;
#define ARM_IOMMU_OPT_SECURE_CFG_ACCESS (1 << 0)
	u32				options;
	u32				num_context_banks;
	u32				num_s2_context_banks;

	u32				num_mapping_groups;

	unsigned long			va_size;
	unsigned long			ipa_size;
	unsigned long			pa_size;

	u32				num_global_irqs;
	u32				num_context_irqs;
	bool				exists;

	unsigned long			hyp_base;
	u32				index;
};

struct hs_iommu_cfg* alloc_iommu_cfg(struct hs_data *hs_data);
#endif /* __RISCV_STAGE2_MMIO__ */
