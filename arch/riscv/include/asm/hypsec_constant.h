#ifndef HYPSEC_CONSTANTS_H
#define HYPSEC_CONSTANTS_H

#define V_INVALID	0xFFFFFFFF
#define INVALID64	0xFFFFFFFFFFFFFFFF
#define INVALID_MEM	-1

#define PT_POOL_START 0x10000
#define PT_POOL_PER_VM STAGE2_VM_POOL_SIZE
#define MAX_VM_NUM 33 
#define MAX_CTXT_NUM 1024
#define MAX_LOAD_INFO_NUM 5
/*
#define KVM_PHYS_SIZE 4096UL
#define PAGE_SIZE 4096UL
#define PAGE_GUEST 0UL
#define PAGE_NONE 0UL
#define PAGE_S2_KERNEL 0UL
#define PAGE_S2_DEVICE 0UL
#define PAGE_HYP 0UL
#define PAGE_S2 0UL
#define PTE_S2_RDWR 0UL
#define PMD_S2_RDWR 0UL
#define PTE_S2_XN 0UL
#define PMD_S2_XN 0UL
*/
#define PHYS_MASK 1UL
/*
#define PAGE_MASK 1UL
#define S2_PGDIR_SHIFT 1UL
#define PTRS_PER_PGD 1UL
#define S2_PMD_SHIFT 1UL
#define PTRS_PER_PMD 1UL
#define PTRS_PER_PTE 1UL
#define PUD_TYPE_TABLE 1UL
#define PMD_TYPE_TABLE 1UL
#define VTTBR_VMID_SHIFT 1UL
#define S2_PGD_PAGES_NUM 1UL
#define MEMBLOCK_NOMAP 1UL
*/
#define MAX_MMIO_ADDR 0x80000000
#define S2_RDWR PTE_S2_RDWR 
#define PMD_PAGE_MASK PMD_MASK 

#define S2_PTE_SHIFT PAGE_SHIFT
#define PMD_TABLE_SHIFT PMD_SHIFT 

#define COREVISOR HS_MAX_VMID
#define HOSTVISOR 0
#define MAX_SHARE_COUNT 100
#define UNUSED 0
//#define READY 1
//#define VERIFIED 2
//#define ACTIVE 3

//Boot
#define SHARED_KVM_START 1
#define SHARED_VCPU_START 1
#define VCPU_PER_VM	8

//#define SHADOW_SYS_REGS_SIZE 1
#define GP_REG_END	31
#define V_PC		32
#define V_SSTATUS 	33
#define	V_HSTATUS	34
#define V_STVAL		35
#define V_HTVAL		36
#define V_HTINST	37
#define V_EC		38
#define V_DIRTY		39
#define V_FLAGS		40
#define CSRS_START	V_VSSTATUS
#define V_VSSTATUS	41
#define V_HIE		42
#define V_VSTVEC	43
#define V_VSSCRATCH	44
#define V_VSEPC		45
#define V_VSCAUSE	46
#define V_VSTVAL	47
#define V_HVIP		48
#define V_VSATP		49
#define V_SCOUNTEREN	50

// Do we need the 32 bit registers?
#define V_ESR_EL1	41 + ESR_EL1
#define V_SPSR_0 8
#define V_HPFAR_MASK 65535UL

/*
#define PENDING_FSC_FAULT 1UL //????????????
#define ARM_EXCEPTION_TRAP 0UL
#define PENDING_EXCEPT_INJECT_FLAG 2UL //????????
#define DIRTY_PC_FLAG 4UL //??????????????
#define ESR_ELx_EC_MASK 63UL
#define ESR_ELx_EC_SHIFT 67108864UL // (1 << 26)
#define PSCI_0_2_FN64_CPU_ON 4UL //?????????
#define PSCI_0_2_FN_AFFINITY_INFO 5UL //?????????
#define PSCI_0_2_FN64_AFFINITY_INFO 6UL //?????????
#define PSCI_0_2_FN_SYSTEM_OFF 7UL //?????????
#define ESR_ELx_EC_WFx 8UL //?????????????????
#define ESR_ELx_EC_HVC32 9UL
#define ESR_ELx_EC_HVC64 10UL
#define ESR_ELx_EC_IABT_LOW 11UL
#define ESR_ELx_EC_DABT_LOW 12UL
*/
#define PSTATE_FAULT_BITS_64 11UL

/* TODO (etm): This is extracted from arch/riscv/kvm/mmu.c
 *  DRY this out
 */
#ifdef CONFIG_64BIT
//static unsigned long stage2_mode = (HGATP_MODE_SV39X4 << HGATP_MODE_SHIFT);
static unsigned long stage2_pgd_levels = 3;
#define stage2_index_bits	9
#else
static unsigned long stage2_mode = (HGATP_MODE_SV32X4 << HGATP_MODE_SHIFT);
static unsigned long stage2_pgd_levels = 2;
#define stage2_index_bits	10
#endif

#define stage2_pgd_xbits	2
#define stage2_pgd_size	(1UL << (HGATP_PAGE_SHIFT + stage2_pgd_xbits))
#define stage2_gpa_bits	(HGATP_PAGE_SHIFT + \
			 (stage2_pgd_levels * stage2_index_bits) + \
			 stage2_pgd_xbits)
#define stage2_gpa_size	((gpa_t)(1ULL << stage2_gpa_bits))

static inline unsigned long stage2_pte_index(gpa_t addr, u32 level)
{
	unsigned long mask;
	unsigned long shift = HGATP_PAGE_SHIFT + (stage2_index_bits * level);

	if (level == (stage2_pgd_levels - 1))
		mask = (PTRS_PER_PTE * (1UL << stage2_pgd_xbits)) - 1;
	else
		mask = PTRS_PER_PTE - 1;

	return (addr >> shift) & mask;
}


// Micros

#define PT_POOL_SIZE (STAGE2_PAGES_SIZE)
// This is some wacky ARM macro that doesn't work with RISCV
//#define phys_page(addr) ((addr) & PHYS_MASK & PAGE_MASK)

#define phys_page(addr) ((addr) << PAGE_SHIFT)
#define pgd_idx(addr)	stage2_pte_index(addr, stage2_pgd_levels - 1)
//#define pud_idx(addr)   pgd_idx(addr)
//#define pud_idx(addr)	pud_index(addr)
#define pmd_idx(addr) stage2_pte_index(addr, stage2_pgd_levels - 2)
#define pte_idx(addr) stage2_pte_index(addr, stage2_pgd_levels - 3)
//#define pmd_idx(addr)	pmd_index(addr)
//#define pte_idx(addr)	pte_index(addr)
#define v_pmd_table(x) (x & )
#define writable(pte) (((pte) >> 2UL) & 1UL)

#define IOMMU_HOST_OFFSET 1000000000UL
#define PMD_PAGE_NUM	512

#define PAGE_HYPSEC __pgprot(_HYP_PAGE_DEFAULT | PTE_HYP | PTE_HYP_XN)
#endif //HYPSEC_CONSTANTS_H
