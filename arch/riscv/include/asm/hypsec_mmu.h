#ifndef __RISCV_STAGE2_MMU__
#define __RISCV_STAGE2_MMU__

#include <linux/memblock.h>

/* S2 Pages can map up to 16GB of RAM */
#define S2_PFN_SIZE	4096 * 4096
#define IPA_HASH_SIZE	4096 * 32 

#define HS_PAGE_OFFSET			0x40000000000UL
//#define HS_REMAP_START                 0xc0000000
#define HS_REMAP_START                 0x100000000
#define HS_REMAP_END			HS_PAGE_OFFSET

#define PAGE_GUEST			__pgprot(PTE_S2_GUEST)

#define __hs_va(x)	(void *)(((unsigned long)(x) & \
					(HS_PAGE_OFFSET - 1)) | HS_PAGE_OFFSET)
#define	HYPSEC_VMID			0xffffffff

#define S2_PGD_PAGES_NUM	(PTRS_PER_S2_PGD * sizeof(pgd_t)) / PAGE_SIZE

struct hs_data;

struct vring_data {
	size_t queue_size_in_bytes;
	u64 host_pfn;
};

struct s2_page {
	int count;
	u32 vmid;
	u64 gfn;
};

struct s2_memblock_info {
	unsigned long index;
};

struct s2_trans {
        kvm_pfn_t pfn;
        phys_addr_t output;
        bool writable;
        bool readable;
        int level;
	u64 desc;
};

struct ipa_hash {
	kvm_pfn_t ipa_pfn;
	kvm_pfn_t pfn;
	u64 vmid;
	struct hlist_node hlist;
};

struct s2_unmapped_ipa {
	phys_addr_t ipa;
	int count;
};

struct hyp_va_region {
	unsigned long from;
	unsigned long to;
};

struct shadow_vcpu_context;

extern u64 get_shadow_vttbr(u32 vmid);
void __set_pfn_host(phys_addr_t start, u64 size, kvm_pfn_t pfn, pgprot_t prot);

void clear_vm_stage2_range(u32 vmid, phys_addr_t start, u64 size);
int hs_create_hyp_mapping(unsigned long start, unsigned long end,
			    unsigned long pfn);


extern void hs_flush_dcache_to_poc(void *addr, size_t size);
extern void hs_flush_icache_range(unsigned long start, unsigned long end);

void grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
void revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
void set_balloon_pfn(struct shadow_vcpu_context *shadow_ctxt);

void* alloc_stage2_page_split(u32 vmid, unsigned int num);
void* alloc_stage2_page(unsigned int num);

struct s2_trans walk_stage2_pgd(u32 vmid, phys_addr_t addr);

int stage2_mem_regions_search(phys_addr_t addr, struct memblock_region *regions,
	unsigned long cnt);

//void post_handle_shadow_s2pt_fault(struct kvm_vcpu *vcpu,
//				   struct shadow_vcpu_context *shadow_ctxt);

extern void clear_shadow_stage2_range(u32 vmid, phys_addr_t start, u64 size);
extern void __kvm_tlb_flush_vmid_hs(void);

extern int map_hs_mem(unsigned long start, unsigned long end,
			    unsigned long pfn, pgprot_t prot);

extern void unmap_image_from_host_s2pt(u32 vmid, unsigned long hs_remap_addr, unsigned long pgnum);
extern void load_image_to_shadow_s2pt(u32 vmid, struct hs_data *hs_data,
				unsigned long target_addr, unsigned long hs_remap_addr,
				unsigned long pgnum);

bool stage2_is_map_memory(phys_addr_t addr);
unsigned long get_hs_image_va(u32 vmid, unsigned long addr);
extern struct s2_trans handle_from_vm_info(struct hs_data *hs_data,
					   unsigned long hs_va, unsigned long addr);

static inline bool is_gic_cpu(u64 addr)
{
	return (addr >= 0x08010000 && addr < 0x08020000) ? true : false;
}

static inline bool is_mmio_gpa(u64 addr)
{
	return (addr < 0x40000000 && !is_gic_cpu(addr)) ? true : false;
}

pmd_t *pmd_offset_hs(pud_t *pud, u64 addr);
pte_t *pte_offset_hs(pmd_t *pmd, u64 addr);

extern void hs_encrypt_buf(u32 vmid, u64 buf, u64 out_buf);
extern void hs_decrypt_buf(u32 vmid, void *buf, uint32_t len);

extern pgd_t *hyp_pg_dir;
extern void setup_vm_hyp(void);
extern void __kvm_tlb_flush_vmid_ipa_shadow(phys_addr_t ipa);
extern void hypsec_tlb_flush_local_vmid(void);

int map_hs_mem(unsigned long start, unsigned long end,
			    unsigned long pfn, pgprot_t prot);
void  __clear_vm_stage2_range(u32 vmid, phys_addr_t start, u64 size);

u32 get_hpa_owner(phys_addr_t addr);

int create_hypsec_io_mappings(phys_addr_t phys_addr, size_t size,
			      unsigned long *haddr);
int hs_create_hyp_mappings(void *from, void *to, pgprot_t prot);
#endif /* __RISCV_STAGE2_MMU__ */

