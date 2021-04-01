#ifndef __RISCV_STAGE2_H__
#define __RISCV_STAGE2_H__
#include <linux/memblock.h>
#include <linux/kvm_host.h>
#include <linux/hashtable.h>
#include <asm/hypsec_boot.h>
#include <asm/hypsec_mmu.h>
#include <asm/hypsec_vcpu.h>
#include <asm/hypsec_mmio.h>
#include <asm/hypsec_constant.h>

#define kvm_ksym_ref(sym) ((void *)&(sym))
#define kern_hyp_va(ptr) (ptr)

/* Handler for ACTLR_EL1 is not defined */
#define SHADOW_SYS_REGS_SIZE		(sizeof(struct kvm_vcpu_csr)/sizeof(unsigned long))
#define SHADOW_32BIT_REGS_SIZE		0
#define SHADOW_SYS_REGS_DESC_SIZE	(SHADOW_SYS_REGS_SIZE + SHADOW_32BIT_REGS_SIZE)
#define NUM_SHADOW_VCPU_CTXT		(HS_MAX_VMID * HYPSEC_MAX_VCPUS)

#define VCPU_IDX(vmid, vcpu_id) \
	(vmid * HYPSEC_MAX_VCPUS) + vcpu_id

struct shared_data {
	struct kvm kvm_pool[HS_MAX_VMID];
	struct kvm_vcpu vcpu_pool[HS_MAX_VMID * HYPSEC_MAX_VCPUS];
};

struct hs_per_cpu_data {
	int vmid;
	int vcpu_id;
	struct s2_host_regs *host_regs;
};

#if 0
typedef struct arch_spinlock_t arch_spinlock_t;
struct arch_spinlock_t {
	volatile unsigned int lock;
};
#endif

enum hypsec_init_state {
	INVALID = 0,
	MAPPED,
	READY,
	VERIFIED,
	ACTIVE
};

struct hs_load_info {
	unsigned long load_addr;
	unsigned long size;
	unsigned long hs_remap_addr;
	int hs_mapped_pages;
	uint8_t signature[64];
};

struct int_vcpu {
	struct kvm_vcpu *vcpu;
	int vcpu_pg_cnt;
	enum hypsec_init_state state;
	u32 ctxtid;
	u32 first_run;
};

struct hs_vm_info {
	u64 hgatp;
	int vmid;
	int load_info_cnt;
	int kvm_pg_cnt;
	bool inc_exe;
	enum hypsec_init_state state;
	struct hs_load_info load_info[HYPSEC_MAX_LOAD_IMG];
	arch_spinlock_t shadow_pt_lock;
	arch_spinlock_t vm_lock;
	struct kvm *kvm;
	struct int_vcpu int_vcpus[HYPSEC_MAX_VCPUS];
	struct shadow_vcpu_context *shadow_ctxt[HYPSEC_MAX_VCPUS];
	uint8_t public_key[32];
	bool powered_on;
	/* For VM private pool */
	u64 page_pool_start;
	u64 pgd_pool;
	u64 pud_pool;
	u64 pmd_pool;
	unsigned long used_pages;
};

struct hs_data {
	struct memblock_region regions[32];
	struct s2_memblock_info s2_memblock_info[32];
	struct s2_cpu_arch arch;

	int regions_cnt;
	u64 page_pool_start;
	phys_addr_t host_hgatp;

	unsigned long used_pages;
	unsigned long used_tmp_pages;
	unsigned long pl011_base;
	unsigned long uart_8250_base;

	arch_spinlock_t s2pages_lock;
	arch_spinlock_t abs_lock;
	arch_spinlock_t hs_pt_lock;
	arch_spinlock_t console_lock;
	arch_spinlock_t smmu_lock;
	arch_spinlock_t spt_lock;

	kvm_pfn_t ram_start_pfn;
	struct s2_page s2_pages[S2_PFN_SIZE];

	struct shadow_vcpu_context shadow_vcpu_ctxt[NUM_SHADOW_VCPU_CTXT];
	int used_shadow_vcpu_ctxt;

	struct s2_sys_reg_desc s2_sys_reg_descs[SHADOW_SYS_REGS_DESC_SIZE];

	struct hs_vm_info vm_info[HS_VM_INFO_SIZE];
	int used_vm_info;
	unsigned long last_remap_ptr;

	struct hs_smmu_cfg smmu_cfg[HS_SMMU_CFG_SIZE];
	struct hs_arm_smmu_device smmus[SMMU_NUM];
	int hs_smmu_num;

	u32 next_vmid;
	phys_addr_t vgic_cpu_base;
	bool installed;

	struct hs_per_cpu_data per_cpu_data[HYPSEC_MAX_CPUS];

	unsigned long core_start, core_end;

	uint64_t hacl_hash[80U];
        uint32_t hacl_hash0[64U];

	uint8_t key[16];
	uint8_t iv[16];

	unsigned long smmu_page_pool_start;
	unsigned long smmu_pgd_pool;
	unsigned long smmu_pmd_pool;

	u64 phys_mem_start;
	u64 phys_mem_size;
};

void init_hs_data_page(void);

#define _arch_spin_is_locked(x)	(READ_ONCE((x)->lock) != 0)

static inline int _arch_spin_trylock(arch_spinlock_t *lock)
{
	int tmp = 1, busy;

	__asm__ __volatile__ (
		"	amoswap.w %0, %2, %1\n"
		RISCV_ACQUIRE_BARRIER
		: "=r" (busy), "+A" (lock->lock)
		: "r" (tmp)
		: "memory");

	return !busy;
}

static inline void _arch_spin_lock(arch_spinlock_t *lock)
{
	while (1) {
		if (_arch_spin_is_locked(lock))
			continue;

		if (_arch_spin_trylock(lock))
			break;
	}
}

static inline void _arch_spin_unlock(arch_spinlock_t *lock)
{
	smp_store_release(&lock->lock, 0);
}

static inline void stage2_spin_lock(arch_spinlock_t *lock)
{	
	_arch_spin_lock(lock);
}

static inline void stage2_spin_unlock(arch_spinlock_t *lock)
{
	_arch_spin_unlock(lock);
}

static inline void hs_init_vgic_cpu_base(phys_addr_t base)
{
	struct hs_data *hs_data = (void *)kvm_ksym_ref(hs_data_start);
	hs_data->vgic_cpu_base = base;
}

extern void __noreturn __hyp_panic(void);

extern void printhex_ul(unsigned long input);
extern void print_string(char *input);

extern void stage2_inject_el1_fault(unsigned long addr);
void hs_memset(void *b, int c, int len);
void hs_memcpy(void *dest, void *src, size_t len);
int hs_memcmp(void *dest, void *src, size_t len);

int hs_hex_to_bin(char ch);
int hs_hex2bin(unsigned char *dst, const char *src, int count);

extern void hs_smmu_alloc_pgd(u32 cbndx, u32 vmid, u32 num);
extern void hs_smmu_free_pgd(u32 cbndx, u32 num);
extern void hs_arm_lpae_map(u64 iova, phys_addr_t paddr, u64 prot, u32 cbndx, u32 num);
extern phys_addr_t hs_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 num);
extern void hs_smmu_clear(u64 iova, u32 cbndx, u32 num);
extern void hypsec_phys_addr_ioremap(u32 vmid, u64 gpa, u64 pa, u64 size);

extern void hs_boot_from_inc_exe(u32 vmid);
extern bool hs_use_inc_exe(u32 vmid);

extern int hs_alloc_vm_info(struct kvm *kvm);

u32 handle_pvops(u32 vmid, u32 vcpuid);
void save_encrypted_vcpu(struct kvm_vcpu *vcpu);
void load_encrypted_vcpu(u32 vmid, u32 vcpu_id);

//extern void set_pfn_owner(struct hs_data *hs_data, phys_addr_t addr,
//				unsigned long pgnum, u32 vmid);

extern phys_addr_t host_alloc_stage2_page(unsigned int num);
extern phys_addr_t host_alloc_pgd(unsigned int num);
extern phys_addr_t host_alloc_pud(unsigned int num);
extern phys_addr_t host_alloc_pmd(unsigned int num);
extern phys_addr_t host_alloc_pte(unsigned int num);
extern void init_hypsec_io(void);

/* VM Bootstrap */
extern int hypsec_register_kvm(void);
extern int hypsec_register_vcpu(u32 vmid, int vcpu_id);

extern u32 __hypsec_register_kvm(void);
extern int __hypsec_register_vcpu(u32 vmid, int vcpu_id);

struct hs_vm_info* vmid_to_vm_info(u32 vmid);
struct int_vcpu* vcpu_id_to_int_vcpu(struct hs_vm_info *vm_info, int vcpu_id);

extern void map_vgic_cpu_to_shadow_s2pt(u32 vmid, struct hs_data *hs_data);

extern struct kvm* hypsec_alloc_vm(u32 vmid);
extern struct kvm_vcpu* hypsec_alloc_vcpu(u32 vmid, int vcpu_id);

static void inline set_per_cpu(int vmid, int vcpu_id)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	int pcpuid = smp_processor_id();
	hs_data->per_cpu_data[pcpuid].vmid = vmid;
	hs_data->per_cpu_data[pcpuid].vcpu_id = vcpu_id;
};

//int get_cur_vmid(void);
//int get_cur_vcpu_id(void);
static int inline get_cur_vmid(void)
{
        struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	int pcpuid = smp_processor_id();
	return hs_data->per_cpu_data[pcpuid].vmid;
};

static int inline get_cur_vcpu_id(void)
{
        struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	int pcpuid = smp_processor_id();
	return hs_data->per_cpu_data[pcpuid].vcpu_id;
};


static u64 inline get_shadow_ctxt(u32 vmid, u32 vcpuid, u32 index)
{
        struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	u64 val;
	if (index < 35)
		val = ((unsigned long *)&hs_data->shadow_vcpu_ctxt[offset].ctxt)[index];
	else if (index == V_FAR_HS)
		val = hs_data->shadow_vcpu_ctxt[offset].far_hs;
	else if (index == V_HPFAR_HS)
		val = hs_data->shadow_vcpu_ctxt[offset].hpfar;
	else if (index == V_HCR_HS)
		val = hs_data->shadow_vcpu_ctxt[offset].hcr_hs;
	else if (index == V_EC)
		val = hs_data->shadow_vcpu_ctxt[offset].ec;
	else if (index == V_DIRTY)
		val = hs_data->shadow_vcpu_ctxt[offset].dirty;
	else if (index == V_FLAGS)
		val = hs_data->shadow_vcpu_ctxt[offset].flags;
	else if (index >= SYSREGS_START) {
		index -= SYSREGS_START;
		val = ((unsigned long *)&hs_data->shadow_vcpu_ctxt[offset].csr)[index];
	} else {
		print_string("\rinvalid get shadow ctxt\n");
		val = INVALID64;
	}

	return val;
};

//TODO: Define the following
static void inline set_shadow_ctxt(u32 vmid, u32 vcpuid, u32 index, u64 value) {
        struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	//hs_data->shadow_vcpu_ctxt[offset].regs[index] = value;
	if (index < 35)
		((unsigned long *)&hs_data->shadow_vcpu_ctxt[offset].ctxt)[index] = value;
	else if (index == V_FAR_HS)
		hs_data->shadow_vcpu_ctxt[offset].far_hs = value;
	else if (index == V_HPFAR_HS)
		hs_data->shadow_vcpu_ctxt[offset].hpfar = value;
	else if (index == V_HCR_HS)
		hs_data->shadow_vcpu_ctxt[offset].hcr_hs = value;
	else if (index == V_EC)
		hs_data->shadow_vcpu_ctxt[offset].ec = value;
	else if (index == V_DIRTY)
		hs_data->shadow_vcpu_ctxt[offset].dirty = value;
	else if (index == V_FLAGS)
		hs_data->shadow_vcpu_ctxt[offset].flags = value;
	else if (index >= SYSREGS_START) {
		index -= SYSREGS_START;
		((unsigned long *)&hs_data->shadow_vcpu_ctxt[offset].csr)[index] = value;
	} else
		print_string("\rinvalid set shadow ctxt\n");
}

void save_shadow_kvm_regs(void);
void restore_shadow_kvm_regs(void);

void __vm_sysreg_restore_state_nvhe(u32 vmid, u32 vcpuid);
void __vm_sysreg_save_state_nvhe(u32 vmid, u32 vcpuid);

void __vm_sysreg_restore_state_nvhe_opt(struct shadow_vcpu_context *ctxt);
void __vm_sysreg_save_state_nvhe_opt(struct shadow_vcpu_context *ctxt);

void init_hacl_hash(struct hs_data *hs_data);
uint64_t get_hacl_hash_sha2_constant_k384_512(int i);
uint32_t get_hacl_hash_sha2_constant_k224_256(int i);

static u64 inline get_pt_hgatp(u32 vmid)
{
	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	if (vmid < COREVISOR) {
		return hs_data->vm_info[vmid].hgatp;
	} else {
		return csr_read(CSR_SATP);
	}
}

static void inline set_pt_hgatp(u32 vmid, u64 hgatp) {
	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	hs_data->vm_info[vmid].hgatp = hgatp;
};

void handle_host_hvc(struct s2_host_regs *hr);
void handle_host_stage2_fault(unsigned long host_lr,
			      struct s2_host_regs *host_regs);

void hvc_enable_s2_trans(void);
#endif /* __RISCV_STAGE2_H__ */
