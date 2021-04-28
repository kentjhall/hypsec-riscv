#ifndef HYPSEC_HYPSEC_H
#define HYPSEC_HYPSEC_H

#include <linux/types.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/hypsec_host.h>
#include <asm/hypsec_pgtable.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include <asm/hypsec_constant.h>

typedef unsigned long long u64;
typedef unsigned u32;
typedef u64 phys_addr_t;

/*
 * AbstractMachine
 */

static u32 inline check(u32 val) {
	return val;
};

static u64 inline check64(u64 val) {
	return val;
};

static inline void __noreturn __hyp_panic(void)
{
	print_string("SEPC:\n");
	printhex_ul(csr_read(CSR_SEPC));
	print_string("Panic in HS mode! Spinning forever now...\n");
	for(;;); // just spin, why not
}

static void inline v_panic(void) {
	//__hyp_panic();
	u32 vmid = get_cur_vmid();
	u32 vcpuid = get_cur_vcpu_id();
	if (vmid) {
		print_string("\rvm\n");
		printhex_ul(get_shadow_ctxt(vmid, vcpuid, V_PC));
	} else {
		print_string("\rhost\n");
		printhex_ul(csr_read(CSR_SEPC));
	}
	printhex_ul(csr_read(CSR_SCAUSE));
}

#define current_hs_thread_info() \
	((struct hs_thread_info *)riscv_current_is_tp)

void    clear_phys_mem(u64 pfn);
//u64     get_shared_kvm(u32 vmid);
//u64     get_shared_vcpu(u32 vmid, u32 vcpuid);
u32     verify_image(u32 vmid, u32 load_idx, u64 addr);
///u64     get_sys_reg_desc_val(u32 index);
u64     get_exception_vector(u64 pstate);

static u64 inline get_shared_kvm(u32 vmid) {
    //return SHARED_KVM_START + vmid * sizeof(struct kvm);
    u64 shared_kvm_start = (u64)kvm_ksym_ref(shared_data_start);
    return shared_kvm_start + vmid * sizeof(struct kvm);
}

static u64 inline get_shared_vcpu(u32 vmid, u32 vcpuid) {
    //return SHARED_VCPU_START + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
    u64 vcpu_off = sizeof(struct kvm) * HS_MAX_VMID;
    u64 shared_vcpu_start = (u64)kvm_ksym_ref(shared_data_start) + vcpu_off;
    return shared_vcpu_start + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
}

static u64 inline get_sys_reg_desc_val(u32 index) {
    // TODO
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->s2_sys_reg_descs[index].val;
}

static void inline fetch_from_doracle(u32 vmid, u64 pfn, u64 pgnum) {
	return;
}
extern void reset_fp_regs(u32 vmid, int vcpu_id);

static u64 inline get_vm_fault_addr(u32 vmid, u32 vcpuid) {
	u64 hpfar;
	hpfar = get_shadow_ctxt(vmid, vcpuid, V_HPFAR_HS);
	return hpfar;
}

static void inline mem_load_raw(u64 gfn, u32 reg) {
}

static void inline mem_store_raw(u64 gfn, u32 reg) {
}
/*
void    acquire_lock_pt(u32 vmid);
void    release_lock_pt(u32 vmid);
u64	pool_start(u32 vmid);
u64	pool_end(u32 vmid);
u64     pt_load(u32 vmid, u64 addr);
void    pt_store(u32 vmid, u64 addr, u64 value);
u64     get_pt_vttbr(u32 vmid);
void    set_pt_vttbr(u32 vmid, u64 vttbr);
*/

static void inline acquire_lock_pt(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_lock(&hs_data->vm_info[vmid].shadow_pt_lock);
};

static void inline release_lock_pt(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_unlock(&hs_data->vm_info[vmid].shadow_pt_lock);
};

// TODO: make the following work
static u64 inline pt_load(u32 vmid, u64 addr) {
	unsigned long *ptr = __va(addr);
	return (u64)*ptr;
};

// TODO: make the following work
static void inline pt_store(u32 vmid, u64 addr, u64 value) {
	unsigned long *ptr = __va(addr);
	*ptr = value;
};

/* for split PT pool */
#define PGD_BASE (PAGE_SIZE * 4)
#define PUD_BASE (PGD_BASE + (PAGE_SIZE * 16))
#define PMD_BASE SZ_2M
static u64 inline get_pgd_next(u32 vmid) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->vm_info[vmid].pgd_pool;
};

static void inline set_pgd_next(u32 vmid, u64 next) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	hs_data->vm_info[vmid].pgd_pool = next;
};

static u64 inline get_pud_next(u32 vmid) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->vm_info[vmid].pud_pool;
};

static void inline set_pud_next(u32 vmid, u64 next) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	hs_data->vm_info[vmid].pud_pool = next;
};

static u64 inline get_pmd_next(u32 vmid) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->vm_info[vmid].pmd_pool;
};

static void inline set_pmd_next(u32 vmid, u64 next) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	hs_data->vm_info[vmid].pmd_pool = next;
};

#define HOST_PUD_BASE (PGD_BASE + PAGE_SIZE * 128)
#define HOST_PMD_BASE (SZ_2M * 2)
static u64 inline pgd_pool_end(u32 vmid) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u64 pool_start = hs_data->vm_info[vmid].page_pool_start;
	if (vmid == HOSTVISOR)
		return pool_start + HOST_PUD_BASE;
	else
		return pool_start + PUD_BASE;
}

static u64 inline pud_pool_end(u32 vmid) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u64 pool_start = hs_data->vm_info[vmid].page_pool_start;
	if (vmid == HOSTVISOR)
		return pool_start + HOST_PMD_BASE;
	else
		return pool_start + PMD_BASE;
}

static u64 inline pmd_pool_end(u32 vmid) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u64 pool_start = hs_data->vm_info[vmid].page_pool_start;
	if (vmid == COREVISOR)
		return pool_start + STAGE2_CORE_PAGES_SIZE;
	else if (vmid == HOSTVISOR)
		return pool_start + STAGE2_HOST_POOL_SIZE;
	return pool_start + PT_POOL_PER_VM;
}

/*
u32     get_mem_region_cnt(void);
u64     get_mem_region_base(u32 index);
u64     get_mem_region_size(u32 index);
u64     get_mem_region_index(u32 index);
u64     get_mem_region_flag(u32 index);
*/
static u32 inline get_mem_region_cnt(void) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	return hs_data->regions_cnt;
}

static u64 inline get_mem_region_base(u32 index) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	return hs_data->regions[index].base;
}
static u64 inline get_mem_region_size(u32 index) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	return hs_data->regions[index].size;
}

static u64 inline get_mem_region_index(u32 index) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	return hs_data->s2_memblock_info[index].index;
}

static u64 inline get_mem_region_flag(u32 index) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	return hs_data->regions[index].flags;
}

/*
void    acquire_lock_s2page(void);
void    release_lock_s2page(void);
u32     get_s2_page_vmid(u64 index);
void    set_s2_page_vmid(u64 index, u32 vmid);
u32     get_s2_page_count(u64 index);
void    set_s2_page_count(u64 index, u32 count);
*/

static void inline acquire_lock_s2page(void) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_lock(&hs_data->s2pages_lock);
}

static void inline release_lock_s2page(void) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_unlock(&hs_data->s2pages_lock);
}

static u32 inline get_s2_page_vmid(u64 index) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->s2_pages[index].vmid;
}

static void inline set_s2_page_vmid(u64 index, u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->s2_pages[index].vmid = vmid;
}

static u32 inline get_s2_page_count(u64 index) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->s2_pages[index].count;
}

static void inline set_s2_page_count(u64 index, u32 count) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->s2_pages[index].count = count;
}

static u64 inline get_s2_page_gfn(u64 index) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->s2_pages[index].gfn;
}

static void inline set_s2_page_gfn(u64 index, u64 gfn) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->s2_pages[index].gfn = gfn;
}

/*
void    acquire_lock_vm(u32 vmid);
void    release_lock_vm(u32 vmid);
u32     get_vm_state(u32 vmid);
void    set_vm_state(u32 vmid, u32 state);
u32     get_vcpu_state(u32 vmid, u32 vcpuid);
void    set_vcpu_state(u32 vmid, u32 vcpuid, u32 state);
u32     get_vm_power(u32 vmid);
void    set_vm_power(u32 vmid, u32 power);
u32     get_vm_inc_exe(u32 vmid);
void    set_vm_inc_exe(u32 vmid, u32 inc_exe);
u64     get_vm_kvm(u32 vmid);
void    set_vm_kvm(u32 vmid, u64 kvm);
u64     get_vm_vcpu(u32 vmid, u32 vcpuid);
void    set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu);
u32     get_vm_next_load_idx(u32 vmid);
void    set_vm_next_load_idx(u32 vmid, u32 load_idx);
u64     get_vm_load_addr(u32 vmid, u32 load_idx);
void    set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr);
u64     get_vm_load_size(u32 vmid, u32 load_idx);
void    set_vm_load_size(u32 vmid, u32 load_idx, u64 size);
u64     get_vm_remap_addr(u32 vmid, u32 load_idx);
void    set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr);
u64     get_vm_mapped_pages(u32 vmid, u32 load_idx);
void    set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped);
*/
static void inline acquire_lock_vm(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_lock(&hs_data->vm_info[vmid].vm_lock);
}

static void inline release_lock_vm(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_unlock(&hs_data->vm_info[vmid].vm_lock);
}

static u32 inline get_vm_state(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->vm_info[vmid].state;
}

static void inline set_vm_state(u32 vmid, u32 state) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].state = state;
}

static u32 inline get_vcpu_first_run(u32 vmid, u32 vcpuid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->vm_info[vmid].int_vcpus[vcpuid].first_run;
}

static void inline set_vcpu_first_run(u32 vmid, u32 vcpuid, u32 state) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].int_vcpus[vcpuid].first_run = state;
}

static u32 inline get_vcpu_state(u32 vmid, u32 vcpuid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->vm_info[vmid].int_vcpus[vcpuid].state;
}

static void inline set_vcpu_state(u32 vmid, u32 vcpuid, u32 state) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].int_vcpus[vcpuid].state = state;
}

static void inline set_vm_power(u32 vmid, u32 power) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].powered_on = power;
}

static u32 inline get_vm_power(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->vm_info[vmid].powered_on;
}

static u32 inline get_vm_inc_exe(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->vm_info[vmid].inc_exe;
}

static void inline set_vm_inc_exe(u32 vmid, u32 inc_exe) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].inc_exe = inc_exe;
}

static u64 inline get_vm_kvm(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return (u64)hs_data->vm_info[vmid].kvm;
}

static void inline set_vm_kvm(u32 vmid, u64 kvm) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].kvm = (struct kvm*)kvm;
}

static u64 inline get_vm_vcpu(u32 vmid, u32 vcpuid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return (u64)hs_data->vm_info[vmid].int_vcpus[vcpuid].vcpu;
}

static void inline set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    hs_data->vm_info[vmid].int_vcpus[vcpuid].vcpu = (struct kvm_vcpu*)vcpu;
}

static u32 inline get_vm_next_load_idx(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    return hs_data->vm_info[vmid].load_info_cnt;
}

static void inline set_vm_next_load_idx(u32 vmid, u32 load_idx) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->vm_info[vmid].load_info_cnt = load_idx;
}

static u64 inline get_vm_load_addr(u32 vmid, u32 load_idx) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->vm_info[vmid].load_info[load_idx].load_addr;
}

static void inline set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->vm_info[vmid].load_info[load_idx].load_addr = load_addr;
}

static u64 inline get_vm_load_size(u32 vmid, u32 load_idx) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->vm_info[vmid].load_info[load_idx].size;
}

static void inline set_vm_load_size(u32 vmid, u32 load_idx, u64 size) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->vm_info[vmid].load_info[load_idx].size = size;
}

static u64 inline get_vm_remap_addr(u32 vmid, u32 load_idx) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->vm_info[vmid].load_info[load_idx].hs_remap_addr;
}

static void inline set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->vm_info[vmid].load_info[load_idx].hs_remap_addr = remap_addr;
}

static u64 inline get_vm_mapped_pages(u32 vmid, u32 load_idx) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->vm_info[vmid].load_info[load_idx].hs_mapped_pages;
}

static void inline set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->vm_info[vmid].load_info[load_idx].hs_mapped_pages = mapped;
}

/*
void    acquire_lock_core(void);
void    release_lock_core(void);
u32     get_next_vmid(void);
void    set_next_vmid(u32 vmid);
u64     get_next_remap_ptr(void);
void    set_next_remap_ptr(u64 remap);
*/
static void inline acquire_lock_core(void) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_lock(&hs_data->abs_lock);
}

static void inline release_lock_core(void) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_unlock(&hs_data->abs_lock);
}

static u32 inline get_next_vmid(void) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->next_vmid;
}

static void inline set_next_vmid(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->next_vmid = vmid;
}

static u64 inline get_next_remap_ptr(void) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->last_remap_ptr + HS_REMAP_START;
}

static void inline set_next_remap_ptr(u64 remap) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_data->last_remap_ptr = remap;
}

//int     get_cur_vmid(void);
//int     get_cur_vcpuid(void);
//u64     get_int_gpr(u32 vmid, u32 vcpuid, u32 index);
//u64     get_int_pc(u32 vmid, u32 vcpuid);
//u64     get_int_pstate(u32 vmid, u32 vcpuid);
static u64 inline get_int_gpr(u32 vmid, u32 vcpuid, u32 index) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	if (index >= 35)
		__hyp_panic();
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return ((unsigned long *)&vcpu->arch.guest_context)[index];
}

static u64 inline get_int_pc(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.guest_context.sepc;
}

static u64 inline get_int_pstate(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.guest_context.hstatus;
}

//void	set_int_gpr(u32 vmid, u32 vcpuid, u32 index, u64 value);
static void inline set_int_gpr(u32 vmid, u32 vcpuid, u32 index, u64 value) {
       struct shared_data *shared_data;
       int offset = VCPU_IDX(vmid, vcpuid);
       struct kvm_vcpu *vcpu;
       if (index >= 35)
               __hyp_panic();
       shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
       vcpu = &shared_data->vcpu_pool[offset];
       ((unsigned long *)&vcpu->arch.guest_context)[index] = value;
}

void	set_int_pstate(u32 vmid, u32 vcpuid, u64 value);
void    clear_shadow_gp_regs(u32 vmid, u32 vcpuid);
void    int_to_shadow_fp_regs(u32 vmid, u32 vcpuid);
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
//u32     get_shadow_dirty_bit(u32 vmid, u32 vcpuid);
//void    set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u64 value);
static u32 inline get_shadow_dirty_bit(u32 vmid, u32 vcpuid) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	return hs_data->shadow_vcpu_ctxt[offset].dirty;
}

static void inline set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u64 value) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	if (value)
		hs_data->shadow_vcpu_ctxt[offset].dirty |= value;
	else
		hs_data->shadow_vcpu_ctxt[offset].dirty = 0;
}
//u64     get_int_new_pte(u32 vmid, u32 vcpuid);
//u32     get_int_new_level(u32 vmid, u32 vcpuid);
//bool	get_int_writable(u32 vmid, u32 vcpuid);
static bool inline get_int_writable(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.writable;
}

static u64 inline get_int_new_pte(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.output;
}

static u32 inline get_int_new_level(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.level;
}

//u32     get_shadow_esr(u32 vmid, u32 vcpuid);
//u32     get_int_esr(u32 vmid, u32 vcpuid);

static u32 inline get_shadow_esr(u32 vmid, u32 vcpuid) {
    	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	return hs_data->shadow_vcpu_ctxt[offset].esr;
}

static u32 inline get_int_esr(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.guest_trap.htinst;
}

extern void test_aes(struct hs_data *hs_data);

//for image verification
uint8_t* get_vm_public_key(u32 vmid);
void set_vm_public_key(u32 vmid);
uint8_t* get_vm_load_signature(u32 vmid, u32 load_idx);
void set_vm_load_signature(u32 vmid, u32 load_idx);

//for IOMMU
#define IOMMU_POOL_START 65536UL
#define IOMMU_PGD_START 131072UL
#define IOMMU_PMD_START 196608UL
#define IOMMU_POOL_END  IOMMU_PAGES_SIZE

#define IOMMU_PMD_BASE	(PAGE_SIZE * 256)
static void inline acquire_lock_plic(void) {
	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	stage2_spin_lock(&hs_data->plic_lock);
};
static void inline release_lock_plic(void) {
	struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
	stage2_spin_unlock(&hs_data->plic_lock);
};

static u64 inline get_plic_base(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->plic.phys_base;
}

static u64 inline get_plic_hyp_base(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->plic.hyp_base;
}

static u64 inline get_plic_size(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->plic.size;
}

static void inline set_per_cpu_host_regs(u64 hr)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	int pcpuid = current_hs_thread_info()->cpu;
	hs_data->per_cpu_data[pcpuid].host_regs = (struct s2_host_regs *)hr;
};

static void inline set_host_regs(int nr, u64 value)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	int pcpuid = current_hs_thread_info()->cpu;
	hs_data->per_cpu_data[pcpuid].host_regs->regs[nr] = value;
};

static u64 inline get_host_regs(int nr)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	int pcpuid = current_hs_thread_info()->cpu;
	return hs_data->per_cpu_data[pcpuid].host_regs->regs[nr];
};

static u64 inline get_phys_mem_size(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->phys_mem_size;
}

static u64 inline get_phys_mem_start_pfn(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->phys_mem_start >> PAGE_SHIFT;
}

static u64 inline get_phys_mem_start(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->phys_mem_start;
}

static void inline acquire_lock_spt(void) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_lock(&hs_data->spt_lock);
};

static void inline release_lock_spt(void) {
    struct hs_data *hs_data = kern_hyp_va((void*)&hs_data_start);
    stage2_spin_unlock(&hs_data->spt_lock);
};

void encrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len);
void decrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len);

static u64 inline get_tmp_buf(void) {
	u64 ret = (u64)kern_hyp_va((void*)&stage2_tmp_pgs_start);
	return ret;
};

/*
 * PTAlloc
 */

u64 alloc_s2pt_pgd(u32 vmid);
u64 alloc_s2pt_pud(u32 vmid);
u64 alloc_s2pt_pmd(u32 vmid);
//u64 alloc_plic_pgd_page(void);
//u64 alloc_plic_pmd_page(void);

/*
 * PTWalk
 */

u64 walk_pgd(u32 vmid, u64 vttbr, u64 addr, u32 alloc);
u64 walk_pud(u32 vmid, u64 pgd, u64 addr, u32 alloc);
u64 walk_pmd(u32 vmid, u64 pud, u64 addr, u32 alloc);
u64 walk_pte(u32 vmid, u64 pmd, u64 addr);
void v_set_pmd(u32 vmid, u64 pud, u64 addr, u64 pmd);
void v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte);
u64 walk_plic_pgd(u64 ttbr, u64 addr, u32 alloc);
u64 walk_plic_pmd(u64 pgd, u64 addr, u32 alloc);
u64 walk_plic_pte(u64 pmd, u64 addr);
void set_plic_pte(u64 pmd, u64 addr, u64 pte);

/*
 * NPTWalk
 */

u32 get_npt_level(u32 vmid, u64 addr);
u64 walk_npt(u32 vmid, u64 addr);
void set_npt(u32 vmid, u64 addr, u32 level, u64 pte);

/*
 * NPTOps
 */

u32 get_level_s2pt(u32 vmid, u64 addr);
u64 walk_s2pt(u32 vmid, u64 addr);
void mmap_s2pt(u32 vmid, u64 addr, u32 level, u64 pte);
void clear_pfn_host(u64 pfn);
extern void kvm_tlb_flush_vmid_ipa_host(phys_addr_t ipa);

/*
 * MemRegion
 */

u32 mem_region_search(u64 addr);

/*
 * PageIndex
 */

u64 get_s2_page_index(u64 addr);

/*
 * PageManager
 */

u32 get_pfn_owner(u64 pfn);
void set_pfn_owner(u64 pfn, u32 vmid);
u32 get_pfn_count(u64 pfn);
void set_pfn_count(u64 pfn, u32 count);
u64 get_pfn_map(u64 pfn);
void set_pfn_map(u64 pfn, u64 gfn);

/*
 * VMPower
 */

void set_vm_poweroff(u32 vmid);
u32 get_vm_poweron(u32 vmid);

/*
 * MemManagerAux
 */
u32 check_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum);
void set_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum);

/*
 * MemManager
 */

void map_page_host(u64 addr);
void clear_vm_page(u32 vmid, u64 pfn);
void assign_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn);
void assign_pfn_to_plic(u32 vmid, u64 gfn, u64 pfn);
void map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level);
void grant_vm_page(u32 vmid, u64 pfn);
void revoke_vm_page(u32 vmid, u64 pfn);
void clear_phys_page(unsigned long pfn);
void update_plic_page(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte);
void unmap_plic_page(u32 cbndx, u32 index, u64 iova);

/*
 * MemoryOps
 */

void clear_vm_stage2_range(u32 vmid, u64 start, u64 size);
void prot_and_map_vm_s2pt(u32 vmid, u64 addr, u64 pte, u32 level);
//void grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
//void revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
void map_vm_io(u32 vmid, u64 gpa, u64 pa);
void clear_vm_range(u32 vmid, u64 pfn, u64 num);

/*
 * BootCore
 */

u32 gen_vmid(void);
u64 alloc_remap_addr(u64 pgnum);

/*
 * BootAux
 */

void unmap_and_load_vm_image(u32 vmid, u64 target_addr, u64 remap_addr, u64 num);

/*
 * BootOps
 */

u32 vm_is_inc_exe(u32 vmid);
void boot_from_inc_exe(u32 vmid);
u64 search_load_info(u32 vmid, u64 addr);
void set_vcpu_active(u32 vmid, u32 vcpuid);
void set_vcpu_inactive(u32 vmid, u32 vcpuid);
void register_vcpu(u32 vmid, u32 vcpuid);
u32 register_kvm(void);
u32 set_boot_info(u32 vmid, u64 load_addr, u64 size);
void remap_vm_image(u32 vmid, u64 pfn, u32 load_idx);
void verify_and_load_images(u32 vmid);

void alloc_plic(u32 vmid, u32 cbndx, u32 index); 
void assign_plic(u32 vmid, u32 pfn, u32 gfn); 
void map_plic(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte);
void clear_plic(u32 vmid, u32 cbndx, u32 index, u64 iova);
void map_io(u32 vmid, u64 gpa, u64 pa);


/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 vmid, u32 vcpuid);
void reset_sys_regs(u32 vmid, u32 vcpuid);
//void save_sys_regs(u32 vmid, u32 vcpuid);
//void restore_sys_regs(u32 vmid, u32 vcpuid);
void sync_dirty_to_shadow(u32 vmid, u32 vcpuid);
void prep_wfx(u32 vmid, u32 vcpuid);
void prep_hvc(u32 vmid, u32 vcpuid);
void prep_abort(u32 vmid, u32 vcpuid);
void v_hypsec_inject_undef(u32 vmid, u32 vcpuid);
void v_update_exception_gp_regs(u32 vmid, u32 vcpuid);
void post_handle_shadow_s2pt_fault(u32 vmid, u32 vcpuid, u64 addr);


/*
 * VCPUOps
 */

void save_shadow_kvm_regs(void);
void restore_shadow_kvm_regs(void);
void __save_encrypted_vcpu(u32 vmid, u32 vcpu_id);
void __load_encrypted_vcpu(u32 vmid, u32 vcpu_id);

/*
 * MmioOps
 */
u32 emulate_mmio(u64 addr, u32 htinst);

/*
 * MmioOpsAux
 */
void handle_host_mmio(u32 htinst);
u32 is_plic_range(u64 addr);

/*
 * MmioCore
 */
void handle_plic_write(u64 fault_ipa, u32 len);
void handle_plic_read(u64 fault_ipa, u32 len);

/*
 * MmioCoreAux
 */
void __handle_plic_write(u64 fault_ipa, u32 len);
void __handle_plic_read(u64 fault_ipa, u32 len);

u64 host_get_mmio_data(void);
u64 plic_init_pte(u64 prot, u64 paddr);
u64 plic_get_cbndx(u64 offset);

/*
 * MemHandler
 */
void hs_clear_vm_stage2_range(u32 vmid, u64 start, u64 size);
void hs_riscv_lpae_map(u64 iova, u64 paddr, u64 prot, u32 cbndx, u32 index);
void hs_kvm_phys_addr_ioremap(u32 vmid, u64 gpa, u64 pa, u64 size);

/*
 * MmioSPTOps
 */
void init_spt(u32 cbndx, u32 index);
u64 walk_spt(u32 cbndx, u32 index, u64 addr);
void map_spt(u32 cbndx, u32 index, u64 addr, u64 pte);
u64 unmap_spt(u32 cbndx, u32 index, u64 addr); 

/*
 * Management
 */
void __hs_encrypt_buf(u32 vmid, u64 buf, u64 out_buf);
void __hs_decrypt_buf(u32 vmid, void *buf, u32 len);
extern void decrypt_gp_regs(u32 vmid, u32 vcpu_id);
extern void encrypt_gp_regs(u32 vmid, u32 vcpu_id);
extern void decrypt_sys_regs(u32 vmid, u32 vcpu_id);
extern void encrypt_sys_regs(u32 vmid, u32 vcpu_id);
#endif //HYPSEC_HYPSEC_H
