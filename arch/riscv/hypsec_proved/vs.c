#include <linux/types.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>
#include <asm/hypsec_pgtable.h>
#include <asm/hypsec_virt.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include "hypsec.h"

u64 mach_phys_mem_start;
u64 mach_phys_mem_size;

static unsigned long stage2_mode = (HGATP_MODE_SV39X4 << HGATP_MODE_SHIFT);

//hypsec_host.c
#define Op0(_x) 	.Op0 = _x
#define Op1(_x) 	.Op1 = _x
#define CRn(_x)		.CRn = _x
#define CRm(_x) 	.CRm = _x
#define Op2(_x) 	.Op2 = _x

#define SYS_DESC(reg)					\
	Op0(sys_reg_Op0(reg)), Op1(sys_reg_Op1(reg)),	\
	CRn(sys_reg_CRn(reg)), CRm(sys_reg_CRm(reg)),	\
	Op2(sys_reg_Op2(reg))

static struct s2_sys_reg_desc host_sys_reg_descs[SHADOW_SYS_REGS_DESC_SIZE] = { 0 };
#if 0
static struct s2_sys_reg_desc host_sys_reg_descs[] = {
	/* TTBR0_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b000),
	  TTBR0_EL1, 0x1de7ec7edbadc0deULL },
	/* TTBR1_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b001),
	  TTBR1_EL1, 0x1de7ec7edbadc0deULL },
	/* VBAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1100), CRm(0b0000), Op2(0b000),
	  VBAR_EL1, 0 },
	/* SCTLR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b000),
	  SCTLR_EL1, 0x00C50078 },
	/* ESR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0010), Op2(0b000),
	  ESR_EL1, 0x1de7ec7edbadc0deULL },
	/* FAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0110), CRm(0b0000), Op2(0b000),
	  FAR_EL1, 0x1de7ec7edbadc0deULL },
	/* TPIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1101), CRm(0b0000), Op2(0b100),
	  TPIDR_EL1, 0x1de7ec7edbadc0deULL },
	/* TPIDRRO_EL0 */
	{ Op0(0b11), Op1(0b011), CRn(0b1101), CRm(0b0000), Op2(0b011),
	  TPIDRRO_EL0, 0x1de7ec7edbadc0deULL },
	/* TPIDR_EL0 */
	{ Op0(0b11), Op1(0b011), CRn(0b1101), CRm(0b0000), Op2(0b010),
	  TPIDR_EL0, 0x1de7ec7edbadc0deULL },
	/* CONTEXTIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1101), CRm(0b0000), Op2(0b001),
	  CONTEXTIDR_EL1, 0 },
	/* PAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0111), CRm(0b0100), Op2(0b000),
	  PAR_EL1, 0x1de7ec7edbadc0deULL },
	/* MPIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0000), CRm(0b0000), Op2(0b101),
	  MPIDR_EL1, 0 },
	/* CSSELR_EL1 */
	{ Op0(0b11), Op1(0b010), CRn(0b0000), CRm(0b0000), Op2(0b000),
	  CSSELR_EL1, 0x1de7ec7edbadc0deULL },
	/* ACTLR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b001),
	  ACTLR_EL1, 0 },
	/* CPACR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b010),
	  CPACR_EL1, 0x1de7ec7edbadc0deULL },
	/* TCR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b010),
	  TCR_EL1, 0 },
	/* AFSR0_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0001), Op2(0b000),
	  AFSR0_EL1, 0x1de7ec7edbadc0deULL },
	/* AFSR1_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0001), Op2(0b001),
	  AFSR1_EL1, 0x1de7ec7edbadc0deULL },
	/* MAIR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1010), CRm(0b0010), Op2(0b000),
	  MAIR_EL1, 0x1de7ec7edbadc0deULL },
	/* AMAIR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1010), CRm(0b0011), Op2(0b000),
	  AMAIR_EL1, 0x1de7ec7edbadc0deULL },
	/* CNTKCTL_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1110), CRm(0b0001), Op2(0b000),
	  CNTKCTL_EL1, 0 },
	{ SYS_DESC(SYS_MDSCR_EL1), MDSCR_EL1, 0 },
	{ SYS_DESC(SYS_MDCCINT_EL1), MDCCINT_EL1, 0 },
	{ SYS_DESC(SYS_DISR_EL1), DISR_EL1, 0 },
	/* DACR32_HS */
	{ Op0(0b11), Op1(0b100), CRn(0b0011), CRm(0b0000), Op2(0b000),
	  DACR32_HS, 0x1de7ec7edbadc0deULL },
	/* IFSR32_HS */
	{ Op0(0b11), Op1(0b100), CRn(0b0101), CRm(0b0000), Op2(0b001),
	  IFSR32_HS, 0x1de7ec7edbadc0deULL },
	/* FPEXC32_HS */
	{ Op0(0b11), Op1(0b100), CRn(0b0101), CRm(0b0011), Op2(0b000),
	  FPEXC32_HS, 0x70 }
};
#endif


void hs_shared_data_init(void)
{
	struct hs_shared_data *shared_data;

	shared_data = (void *)kvm_ksym_ref(shared_data_start);
	memset(shared_data, 0, sizeof(struct shared_data));
	printk("[HS] cleared %lx byte data size %lx\n",
		sizeof(struct shared_data), PAGE_SIZE * PAGE_SIZE);
}

#define CORE_PUD_BASE PAGE_SIZE
#define CORE_PMD_BASE (CORE_PUD_BASE + (PAGE_SIZE * 16))
#define CORE_PTE_BASE SZ_2M
#define CORE_PGD_START	(10 * PAGE_SIZE * PAGE_SIZE) 
void init_hs_data_page(void)
{
	int i = 0, index = 0;
	struct hs_data *hs_data;
	struct memblock_region *r;
	u64 pool_start, vmid64, hgatp;
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	WARN_ON(sizeof(struct hs_data) >= CORE_DATA_SIZE);

	printk("[HS] stage2: hs_data struct size %lx reserved core data size %lx\n",
		sizeof(struct hs_data), CORE_DATA_SIZE);


	memset((void *)kvm_ksym_ref(stage2_pgs_start), 0, STAGE2_PAGES_SIZE);
	__flush_dcache_area((void *)kvm_ksym_ref(stage2_pgs_start), STAGE2_PAGES_SIZE);

	hs_data = (void *)kvm_ksym_ref(hs_data_start);
	hs_data->installed = false;

	/* We copied memblock_regions to the HS data structure*/
	for_each_mem_region(r) {
		hs_data->regions[i] = *r;
		if (!(r->flags & MEMBLOCK_NOMAP)) {
			hs_data->s2_memblock_info[i].index = index;
			index += (r->size >> PAGE_SHIFT);
		} else
			hs_data->s2_memblock_info[i].index = S2_PFN_SIZE;
		hs_data->phys_mem_size += hs_data->regions[i].size; 
		i++;
	}
	hs_data->regions_cnt = i;
	hs_data->phys_mem_start = hs_data->regions[0].base;

	smp_wmb();

	mach_phys_mem_start = hs_data->phys_mem_start;
	mach_phys_mem_size = hs_data->phys_mem_size;

	printk("HS system phys mem start %llx end %llx\n",
		hs_data->phys_mem_start, hs_data->phys_mem_size);

	hs_data->used_pages = 0;
	hs_data->used_tmp_pages = 0;
	hs_data->page_pool_start = (u64)__pa(stage2_pgs_start);

	hs_data->s2pages_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	hs_data->abs_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	hs_data->hs_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	hs_data->console_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	hs_data->plic_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	hs_data->spt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	memset(&hs_data->arch, 0, sizeof(struct s2_cpu_arch));

	memset(hs_data->s2_pages, 0, sizeof(struct s2_page) * S2_PFN_SIZE);
	hs_data->ram_start_pfn = hs_data->regions[0].base >> PAGE_SHIFT;

	memset(hs_data->shadow_vcpu_ctxt, 0,
	       sizeof(struct shadow_vcpu_context) * NUM_SHADOW_VCPU_CTXT);
	hs_data->used_shadow_vcpu_ctxt = 0;

	/* This guarantees all locks are initially zero. */
	memset(hs_data->vm_info, 0,
		sizeof(struct hs_vm_info) * HS_VM_INFO_SIZE);
	hs_data->last_remap_ptr = 0;

	pool_start = hs_data->page_pool_start + STAGE2_CORE_PAGES_SIZE + STAGE2_HOST_POOL_SIZE;
	for (i = 1; i < HS_VM_INFO_SIZE - 1; i++) {
		hs_data->vm_info[i].page_pool_start =
			pool_start + (STAGE2_VM_POOL_SIZE * (i - 1));
		hs_data->vm_info[i].pgd_pool =
			hs_data->vm_info[i].page_pool_start + PGD_BASE;
		hs_data->vm_info[i].pud_pool =
			hs_data->vm_info[i].page_pool_start + PUD_BASE;
		hs_data->vm_info[i].pmd_pool =
			hs_data->vm_info[i].page_pool_start + PMD_BASE;
		memset(__va(hs_data->vm_info[i].page_pool_start), 0, STAGE2_VM_POOL_SIZE);

		vmid64 = (u64)i;
		vmid64 = (vmid64 << HGATP_VMID_SHIFT) & HGATP_VMID_MASK;
		hgatp = (hs_data->vm_info[i].page_pool_start >> PAGE_SHIFT) & HGATP_PPN;
		hs_data->vm_info[i].hgatp = (hgatp | vmid64 | stage2_mode);

		hs_data->vm_info[i].shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	}

	hs_data->vm_info[HOSTVISOR].page_pool_start =
		hs_data->page_pool_start + STAGE2_CORE_PAGES_SIZE;
	hs_data->vm_info[HOSTVISOR].pgd_pool =
		hs_data->vm_info[HOSTVISOR].page_pool_start + PGD_BASE;
	hs_data->vm_info[HOSTVISOR].pud_pool =
		hs_data->vm_info[HOSTVISOR].page_pool_start + HOST_PUD_BASE;
	hs_data->vm_info[HOSTVISOR].pmd_pool =
		hs_data->vm_info[HOSTVISOR].page_pool_start + HOST_PMD_BASE;

	hs_data->host_hgatp = (hs_data->vm_info[HOSTVISOR].page_pool_start >> PAGE_SHIFT) & HGATP_PPN;
	hs_data->host_hgatp |= stage2_mode;
	hs_data->vm_info[HOSTVISOR].hgatp = hs_data->host_hgatp;
	hs_data->vm_info[HOSTVISOR].shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	/* CORE POOL -> HOSTVISOR POOL -> VM POOL */
	hs_data->vm_info[COREVISOR].page_pool_start =
		hs_data->page_pool_start + CORE_PGD_START;
	hs_data->vm_info[COREVISOR].pgd_pool =
		hs_data->vm_info[COREVISOR].page_pool_start + CORE_PUD_BASE;
	hs_data->vm_info[COREVISOR].pud_pool =
		hs_data->vm_info[COREVISOR].page_pool_start + CORE_PMD_BASE;
	hs_data->vm_info[COREVISOR].pmd_pool =
		hs_data->vm_info[COREVISOR].page_pool_start + CORE_PTE_BASE;

	hs_data->vm_info[COREVISOR].used_pages = 0;
	hs_data->vm_info[COREVISOR].shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	for (i = 0; i < SHADOW_SYS_REGS_DESC_SIZE; i++)
		hs_data->s2_sys_reg_descs[i] = host_sys_reg_descs[i];

	hs_data->next_vmid = 1;

	/* We init intermediate data structure here. */
	hs_shared_data_init();

	BUG_ON(num_online_cpus() > HYPSEC_MAX_CPUS);
	for (i = 0; i < num_online_cpus(); i++) {
		hs_data->per_cpu_data[i].vmid = 0;
		hs_data->per_cpu_data[i].vcpu_id = i;
	}

	hs_data->core_start = __pa_symbol(stage2_pgs_start);
	hs_data->core_end = __pa_symbol(hs_data_end);

#if 0 // TEMPORARY
	init_hacl_hash(hs_data);
#endif
	//test_aes(hs_data);

	memcpy(hs_data->key, key, 16);
	memcpy(hs_data->iv, iv, 16);

	return;
}

void init_hypsec_io(void)
{
	int i = 0, err;
	struct hs_data *hs_data;
	struct hs_riscv_plic_device *plic;

	hs_data = (void *)kvm_ksym_ref(hs_data_start);

#ifdef CONFIG_SERIAL_8250_CONSOLE
	//TODO: Hacky stuff for prints on m400
	err = create_hypsec_io_mappings((phys_addr_t)0x1c021000,
					 PAGE_SIZE,
					 &hs_data->uart_8250_base);
	if (err) {
		kvm_err("Cannot map uart 8250\n");
		goto out_err;
	}
#endif

	err = create_hypsec_io_mappings((phys_addr_t)hs_data->pl011_base,
					 PAGE_SIZE,
					 &hs_data->pl011_base);
	if (err) {
		kvm_err("Cannot map pl011\n");
		goto out_err;
	}

	plic = &hs_data->plic;
	err = create_hypsec_io_mappings(plic->phys_base, plic->size,
					&plic->hyp_base);
	if (err) {
		kvm_err("Cannot map plic %d from %llx\n", i, plic->phys_base);
		goto out_err;
	}

out_err:
	return;
}

//hypsec_mmu.c
phys_addr_t host_alloc_stage2_page(unsigned int num)
{
	u64 p_addr, start, unaligned, append, used_pages;
	struct hs_data *hs_data;

	if (!num)
		return 0;

	hs_data = kvm_ksym_ref(hs_data_start);
	stage2_spin_lock(&hs_data->abs_lock);

	/* Check if we're out of memory in the reserved area */
	BUG_ON(hs_data->vm_info[COREVISOR].used_pages >= (CORE_PGD_START >> PAGE_SHIFT));

	/* Start allocating memory from the normal page pool */
	//start = hs_data->vm_info[COREVISOR].page_pool_start;
	start = hs_data->page_pool_start;
	used_pages = hs_data->vm_info[COREVISOR].used_pages;
	p_addr = (u64)start + (PAGE_SIZE * used_pages);

	unaligned = p_addr % (PAGE_SIZE * num);
	/* Append to make p_addr aligned with (PAGE_SIZE * num) */
	if (unaligned) {
		append = num - (unaligned >> PAGE_SHIFT);
		p_addr += append * PAGE_SIZE;
		num += append;
	}

	hs_data->vm_info[COREVISOR].used_pages += num;

	stage2_spin_unlock(&hs_data->abs_lock);
	return (phys_addr_t)p_addr;
}

phys_addr_t host_alloc_pgd(unsigned int num)
{
	u64 p_addr;
	struct hs_data *hs_data;

	hs_data = kvm_ksym_ref(hs_data_start);
	stage2_spin_lock(&hs_data->abs_lock);	
	p_addr = hs_data->vm_info[COREVISOR].page_pool_start;
	stage2_spin_unlock(&hs_data->abs_lock);

	return (phys_addr_t)p_addr;
}

phys_addr_t host_alloc_pud(unsigned int num)
{
	u64 p_addr, start;
	struct hs_data *hs_data;

	hs_data = kvm_ksym_ref(hs_data_start);
	stage2_spin_lock(&hs_data->abs_lock);

	start = hs_data->vm_info[COREVISOR].page_pool_start;
	p_addr = hs_data->vm_info[COREVISOR].pgd_pool;
	smp_wmb();
	hs_data->vm_info[COREVISOR].pgd_pool += PAGE_SIZE;

	stage2_spin_unlock(&hs_data->abs_lock);
	if (p_addr >= (start + CORE_PMD_BASE)) {
		printk("BUG: pud [start %lx paddr %lx pud_pool_end %lx\n",
			(unsigned long)hs_data->vm_info[COREVISOR].page_pool_start,
			(unsigned long)p_addr, (unsigned long)(start + CORE_PMD_BASE)
			);
		BUG();
	}

	return (phys_addr_t)p_addr;
}


phys_addr_t host_alloc_pmd(unsigned int num)
{
	u64 p_addr, start;
	struct hs_data *hs_data;

	hs_data = kvm_ksym_ref(hs_data_start);
	stage2_spin_lock(&hs_data->abs_lock);

	start = hs_data->vm_info[COREVISOR].page_pool_start;
	p_addr = hs_data->vm_info[COREVISOR].pud_pool;
	smp_wmb();
	hs_data->vm_info[COREVISOR].pud_pool += PAGE_SIZE;

	stage2_spin_unlock(&hs_data->abs_lock);
	if (p_addr >= (start + CORE_PTE_BASE)) {
		printk("BUG: pmd [start %lx paddr %lx pmd_pool_end %lx\n",
			(unsigned long)hs_data->vm_info[COREVISOR].page_pool_start,
			(unsigned long)p_addr, (unsigned long)(start + CORE_PTE_BASE)
			);
		BUG();
	}

	return (phys_addr_t)p_addr;
}

phys_addr_t host_alloc_pte(unsigned int num)
{
	u64 p_addr, start;
	struct hs_data *hs_data;

	hs_data = kvm_ksym_ref(hs_data_start);
	stage2_spin_lock(&hs_data->abs_lock);

	start = hs_data->vm_info[COREVISOR].page_pool_start;
	p_addr = hs_data->vm_info[COREVISOR].pmd_pool;
	smp_wmb();
	hs_data->vm_info[COREVISOR].pmd_pool += PAGE_SIZE;

	stage2_spin_unlock(&hs_data->abs_lock);
	if (p_addr >= hs_data->host_hgatp) {
		printk("BUG: pte [start %lx paddr %lx host_hgatp %lx\n",
			(unsigned long)hs_data->vm_info[COREVISOR].page_pool_start,
			(unsigned long)p_addr, (unsigned long)hs_data->host_hgatp
			);
		BUG();
	}	

	return (phys_addr_t)p_addr;
}

struct kvm* hypsec_alloc_vm(u32 vmid)
{
	struct shared_data *shared_data;
	shared_data = kvm_ksym_ref(shared_data_start);
	if (vmid >= HS_MAX_VMID)
		BUG();
	return &shared_data->kvm_pool[vmid];
}

struct kvm_vcpu* hypsec_alloc_vcpu(u32 vmid, int vcpu_id)
{
	struct shared_data *shared_data;
	int index;
	shared_data = kvm_ksym_ref(shared_data_start);
	if (vmid >= HS_MAX_VMID || vcpu_id >= HYPSEC_MAX_VCPUS)
		BUG();
	index = (vmid * HYPSEC_MAX_VCPUS) + vcpu_id;
	return &shared_data->vcpu_pool[index];
}

int hs_set_boot_info(u32 vmid, unsigned long load_addr,
			unsigned long size, int type)
{
	return kvm_call_core(HVC_SET_BOOT_INFO, vmid, load_addr, size, type);
}

int hs_remap_vm_image(u32 vmid, unsigned long pfn, int id)
{
	return kvm_call_core(HVC_REMAP_VM_IMAGE, vmid, pfn, id);
}

int hs_verify_and_load_images(u32 vmid)
{
	return kvm_call_core(HVC_VERIFY_VM_IMAGES, vmid);
}

void hs_boot_from_inc_exe(u32 vmid)
{
	kvm_call_core(HVC_BOOT_FROM_SAVED_VM, vmid);
}

void save_encrypted_vcpu(struct kvm_vcpu *vcpu)
{
	kvm_call_core(HVC_SAVE_CRYPT_VCPU,
			vcpu->kvm->arch.vmid.vmid, vcpu->vcpu_id);
}

void load_encrypted_vcpu(u32 vmid, u32 vcpu_id)
{
	kvm_call_core(HVC_LOAD_CRYPT_VCPU, vmid, vcpu_id);
}

void clear_vm_stage2_range(u32 vmid, phys_addr_t start, u64 size)
{
	kvm_call_core(HVC_CLEAR_VM_S2_RANGE, vmid, start, size);
}

//void hs_encrypt_buf(u32 vmid, void *buf, uint32_t len)
void hs_encrypt_buf(u32 vmid, u64 buf, u64 out_buf)
{
	kvm_call_core(HVC_ENCRYPT_BUF, vmid, buf, out_buf);
}

void hs_decrypt_buf(u32 vmid, void *buf, uint32_t len)
{
	kvm_call_core(HVC_DECRYPT_BUF, vmid, (uintptr_t)buf, len);
}

int hypsec_register_kvm(void)
{
	return kvm_call_core(HVC_REGISTER_KVM);
}

int hypsec_register_vcpu(u32 vmid, int vcpu_id)
{
	return kvm_call_core(HVC_REGISTER_VCPU, vmid, vcpu_id);
}
