#include "hypsec.h"
#include "hacl-20/Hacl_Ed25519.h"
#include "hacl-20/Hacl_AES.h"

void clear_phys_mem(u64 pfn) {
    hs_memset((void *)kern_hyp_va(pfn << PAGE_SHIFT), 0, PAGE_SIZE);
}

u64 get_exception_vector(u64 pstate) {
    // TODO
	return 0;
}

uint8_t* get_vm_public_key(u32 vmid) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->vm_info[vmid].public_key;
}

void set_vm_public_key(u32 vmid) {
    unsigned char *public_key_hex = "2ef2440a2b5766436353d07705b602bfab55526831460acb94798241f2104f3a";
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_hex2bin(hs_data->vm_info[vmid].public_key, public_key_hex, 32);
}

uint8_t* get_vm_load_signature(u32 vmid, u32 load_idx) {
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    return hs_data->vm_info[vmid].load_info[load_idx].signature;
}

void set_vm_load_signature(u32 vmid, u32 load_idx) {
    unsigned char *signature_hex = "35e9848eb618e7150566716662b2f7d8944f0a4e8582ddeb2b209d2bae6b63d5f51ebf1dc54742227e45f7bbb9d4ba1d1f83b52b87a4ce99180aa9a548e7dd05";
    struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
    hs_hex2bin(hs_data->vm_info[vmid].load_info[load_idx].signature,
		signature_hex, 64);
}

//make sure we only use get_int_ctxt to access general purposes regs
void clear_shadow_gp_regs(u32 vmid, u32 vcpuid) {
	struct hs_data *hs_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	hs_memset(&hs_data->shadow_vcpu_ctxt[offset].ctxt, 0, sizeof(struct kvm_cpu_context));
}

void int_to_shadow_fp_regs(u32 vmid, u32 vcpuid) {

}

void clear_phys_page(unsigned long pfn)
{
	u64 addr = (u64)__hs_va(pfn << PAGE_SHIFT);
	hs_memset((void *)addr, 0, PAGE_SIZE);
}

u32 verify_image(u32 vmid, u32 load_idx, u64 addr) {
    uint8_t* signature;
    uint8_t* public_key;
    int result = 0;
    u64 size;

    size = get_vm_load_size(vmid, load_idx);
    public_key = get_vm_public_key(vmid);
    signature = get_vm_load_signature(vmid, load_idx);
    print_string("\rverifying image:\n");
    //printhex_ul(size);
    result = Hacl_Ed25519_verify(public_key, size, (uint8_t *)addr, signature);
    //result = Hacl_Ed25519_verify(key, size, (char *)addr, signature1);
    print_string("\r[result]\n");
    printhex_ul(result);
    return 1;
}

void dump_output(char *str, uint8_t *out, int len)
{
	int i;
	unsigned s = 0;
	printk("%s\n", str);
	for (i = 0; i < len; i++) {
		s = out[i];
		printk("%x", s);
	}
	printk("\n");
}

void dump_output_hs(uint8_t *out, int len)
{
	int i;
	unsigned long s = 0;
	for (i = 0; i < len; i++) {
		s = out[i];
		printhex_ul(s);
	}
}

void test_aes(struct hs_data *hs_data)
{
	uint8_t sbox[256];
	uint8_t input[32] = { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
	uint8_t out[32], out1[32];

	hs_memset(out, 0, sizeof(uint8_t) * 32);
	hs_memset(out1, 0, sizeof(uint8_t) * 32);
	//dump_output_hs(input, 16);
	dump_output("plain", input, 32);
	AES_encrypt_buffer(out, input, hs_data->key, 32);
	//dump_output_hs(out, 16);
	dump_output("crypt", out, 32);

	hs_memset(sbox, 0, sizeof(uint8_t) * 32);
	AES_decrypt_buffer(out1, out, hs_data->key, 32);
	//dump_output_hs(out1, 16);
	dump_output("decrypt", out1, 32);
}

void encrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	AES_encrypt_buffer((uint8_t*)out_buf, (uint8_t*)in_buf, hs_data->key, len); 
}

void decrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len)
{
        struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	AES_decrypt_buffer((uint8_t*)out_buf, (uint8_t*)in_buf, hs_data->key, len);
}

#if 0
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
#endif

//MMIOOps
u32 get_iommu_cfg_vmid(u32 cbndx, u32 num)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u32 index;
	index = IOMMU_NUM_CTXT_BANKS * num + cbndx;
	return hs_data->iommu_cfg[index].vmid;
}

void set_iommu_cfg_vmid(u32 cbndx, u32 num, u32 vmid)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u32 index;
	index = IOMMU_NUM_CTXT_BANKS * num + cbndx;
	hs_data->iommu_cfg[index].vmid = vmid;
}

u64 get_iommu_cfg_hw_ttbr(u32 cbndx, u32 num)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u32 index;
	index = IOMMU_NUM_CTXT_BANKS * num + cbndx;
	return hs_data->iommu_cfg[index].hw_ttbr;
}

void set_iommu_cfg_hw_ttbr(u32 cbndx, u32 num, u64 hw_ttbr)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u32 index;
	index = IOMMU_NUM_CTXT_BANKS * num + cbndx;
	hs_data->iommu_cfg[index].hw_ttbr = hw_ttbr;
}

//MMIOAux
u32 get_iommu_num(void)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->hs_iommu_num;
}	

u32 get_iommu_num_context_banks(u32 num)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->iommus[num].num_context_banks;
}

u32 get_iommu_pgshift(u32 num)
{
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	return hs_data->iommus[num].pgshift;
}

void iommu_pt_clear(u32 cbndx, u32 num) {
	struct hs_data *hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	u32 index;
	u64 va;
	index = IOMMU_NUM_CTXT_BANKS * num + cbndx;
	va = (u64)__hs_va(hs_data->iommu_cfg[index].hw_ttbr); 
	hs_memset((void *)va, 0, PAGE_SIZE * 2);
};

void reset_fp_regs(u32 vmid, int vcpu_id)
{
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	struct kvm_vcpu *vcpu = vcpu;
	struct kvm_cpu_context *kvm_cpu_context;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	kvm_cpu_context = &vcpu->arch.guest_context;
	hs_memcpy(&shadow_ctxt->ctxt.fp, &kvm_cpu_context->fp,
					sizeof(union __riscv_fp_state));
}

//Management

static void encrypt_kvm_cpu_context(u32 vmid,
		struct kvm_cpu_context *kvm_cpu_context)
{
	union __riscv_fp_state fpsimd;
	__u64 out_gpr[35];

	//old_encrypt_buf(vmid, regs, sizeof(__u64) * 32);
	encrypt_buf(vmid, (u64)kvm_cpu_context, (u64)out_gpr, sizeof(__u64) * 35);
	hs_memcpy(kvm_cpu_context, out_gpr, sizeof(__u64) * 35);

	encrypt_buf(vmid, (u64)&kvm_cpu_context->fp, (u64)&fpsimd, sizeof(union __riscv_fp_state));
	hs_memcpy(&kvm_cpu_context->fp, &fpsimd, sizeof(union __riscv_fp_state));
	//old_encrypt_buf(vmid, &kvm_cpu_context->fp_regs, sizeof(union __riscv_fp_state));
}

static void decrypt_kvm_cpu_context(u32 vmid, struct kvm_cpu_context *kvm_cpu_context)
{
	union __riscv_fp_state fpsimd;
	__u64 out_gpr[32];

	// sizeof(regs[31] + sp + pc), all in __u64
	decrypt_buf(vmid, (u64)kvm_cpu_context, (u64)out_gpr, sizeof(__u64) * 35);
	hs_memcpy(kvm_cpu_context, out_gpr, sizeof(__u64) * 35);
	//old_decrypt_buf(vmid, regs, sizeof(__u64) * 32);

	decrypt_buf(vmid, (u64)&kvm_cpu_context->fp, (u64)&fpsimd, sizeof(union __riscv_fp_state));
	hs_memcpy(&kvm_cpu_context->fp, &fpsimd, sizeof(union __riscv_fp_state));
	//old_decrypt_buf(vmid, &kvm_cpu_context->fp_regs, sizeof(union __riscv_fp_state));
}

#define SHADOW_SYS_REGS_LEN 	8 * (SHADOW_SYS_REGS_SIZE)
void encrypt_gp_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	struct kvm_cpu_context gp_local;
	int i;
	uint64_t *p;
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	hs_memcpy(&gp_local, &shadow_ctxt->ctxt, sizeof(struct kvm_cpu_context));
	encrypt_kvm_cpu_context(vmid, &gp_local);
	//gp_local.regs.pstate = shadow_ctxt->regs[V_PSTATE];
	//gp_local.regs.pstate = shadow_ctxt->gp_regs.regs.pstate;
	hs_memcpy(&vcpu->arch.guest_context, &gp_local, sizeof(struct kvm_cpu_context));
	/* for (i = 0; i < 31; i++) */
	/* 	printhex_ul(shadow_ctxt->gp_regs.regs.regs[i]); */
	/* printhex_ul(shadow_ctxt->gp_regs.regs.sp); */
	/* printhex_ul(shadow_ctxt->gp_regs.regs.pc); */
	/* printhex_ul(shadow_ctxt->gp_regs.regs.pstate); */
	/* printhex_ul(shadow_ctxt->gp_regs.sp_el1); */
	/* printhex_ul(shadow_ctxt->gp_regs.elr_el1); */
	/* for (i = 0; i < 5; i++) */
	/* 	printhex_ul(shadow_ctxt->gp_regs.spsr[i]); */
	/* p = (uint64_t *)&vcpu->arch.ctxt.gp_regs.fp_regs; */
	/* for (i = 0; i < 66; i++) */
	/* 	printhex_ul(*p++); */
}

void decrypt_gp_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	struct kvm_cpu_context gp_local;
	int i;
	uint64_t *p;
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	hs_memcpy(&gp_local, &vcpu->arch.guest_context, sizeof(struct kvm_cpu_context));
	decrypt_kvm_cpu_context(vmid, &gp_local);
	//gp_local.regs.pstate = vcpu->arch.ctxt.gp_regs.regs.pstate;
	hs_memcpy(&shadow_ctxt->ctxt, &gp_local, sizeof(struct kvm_cpu_context));
	hs_memset(&vcpu->arch.guest_context, 0, sizeof(struct kvm_cpu_context));
	/* for (i = 0; i < 31; i++) */
	/* 	printhex_ul(shadow_ctxt->gp_regs.regs.regs[i]); */
	/* printhex_ul(shadow_ctxt->gp_regs.regs.sp); */
	/* printhex_ul(shadow_ctxt->gp_regs.regs.pc); */
	/* printhex_ul(shadow_ctxt->gp_regs.regs.pstate); */
	/* printhex_ul(shadow_ctxt->gp_regs.sp_el1); */
	/* printhex_ul(shadow_ctxt->gp_regs.elr_el1); */
	/* for (i = 0; i < 5; i++) */
	/* 	printhex_ul(shadow_ctxt->gp_regs.spsr[i]); */

	/* p = (uint64_t *)&shadow_ctxt->gp_regs.fp_regs; */
	/* for (i = 0; i < 66; i++) */
	/* 	printhex_ul(*p++); */
}

void encrypt_sys_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	int i;
	u64 sr_local[SHADOW_SYS_REGS_SIZE + 1];
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	encrypt_buf(vmid, (u64)&shadow_ctxt->csr, (u64)sr_local, SHADOW_SYS_REGS_LEN);
	hs_memcpy(&vcpu->arch.guest_csr, sr_local, SHADOW_SYS_REGS_LEN);
	//hs_memcpy(&vcpu->arch.ctxt.sys_regs, &shadow_ctxt->sys_regs, SHADOW_SYS_REGS_LEN);
	for (i = 0; i < SHADOW_SYS_REGS_SIZE + 1; i++) {
		//printhex_ul(vcpu->arch.ctxt.sys_regs[i]);
		//printhex_ul(shadow_ctxt->sys_regs[i]);
	}
}

void decrypt_sys_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	u64 sr_local[SHADOW_SYS_REGS_SIZE + 1];
	int i;
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	decrypt_buf(vmid, (u64)&vcpu->arch.guest_csr, (u64)sr_local, SHADOW_SYS_REGS_LEN);
	hs_memcpy(&shadow_ctxt->csr, sr_local, SHADOW_SYS_REGS_LEN);
	//hs_memcpy(&shadow_ctxt->sys_regs, &vcpu->arch.ctxt.sys_regs, SHADOW_SYS_REGS_LEN);
	for (i = 0; i < SHADOW_SYS_REGS_SIZE + 1; i++) {
		//printhex_ul(vcpu->arch.ctxt.sys_regs[i]);
		//printhex_ul(shadow_ctxt->sys_regs[i]);
	}
	hs_memset(&vcpu->arch.guest_csr, 0, SHADOW_SYS_REGS_LEN);
}
