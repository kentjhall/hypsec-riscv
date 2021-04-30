#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/csr.h>

#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

void __csr_restore_state(struct kvm_vcpu_csr *csr)
{
	csr_write(CSR_VSSTATUS, csr->vsstatus);
	csr_write(CSR_HIE, csr->hie);
	csr_write(CSR_VSTVEC, csr->vstvec);
	csr_write(CSR_VSSCRATCH, csr->vsscratch);
	csr_write(CSR_VSEPC, csr->vsepc);
	csr_write(CSR_VSCAUSE, csr->vscause);
	csr_write(CSR_VSTVAL, csr->vstval);
	csr_write(CSR_HVIP, csr->hvip);
	csr_write(CSR_VSATP, csr->vsatp);
}

void __csr_save_state(struct kvm_vcpu_csr *csr)
{
	csr->vsstatus = csr_read(CSR_VSSTATUS);
	csr->hie = csr_read(CSR_HIE);
	csr->vstvec = csr_read(CSR_VSTVEC);
	csr->vsscratch = csr_read(CSR_VSSCRATCH);
	csr->vsepc = csr_read(CSR_VSEPC);
	csr->vscause = csr_read(CSR_VSCAUSE);
	csr->vstval = csr_read(CSR_VSTVAL);
	csr->hvip = csr_read(CSR_HVIP);
	csr->vsatp = csr_read(CSR_VSATP);
}

void __vm_csr_restore_state_opt(struct shadow_vcpu_context *ctxt)
{
	__csr_restore_state(&ctxt->csr);
}

void __vm_csr_save_state_opt(struct shadow_vcpu_context *ctxt)
{
	__csr_save_state(&ctxt->csr);
}
