// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kvm_host.h>

#ifdef CONFIG_VERIFIED_KVM
#include <asm/hypsec_missing.h>
#include <asm/hypsec_host.h>
#endif


int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
#ifdef CONFIG_VERIFIED_KVM
	int cpu;

	kvm->arch.last_vcpu_ran = alloc_percpu(typeof(*kvm->arch.last_vcpu_ran));
	if (!kvm->arch.last_vcpu_ran) {
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu)
		*per_cpu_ptr(kvm->arch.last_vcpu_ran, cpu) = -1;
#else
	int r;

	r = kvm_riscv_stage2_alloc_pgd(kvm);
	if (r)
		return r;

	r = kvm_riscv_stage2_vmid_init(kvm);
	if (r) {
		kvm_riscv_stage2_free_pgd(kvm);
		return r;
	}
#endif

	return kvm_riscv_guest_timer_init(kvm);
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (kvm->vcpus[i]) {
			kvm_arch_vcpu_destroy(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_DEVICE_CTRL:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_IMMEDIATE_EXIT:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = num_online_cpus();
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	default:
		r = 0;
		break;
	}

	return r;
}

long kvm_arch_vm_ioctl(struct file *filp,
		       unsigned int ioctl, unsigned long arg)
{
#ifdef CONFIG_VERIFIED_KVM
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;

	switch (ioctl) {
		case KVM_RISCV_SET_BOOT_INFO: {
			struct kvm_boot_info info;
			struct page *page[1];
			long npages;
			int id;
			unsigned long start, end, virt_addr, curr_pfn;
			unsigned long prev_pfn = 0;
			int is_aligned;

			if (copy_from_user(&info, argp, sizeof(info)))
				return -EFAULT;

			start = (unsigned long)info.data;
			end = start + info.datasize;

			id = hs_set_boot_info(kvm->arch.vmid.vmid, info.addr, info.datasize, 0);
			for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
				npages = get_user_pages(virt_addr, 1, FOLL_WRITE, page, NULL);
				curr_pfn = page_to_pfn(page[0]);
				is_aligned = IS_ALIGNED(curr_pfn << PAGE_SHIFT, 1<<PMD_SHIFT);
				/*
				 * We're mapping 2MB huge pages in unmap_and_load_vm_image (corevisor),
				 * so the physmem backing the kernel image must be either 2MB aligned
				 * or contiguous with a 2MB aligned page in the kernel image.
				 */
				if (unlikely(prev_pfn == 0 && !is_aligned)) {
					pr_err("set_boot_info: first phys page is not 2MB aligned 0x%lx\n",
							curr_pfn << PAGE_SHIFT);
					return -EINVAL;
				} else if (unlikely(curr_pfn - prev_pfn != 1 && !is_aligned)) {
					pr_err("set_boot_info: non-contiguous unaligned phys page: 0x%lx, 0x%lx\n",
							prev_pfn, curr_pfn);
					return -EINVAL;
				}
				prev_pfn = curr_pfn;

				if (npages == 1)
					hs_remap_vm_image(kvm->arch.vmid.vmid, curr_pfn, id);
				else
					return -EFAULT;
			}
			return 0;
		}
		case KVM_RISCV_RESUME_INC_EXE:
			kvm->arch.resume_inc_exe = true;
			return 0;
		case KVM_RISCV_ENCRYPT_BUF: {
			struct page *page[1];
			int npages;
			struct kvm_user_encrypt kue;
			unsigned long out;

			if (copy_from_user(&kue, argp, sizeof(kue))) {
				printk("ENCRYPT_BUF: can't copy from user\n");
				return -EFAULT;
			}

			out = get_zeroed_page(GFP_KERNEL);
			if (!out) {
				printk("ENCRYPT_BUF: can't get zero page\n");
				return -ENOMEM;
			}

			npages = get_user_pages_fast_only(kue.uva, 1, FOLL_WRITE, page);
			if (npages == 1) {
				hs_encrypt_buf(kvm->arch.vmid.vmid,
					(u64) (page_to_pfn(page[0]) << PAGE_SHIFT),
					(u64) __pa(out));
			} else {
				//printk("ENCRYPT_BUF: cant get user pages %lx\n", (unsigned long)kue.uva);
				free_page(out);
				return 0;
				//return -EFAULT;
			}

			if(copy_to_user((void*)kue.out_uva, (void*)out, PAGE_SIZE)) {
				printk("ENCRYPT_BUF: cannt copy to user\n");
				return -EFAULT;
			}
			free_page(out);
			return 0;
		}
		case KVM_RISCV_DECRYPT_BUF: {
			struct page *page[1];
			int npages;

			npages = get_user_pages_fast_only(arg, 1, FOLL_WRITE, page);
			if (npages == 1)
				hs_decrypt_buf(kvm->arch.vmid.vmid,
					(void *)(page_to_pfn(page[0]) << PAGE_SHIFT), PAGE_SIZE);
			else
				return -EFAULT;

			return 0;
		}
		case KVM_RISCV_GET_VMID:
			return kvm->arch.vmid.vmid;
		case KVM_RISCV_IS_ZERO_PAGE: {
			struct page *page[1];
			int npages;

			npages = get_user_pages_fast_only(arg, 1, FOLL_WRITE, page);
			if (npages == 1) {
				return 0;
			} else {
				printk("IS_ZERO_PAGE %lx\n", (unsigned long)arg);
				return 2;
			}
		}
		default:
			return -EINVAL;
	}
#else
	return -EINVAL;
#endif

}
