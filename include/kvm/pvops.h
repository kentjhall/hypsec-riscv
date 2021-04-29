#ifndef __KVM_PVOPS_H__
#define __KVM_PVOPS_H__

#include <asm/kvm_host.h>

#define kvm_pvops(...) kvm_call_core(__VA_ARGS__)

#define KVM_SET_DESC_PFN 0x81000
#define KVM_UNSET_DESC_PFN 0x82000
#define KVM_SET_BALLOON_PFN 0x83000

#endif /* __KVM_PVOPS_H__ */
