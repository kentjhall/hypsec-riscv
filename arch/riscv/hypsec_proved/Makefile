#
# Makefile for host Kernel running with stage 2 translation
#
obj-y += AbstractMachine.o
obj-y += MemBlock.o
obj-y += PageIndex.o
obj-y += PageMgmt.o
obj-y += PTAlloc.o
obj-y += PTWalk.o
obj-y += NPTWalk.o
obj-y += NPTOps.o
obj-y += MemAux.o
obj-y += MemOps.o
obj-y += VMPower.o
obj-y += BootCore.o
obj-y += BootOps.o
obj-y += BootAux.o
obj-y += Helper.o
obj-y += VCPUOpsAux.o
obj-y += VCPUOps.o
obj-y += hs.o
obj-y += csr-sr.o
obj-y += hacl-20/Hacl_Hash.o
obj-y += hacl-20/Hacl_Curve25519_51.o
obj-y += hacl-20/Hacl_Ed25519.o
obj-y += hacl-20/Hacl_AES.o
obj-y += hacl-20/Hacl_Host.o
obj-y += PlicOps.o
obj-y += PlicAux.o
obj-y += PlicCore.o
obj-y += PlicCoreAux.o
obj-y += PlicRaw.o
obj-y += MemHandler.o
obj-y += TrapDispatcher.o
obj-y += FaultHandler.o
obj-y += switch.o
obj-y += host_switch.o
obj-y += vcpu_switch.o

hyp-obj := $(patsubst %.o,%.o,$(obj-y))
obj-y := hyp.o vs.o
extra-y := $(hyp-obj) hyp.lds

# 1) Compile all source files.
$(obj)/%.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/%.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)

# 2) Compile linker script.
$(obj)/hyp.lds: $(src)/hyp.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

# 3) Link all '.o' files and apply the linker script.
LDFLAGS_hyp.o := -r -T
$(obj)/hyp.o: $(obj)/hyp.lds $(addprefix $(obj)/,$(hyp-obj)) FORCE
	$(call if_changed,ld)
