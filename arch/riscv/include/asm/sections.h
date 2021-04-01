/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */
#ifndef __ASM_SECTIONS_H
#define __ASM_SECTIONS_H

#include <asm-generic/sections.h>

extern char _start[];
extern char _start_kernel[];
extern char __init_data_begin[], __init_data_end[];
extern char __init_text_begin[], __init_text_end[];
#ifdef CONFIG_VERIFIED_KVM
extern char stage2_pgs_start[];
extern char stage2_pgs_end[];
extern char hs_data_start[];
extern char hs_data_end[];
extern char shared_data_start[];
extern char shared_data_end[];
extern char stage2_tmp_pgs_start[];
extern char stage2_tmp_pgs_end[];
extern char smmu_pgs_start[];
extern char smmu_pgs_end[];
#endif

#endif /* __ASM_SECTIONS_H */
