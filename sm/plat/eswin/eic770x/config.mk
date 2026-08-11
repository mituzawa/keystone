# Out-of-tree OpenSBI platform config for the ESWIN EIC770X
# (HiFive Premier P550).
#
# The vendor config.mk (platform/eswin/eic770x/config.mk in the
# eswincomputing/opensbi fork) selects the memory layout from $(chiplet)/
# $(chiplet_die_available) make variables and silently falls back to the
# wrong DIE1 layout when they are unset, so we do not chain-include it.
# Instead the single-die EIC7700X (CHIPLET_1 / DIE0) values are hardcoded
# here, and the matching C macros are passed so that the vendor platform.c
# picks the 4-hart topology.

ifeq ($(KEYSTONE_SM),)
$(error KEYSTONE_SM not defined for SM)
endif

ifeq ($(KEYSTONE_SDK_DIR),)
$(error KEYSTONE_SDK_DIR not defined)
endif

platform-cppflags-y =
platform-cflags-y = -I$(KEYSTONE_SM)/src -I$(KEYSTONE_SDK_DIR)/include/shared
platform-asflags-y =
platform-ldflags-y = -fno-stack-protector

# EIC7700X (HiFive Premier P550): single die (DIE0), 4x P550 harts 0-3.
# The vendor top-level Makefile injects -D$(chiplet) -D$(mem_mode)
# -D$(chiplet_die_available) -D$(platform_cluster_x_core) into CFLAGS/ASFLAGS
# (exported from these variables around Makefile:89); left unset they expand
# to a bare "-D" and every compile fails with "macro names must be
# identifiers". The macros are also read outside the platform dir (e.g.
# lib/sbi/sbi_domain.c), so they must be set globally here and not via
# platform-cflags. BR2_MEMMODE_FLAT is a placeholder identifier: only
# BR2_MEMMODE_INTERLEAVE (dual-chiplet) is ever tested for.
CHIPLET := BR2_CHIPLET_1
MEM_MODE := BR2_MEMMODE_FLAT
CHIPLET_DIE_AVAILABLE := BR2_CHIPLET_1_DIE0_AVAILABLE
PLATFORM_CLUSTER_X_CORE := BR2_CLUSTER_4_CORE

# Same mechanism: -DENABLE_VPU_SDK=$(ENABLE_VPU_SDK) -DENABLE_ECC=$(ENABLE_ECC)
# end up empty-valued when unset, and the sources use "#if (ENABLE_ECC == 1)",
# which does not compile with an empty expansion. The Premier P550 does have
# ECC DDR — revisit ENABLE_ECC=1 during hardware bring-up.
ENABLE_VPU_SDK := 0
ENABLE_ECC := 0

# Blobs to build; the SM lives in [FW_TEXT_START, FW_TEXT_START +
# FW_PAYLOAD_OFFSET) — keep in sync with SMM_BASE/SMM_SIZE in
# sm/src/platform/eswin/eic770x/platform.h
FW_TEXT_START=0x80000000
FW_DYNAMIC=y
FW_JUMP=y
FW_JUMP_ADDR=0x80200000
FW_JUMP_FDT_ADDR=0xf8000000
FW_PAYLOAD=y
FW_PAYLOAD_OFFSET=0x200000
FW_PAYLOAD_FDT_ADDR=0xf8000000
