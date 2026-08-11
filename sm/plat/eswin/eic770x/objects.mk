# Pull in the vendor in-tree platform objects (platform.o, eic770x_uart.o,
# eic770x_dram.o, eic770x_mailbox.o); their sources are compiled from
# $(src_dir) by OpenSBI's build rules even though the platform dir is
# out-of-tree.
include $(src_dir)/platform/$(PLATFORM)/objects.mk

# And then also define custom keystone SM functionality
ifeq ($(PLATFORM),)
$(error PLATFORM not defined for SM)
endif

platform-genflags-y += "-DTARGET_PLATFORM_HEADER=\"platform/$(PLATFORM)/platform.h\""

include $(KEYSTONE_SM)/src/objects.mk
# this platform dir is three levels below sm/, cf. sm/plat/fpga/ariane
platform-objs-y += $(addprefix ../../../src/,$(subst .c,.o,$(keystone-sm-sources)))
