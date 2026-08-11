#########################
## Flush SD card image ##
#########################

# The image holds a single GPT rootfs partition (partition 1); the firmware
# (bootchain with fw_payload.bin) is flashed to QSPI separately.

DEVICE      ?=
EXTEND      ?= 0
FLUSH_IMAGE ?= $(BUILDROOT_BUILDDIR)/images/sdcard.img

flush:
ifeq ($(DEVICE),)
	$(call log,error,Set target device to env DEVICE)
else
	$(call log,info,Flushing SD image)
	sudo dd if=$(FLUSH_IMAGE) of=$(DEVICE) bs=64k iflag=fullblock oflag=direct conv=fsync status=progress

ifeq ($(EXTEND),1)
	$(call log,info,Extending rootfs end of the block device)
	echo "w" | sudo fdisk $(DEVICE)
	echo "- +" | sudo sfdisk -N 1 $(DEVICE)
	sudo e2fsck -f $(DEVICE)1
	sudo resize2fs $(DEVICE)1
endif

endif
