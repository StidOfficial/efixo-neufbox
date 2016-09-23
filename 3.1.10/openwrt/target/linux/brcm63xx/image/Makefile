# 
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

LOADADDR = 0x80010000		# RAM start + CFE SIZE 
KERNEL_ENTRY = $(LOADADDR)	# Newer kernels add a jmp to the kernel_entry at the start of the binary
RAMSIZE = 0x01000000		# 64MB

ifeq ($(CONFIG_TARGET_brcm63xx_nb4_rescue),y) 
FIRMWARE_OFFSET = "-n 0x600000"
endif
ifeq ($(CONFIG_TARGET_brcm63xx_nb6_rescue),y) 
FIRMWARE_OFFSET = "-n 0xE00000"
endif
BLOCKSIZE="-k 4"

define Image/Build/CFE
	# Generate the tagged image
	$(STAGING_DIR_HOST)/bin/imagetag -i $(KDIR)/vmlinux.lzma.cfe -f $(KDIR)/root.$(1) \
		-o $(BIN_DIR)/openwrt-$(4)-$(1)-cfe.bin \
		-b $(2) -c $(3) -e $(LOADADDR) -l $(LOADADDR) \
		$(FIRMWARE_OFFSET) $(BLOCKSIZE) \
	        -r "$(5)" $(6)
#		-b $(2) -c $(3) -e $(KERNEL_ENTRY) -l $(LOADADDR)

endef

define Image/Prepare
	# Standard LZMA kernel
	cat $(KDIR)/vmlinux | $(STAGING_DIR_HOST)/bin/lzma e -si -so -eos -lc1 -lp2 -pb2 > $(KDIR)/vmlinux.lzma

	# CFE is a LZMA nazi! It took me hours to find out the parameters!
	# Also I think lzma has a bug cause it generates different output depending on
	# if you use stdin / stdout or not. Use files instead of stdio here, cause
	# otherwise CFE will complain and not boot the image.
	$(STAGING_DIR_HOST)/bin/lzma e -d22 -fb64 -a1 $(KDIR)/vmlinux $(KDIR)/vmlinux.lzma.tmp

	# Strip out the length, CFE doesn't like this
	dd if=$(KDIR)/vmlinux.lzma.tmp of=$(KDIR)/vmlinux.lzma.cfe bs=5 count=1
	dd if=$(KDIR)/vmlinux.lzma.tmp of=$(KDIR)/vmlinux.lzma.cfe ibs=13 obs=5 skip=1 seek=1 conv=notrunc
	rm -f $(KDIR)/vmlinux.lzma.tmp

	rm -f $(KDIR)/fs_mark
	touch $(KDIR)/fs_mark
	$(call prepare_generic_squashfs,$(KDIR)/fs_mark)
endef

define Image/Build
	cp $(KDIR)/vmlinux.elf $(BIN_DIR)/openwrt-$(BOARD)-vmlinux.elf
	dd if=$(KDIR)/root.$(1) of=$(BIN_DIR)/openwrt-$(BOARD)-root.$(1) bs=128k conv=sync
	dd if=$(KDIR)/root.$(1) of=$(BIN_DIR)/$(IMG_PREFIX)-root.$(1) bs=128k conv=sync
	# neufbox
	$(call Image/Build/CFE,$(1),96358VW,6358,NEUFBOX4,OpenWRT-$(REVISION))
	$(call Image/Build/CFE,$(1),96358VW,6358,nb4,$(CONFIG_FIRMWARE_RELEASE))
	$(call Image/Build/CFE,$(1),NB6-FXC-r0,6362,nb6,$(CONFIG_FIRMWARE_RELEASE))
endef

define Image/Build/Initramfs
	touch $(KDIR)/root.initramfs
	$(STAGING_DIR_HOST)/bin/lzma e -d22 -fb64 -a1 $(KDIR)/vmlinux $(KDIR)/vmlinux.lzma.tmp
	# Strip out the length, CFE doesn't like this
	dd if=$(KDIR)/vmlinux.lzma.tmp of=$(KDIR)/vmlinux.lzma.cfe bs=5 count=1
	dd if=$(KDIR)/vmlinux.lzma.tmp of=$(KDIR)/vmlinux.lzma.cfe ibs=13 obs=5 skip=1 seek=1 conv=notrunc
	rm -f $(KDIR)/vmlinux.lzma.tmp
	$(call Image/Build/CFE,initramfs,96358VW,6358,nb4,$(CONFIG_FIRMWARE_RELEASE))
	$(call Image/Build/CFE,initramfs,NB6-FXC-r0,6362,nb6,$(CONFIG_FIRMWARE_RELEASE))
endef

$(eval $(call BuildImage))
