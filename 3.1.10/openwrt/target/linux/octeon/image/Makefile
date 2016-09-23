#
# Copyright (C) 2009-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

ifeq ($(CONFIG_TARGET_octeon_nb5_main)$(CONFIG_TARGET_octeon_nb5_rescue)$(CONFIG_TARGET_octeon_nb5_refurbishing),)
define Image/BuildKernel
	# Workaround pre-SDK-1.9.0 u-boot versions not handling the .notes section
	$(TARGET_CROSS)strip -R .notes $(KDIR)/vmlinux.elf -o $(BIN_DIR)/$(IMG_PREFIX)-vmlinux.elf
	$(STAGING_DIR_HOST)/bin/lzma e $(KDIR)/vmlinux $(KDIR)/vmlinux.bin.l7
	dd if=$(KDIR)/vmlinux.bin.l7 of=$(BIN_DIR)/$(IMG_PREFIX)-vmlinux.lzma bs=65536 conv=sync
endef

define Image/Build/squashfs
    $(call prepare_generic_squashfs,$(KDIR)/root.squashfs)
endef

define Image/Build
	$(call Image/Build/$(1))
	dd if=$(KDIR)/root.$(1) of=$(BIN_DIR)/$(IMG_PREFIX)-root.$(1) bs=128k conv=sync
endef
else
define Image/Build/Initramfs
	# Workaround pre-SDK-1.9.0 u-boot versions not handling the .notes section
	$(TARGET_CROSS)strip -R .notes $(KDIR)/vmlinux.elf -o $(BIN_DIR)/$(IMG_PREFIX)-vmlinux.elf
	$(STAGING_DIR_HOST)/bin/lzma e $(KDIR)/vmlinux.elf $(KDIR)/vmlinux.bin.l7
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-vmlinux.elf $(BIN_DIR)/openwrt-$(BOARD)
	$(if $(CONFIG_FIRMWARE_RELEASE),$(STAGING_DIR_HOST)/bin/mkfirmware-nb5 \
		$(KDIR)/vmlinux.bin.l7 $(BIN_DIR)/$(CONFIG_FIRMWARE_RELEASE); \
		mv -f $(BIN_DIR)/$(CONFIG_FIRMWARE_RELEASE) $(BIN_DIR)/openwrt-$(BOARD)-nb5)
endef
endif

$(eval $(call BuildImage))
