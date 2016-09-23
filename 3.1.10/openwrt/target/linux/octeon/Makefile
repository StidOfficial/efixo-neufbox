#
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

BOARD:=octeon
BOARDNAME:=Cavium Networks Octeon
FEATURES:=squashfs jffs2 pci usb
CFLAGS:=-Os -pipe -mtune=octeon -funit-at-a-time

SUBTARGETS=openwrt nb5-main nb5-rescue nb5-refurbishing
INITRAMFS_EXTRA_FILES:=$(TOPDIR)/target/linux/$(BOARD)/image/initramfs-base-files.txt

LINUX_VERSION:=2.6.30.10

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES +=

define Target/Description
	Build firmware images for Cavium Networks Octeon-based boards.
endef

$(eval $(call BuildTarget))
