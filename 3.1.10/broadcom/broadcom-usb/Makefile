# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-usb
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-usb
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=63xx USB driver
  FILES:=$(PKG_BUILD_DIR)/bcm_usb.$(LINUX_KMOD_SUFFIX)
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers
endef

define KernelPackage/broadcom-usb/description
 This package contains the proprietary usb driver for the Broadcom 963xx chips.
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)/
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,broadcom-usb))
