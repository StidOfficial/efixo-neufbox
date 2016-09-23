# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id$

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=efixo-voice-subsys
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/efixo-voice-subsys
  TITLE:=Telephony Drivers
  SUBMENU:=Telephony Drivers
  DEPENDS:=@(TARGET_brcm63xx||TARGET_octeon) +TARGET_brcm63xx:kmod-broadcom-headers +TARGET_octeon:kmod-d2tech-driver
  FILES:=$(PKG_BUILD_DIR)/voiceSubSys_tst.ko
endef

define KernelPackage/efixo-voice-subsys/description
 This package contains drivers for telephony
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

MAKE_VARS += STAGING_DIR=$(STAGING_DIR)
include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	$(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) src/includes/*.h $(1)/usr/include
endef


$(eval $(call KernelPackage,efixo-voice-subsys))
