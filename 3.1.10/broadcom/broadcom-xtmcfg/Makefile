# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-xtmcfg
PKG_RELEASE:=1

PATCH_DIR=./patches-$(CONFIG_BROADCOM_XTMCFG_VERSION)

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-xtmcfg
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=Kernel driver for ATM controler
  FILES:=$(PKG_BUILD_DIR)/bcmxtmcfg.$(LINUX_KMOD_SUFFIX)
  KCONFIG:=CONFIG_ATM_RT2684=y
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers +kmod-broadcom-adsl +kmod-atm
endef

define KernelPackage/broadcom-xtmcfg/description
 This package contains the proprietary atm driver for the Broadcom 963xx chips.
endef

define KernelPackage/broadcom-xtmcfg/config
config BROADCOM_XTMCFG_VERSION
    string
    depends on PACKAGE_kmod-broadcom-xtmcfg
    default 'impl1' if neufbox_soc_6358
    default 'impl3' if neufbox_soc_6362
endef

define Build/Prepare
	$(CP) src-$(CONFIG_BROADCOM_XTMCFG_VERSION)/* $(PKG_BUILD_DIR)/
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	ADSL=ANNEX_A \
	ADSL_PHY_MODE=file \
	LINUX_DIR="$(LINUX_DIR)" \
	STAGING_DIR="$(STAGING_DIR)" \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,broadcom-xtmcfg))
