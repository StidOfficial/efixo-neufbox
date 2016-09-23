# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-ethernet
PKG_RELEASE:=1

PATCH_DIR=./patches-$(CONFIG_BROADCOM_ETHERNET_VERSION)

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-ethernet
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=63xx Ethernet driver
  FILES:=$(PKG_BUILD_DIR)/bcm_enet.$(LINUX_KMOD_SUFFIX) 
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers +(LINUX_2_6_30||LINUX_2_6_32):kmod-broadcom-pktdma
endef

define KernelPackage/broadcom-ethernet/description
 This package contains the proprietary ethernet driver for the Broadcom 963xx chips.
endef

define KernelPackage/broadcom-ethernet/config
config BROADCOM_ETHERNET_VERSION
    string
    default 'impl2' if neufbox_soc_6358
    default 'impl4' if neufbox_soc_6362
endef

define Build/Prepare
	$(CP) src-$(CONFIG_BROADCOM_ETHERNET_VERSION)/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,broadcom-ethernet))
