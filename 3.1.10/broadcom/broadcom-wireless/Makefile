# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-wireless
PKG_RELEASE:=1

PKG_CONFIG_DEPENDS:=CONFIG_BROADCOM_WIRELESS_CONFIGNAME \
	CONFIG_BROADCOM_WIRELESS_VERSION

DRIVER_KMOD:=$(PKG_BUILD_DIR)/wl.$(LINUX_KMOD_SUFFIX)

PATCH_DIR=./patches-$(CONFIG_BROADCOM_WIRELESS_VERSION)

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-wireless
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=Kernel driver for wireless device
  FILES:=$(DRIVER_KMOD)
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers
  MENU:=1
endef

define KernelPackage/broadcom-wireless/description
 This package contains the proprietary wireless driver for the Broadcom 963xx chips.
endef

define KernelPackage/broadcom-wireless/config
config BROADCOM_WIRELESS_VERSION
    string "Broadcom Wireless release"
    depends on PACKAGE_kmod-broadcom-wireless
    default 'impl5-full' if neufbox_soc_6358
    default 'impl8-full' if neufbox_soc_6362

config BROADCOM_WIRELESS_CONFIGNAME
    string "Broadcom Wireless driver configuration"
    depends on PACKAGE_kmod-broadcom-wireless
    default 'wlconfig_lx_wl_dslcpe_pci_ap_1g' if neufbox_soc_6358
    default 'wlconfig_lx_wl_dslcpe_pci_ap_1gn' if neufbox_soc_6362
    help
          Select Broadcom Wireless driver configuration name
endef

define Build/Prepare
	$(CP) src-$(CONFIG_BROADCOM_WIRELESS_VERSION)/* $(PKG_BUILD_DIR)
	mkdir $(PKG_BUILD_DIR)/lib
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
	BRCM_CHIP=$(CONFIG_NEUFBOX_SOC_TYPE) \
	BRCM_CONFIGNAME=$(CONFIG_BROADCOM_WIRELESS_CONFIGNAME) \
	$(KMAKE_EXTRA_VARS) \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include/broadcom
	$(CP) $(PKG_BUILD_DIR)/include/* \
		$(STAGING_DIR)/usr/include/broadcom
endef

define Srom/Install/nb4
	$(CP) files/etc/wlan/*.bin $(1)/etc/wlan
endef

define Srom/Install/nb6
	$(CP) $(PKG_BUILD_DIR)/shared/bcm*_map.bin $(1)/etc/wlan
endef

define KernelPackage/broadcom-wireless/install
	$(INSTALL_DIR) $(1)/etc/wlan
	$(call Srom/Install/$(BOX),$(1))
	$(CP) files/lib $(1)
endef

$(eval $(call KernelPackage,broadcom-wireless))
