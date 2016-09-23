# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-xtmctl
PKG_RELEASE:=1

PATCH_DIR=./patches-$(CONFIG_BROADCOM_XTMCFG_VERSION)

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/broadcom-xtmctl
  SECTION:=broadcom
  CATEGORY:=Broadcom applications
  TITLE:=atm driver setup utility
  DEPENDS:=kmod-broadcom-xtmcfg +libgcc
endef

define Package/broadcom-xtmctl/description
 This package contains an utility for initializing the proprietary Broadcom 
 atm driver.
endef

define Build/Prepare
	$(CP) src-$(CONFIG_BROADCOM_XTMCFG_VERSION)/* $(PKG_BUILD_DIR)/
	$(call Build/Prepare/Default)
endef

MAKE_VARS += \
	BRCM_ADSL_STANDARD=ANNEX_A
MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS) $(EXTRA_CFLAGS) $(RGET_CPPFLAGS) -DCONFIG_BCM9$(call qstrip,$(CONFIG_NEUFBOX_SOC_TYPE))"
EXTRA_CFLAGS += \
	-I$(STAGING_DIR)/usr/include/broadcom \
	-I$(STAGING_DIR)/usr/include/broadcom/linux \
	-I$(STAGING_DIR)/usr/include/broadcom/kernel \
	$(if $(CONFIG_LINUX_2_6_21),\
		-I$(LINUX_DIR)/include/asm-mips/mach-bcm63xx,\
		-I$(LINUX_DIR)/arch/mips/include/asm/mach-bcm63xx) \
	-DCMS_LOG0 \
	-DANNEX_A \
	-DCONFIG_BOARD_NEUFBOX6

define Package/broadcom-xtmctl/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xtmctl $(1)/bin
	ln -sf xtmctl $(1)/bin/xtm
	ln -sf xtmctl $(1)/bin/dumpmem
	ln -sf xtmctl $(1)/bin/setmem
endef

$(eval $(call BuildPackage,broadcom-xtmctl))
