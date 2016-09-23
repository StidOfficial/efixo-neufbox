# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-ethswctl
PKG_RELEASE:=1

PATCH_DIR=./patches-$(CONFIG_BROADCOM_ETHERNET_VERSION)

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/broadcom-ethswctl
  SECTION:=broadcom
  CATEGORY:=Broadcom applications
  TITLE:=switch driver setup utility
  DEPENDS:=kmod-broadcom-ethernet @neufbox_soc_6362
endef

define Package/broadcom-ethswctl/description
 This package contains an utility for controling the proprietary Broadcom 
 ethernet switch driver.
endef

define Build/Prepare
	$(CP) src-$(CONFIG_BROADCOM_ETHERNET_VERSION)/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

MAKE_VARS+=LINUX_DIR=$(LINUX_DIR)

define Package/broadcom-ethswctl/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ethswctl $(1)/usr/sbin
endef

$(eval $(call BuildPackage,broadcom-ethswctl))
