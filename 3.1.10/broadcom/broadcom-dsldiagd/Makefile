# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-dsldiagd
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/broadcom-dsldiagd
  SECTION:=broadcom
  CATEGORY:=Broadcom applications
  TITLE:=adsl driver setup utility
  DEPENDS:=kmod-broadcom-adsl 
endef

define Package/broadcom-dsldiagd/description
 This package contains an utility for controling the proprietary Broadcom 
 adsl driver.
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

MAKE_VARS+=LINUX_DIR=$(LINUX_DIR)

define Package/broadcom-dsldiagd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dsldiagd $(1)/usr/sbin
endef

$(eval $(call BuildPackage,broadcom-dsldiagd))
