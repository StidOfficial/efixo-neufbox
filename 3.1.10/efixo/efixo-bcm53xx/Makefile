# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z bcm53xx $

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-bcm53xx
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/efixo-bcm53xx
  TITLE:=bcm53xx switch control library
  SECTION:=efixo
  CATEGORY:=Efixo applications
  MAINTAINER:=Miguel GAIO
  DEPENDS:=+efixo-libetk
endef

define Package/efixo-bcm53xx/description
 This package contains library for bcm53xx robo switch
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

MAKE_VARS+=LINUX_DIR=$(LINUX_DIR)

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libbcm53xx.a $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/bcm53xx.h $(1)/usr/include
endef

define Package/efixo-bcm53xx/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/switch-robo $(1)/usr/sbin
endef

$(eval $(call BuildPackage,efixo-bcm53xx))
