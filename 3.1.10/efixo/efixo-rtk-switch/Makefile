# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z rtl83xx $

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-rtk-switch
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/efixo-rtk-switch
  TITLE:=rtl83xx switch control util
  SECTION:=efixo
  CATEGORY:=Efixo applications
  MAINTAINER:=Miguel GAIO
  DEPENDS:=+realtek-rtl8370 +libgcc +efixo-libetk
endef

define Package/efixo-rtk-switch/description
 This package contains tool for rtl83xx switch
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

EXTRA_CFLAGS += -I$(STAGING_DIR)/usr/include/rtl83xx/

define Package/efixo-rtk-switch/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rtk-switch $(1)/usr/sbin
endef

$(eval $(call BuildPackage,efixo-rtk-switch))
