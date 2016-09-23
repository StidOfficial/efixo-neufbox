# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z libnbu $

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-voicessdiags
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/efixo-voicessdiags
  SECTION:=efixo
  CATEGORY:=Efixo applications
  DEPENDS:=+kmod-efixo-voice-subsys
  TITLE:=Neufbox voice diag tool
  MAINTAINER:=Miguel GAIO
endef

define Package/efixo-voicessdiags/description
 This package contains a diag tool for voice
endef


MAKE_VARS += PROFILE=LOST

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) src/* $(PKG_BUILD_DIR)
endef

define Package/efixo-voicessdiags/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/voiceSSDiags $(1)/usr/sbin
endef

$(eval $(call BuildPackage,efixo-voicessdiags))
