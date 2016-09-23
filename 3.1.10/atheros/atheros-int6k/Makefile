# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 11868 2008-07-18 22:57:30Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=atheros-int6k
PKG_RELEASE:=1

PKG_TARFILE:=int6000-utils-1.2.0.tar.gz

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/atheros-int6k
  SECTION:=atheros
  CATEGORY:=Atheros HomePlug AV
  TITLE:=Atheros HomePlug AV diag int6k tools
  MAINTAINER:=Miguel GAIO
endef

define Build/Prepare
	tar xzf $(PKG_TARFILE) -C $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

MAKE_PATH := int6000-utils-1.2.0
MAKE_VARS += \
	LFLAGS="$(TARGET_CFLAGS) $(TARGET_LDFLAGS) $(EXTRA_LDFLAGS)"
MAKE_FLAGS += \
	FOLDERS="amp int6k int6k2 efsu tools mme ram nvm pib crypt nodes"

define Package/atheros-int6k/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MAKE_PATH)/int6k/int6k $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MAKE_PATH)/int6k/int6keth $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MAKE_PATH)/int6k/int6krate $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MAKE_PATH)/int6k/int6ktone $(1)/usr/bin
endef

$(eval $(call BuildPackage,atheros-int6k))

