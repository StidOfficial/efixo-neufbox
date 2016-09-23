#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-libbackup
PKG_RELEASE:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/efixo-libbackup
  SECTION:=efixo
  CATEGORY:=Efixo library
  TITLE:=backup library
  MAINTAINER:=Severin Lageder
  DEPENDS:=
endef

define Package/efixo-libbackup/description
 Library used for dealing with the backup daemon
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	#$(INSTALL_DIR) $(STAGING_DIR)/user/include/backupd
	#$(CP) src/include/* $(STAGING_DIR)/usr/include/backupd
	$(call Build/Prepare/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/include/backupd/
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/include/backupd/* $(1)/usr/include/backupd
	$(CP) $(PKG_BUILD_DIR)/libbackup.{a,so} $(1)/usr/lib
endef

define Package/efixo-libbackup/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libbackup.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,efixo-libbackup))

