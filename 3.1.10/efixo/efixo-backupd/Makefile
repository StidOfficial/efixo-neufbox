#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-backupd
PKG_RELEASE:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/efixo-backupd
  SECTION:=efixo
  CATEGORY:=Efixo applications
  TITLE:=backup daemon
  MAINTAINER:=Severin Lageder
  DEPENDS:=+libezxml +libpthread +efixo-libecom +efixo-libbackup +efixo-libnbd +efixo-libetk +libtropicssl
endef

define Package/efixo-backupd/description
 Backup daemon is used to manage backup usb extentions
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	#$(INSTALL_DIR) $(STAGING_DIR)/user/include/backupd
	#$(CP) src/include/backupd/* $(STAGING_DIR)/usr/include/backupd
	$(call Build/Prepare/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/include/backupd/
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/include/backupd/* $(1)/usr/include/backupd

endef

define Package/efixo-backupd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/backupd $(1)/usr/sbin
endef

$(eval $(call BuildPackage,efixo-backupd))
