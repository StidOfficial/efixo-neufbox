# 
# Copyright (C) 2007 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wshaper
PKG_VERSION:=0.1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/wshaper
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+kmod-sched +tc
  TITLE:=wshaper
  URL:=http://lartc.org/wondershaper/
endef

define Package/wshaper/description
 A script to do traffing shaping with the HTB algorithm.
 Wshaper attempts to:
 * Maintain low latency for interfactive traffic at all times 
 * Allow 'surfing' at reasonable speeds while up or downloading
 * Make sure uploads don't harm downloads, and the other way around
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/wshaper/install
	$(INSTALL_DIR) $(1)/usr/sbin/ $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wshaper.htb $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/wshaper.init $(1)/etc/init.d/wshaper
endef

$(eval $(call BuildPackage,wshaper))
