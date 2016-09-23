#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=fuzz
PKG_VERSION:=0.6

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=ftp://ftp.free.fr/mirrors/ftp.gentoo.org/distfiles/
PKG_MD5SUM:=8c8e7c49729e0a98c0414faac7778ec7

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/fuzz
  SECTION:=debug
  CATEGORY:=Fuzzing
  TITLE:=fuzz the world
  URL:=http://fuzz.sourceforge.net/
endef

define Package/fuzz/description
Stress-tests programs by giving them random input
endef

define Package/fuzz/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/fuzz $(1)/usr/bin/
endef

$(eval $(call BuildPackage,fuzz))
