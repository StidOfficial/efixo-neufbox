# 
# Copyright (C) 2008-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bemused-mpd
PKG_VERSION:=r062
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://download.origo.ethz.ch/bemused-lnx-mpdhack/526
PKG_MD5SUM:=aed8b41aed530e9177e43d9bebad10b7

include $(INCLUDE_DIR)/package.mk

define Package/bemusedlinuxserver
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+bluez-libs +glib1 +mpd +libstdcpp +libiconv
  TITLE:=Bemused linux server
  URL:=http://bemused-lnx-mpdhack.origo.ethz.ch/
endef

define Package/bemusedlinuxserver/description
    Bemused is a system which allows you to control your music collection
    from your phone, using Bluetooth.
    This is the MPD hack version.
    Check http://jamse.sourceforge.net/ for a mobile phone client.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
	$(TARGET_CONFIGURE_OPTS) \
	CFLAGS="$(TARGET_CFLAGS) $(EXTRA_CPPFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS) " \
	CPPFLAGS="$(TARGET_CPPFLAGS)" \
	INCL="$(TARGET_CPPFLAGS) -I$(STAGING_DIR)/usr/include/glib-1.2 -I$(STAGING_DIR)/usr/lib/glib/include -I$(STAGING_DIR)/usr/lib/libiconv/include" \
	MYLIBS="-lbluetooth -lglib -L$(STAGING_DIR)/usr/lib/libiconv/lib -liconv"
	$(STRIP) $(PKG_BUILD_DIR)/bemusedlinuxserver
endef

define Package/bemusedlinuxserver/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bemusedlinuxserver $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./files/bemused.conf $(1)/etc/bemused.conf
	$(INSTALL_CONF) ./files/bemused-bookmarks $(1)/etc/bemused-bookmarks
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/bemused.init $(1)/etc/init.d/bemused
endef

$(eval $(call BuildPackage,bemusedlinuxserver))
