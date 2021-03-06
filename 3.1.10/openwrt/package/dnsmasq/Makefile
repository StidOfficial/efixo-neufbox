# 
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dnsmasq
PKG_VERSION:=2.55
PKG_RELEASE:=6

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://thekelleys.org.uk/dnsmasq
PKG_MD5SUM:=b093d7c6bc7f97ae6fd35d048529232a

PKG_BUILD_DEPENDS:=PACKAGE_efixo-libnbd:efixo-libnbd
PKG_CONFIG_DEPENDS:=CONFIG_PACKAGE_efixo-libnbd

include $(INCLUDE_DIR)/package.mk

define Package/dnsmasq
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=A lightweight DNS and DHCP server
  URL:=http://www.thekelleys.org.uk/dnsmasq/
endef

define Package/dnsmasq/description
 It is intended to provide coupled DNS and DHCP service to a LAN.
endef

define Package/dnsmasq/conffiles
#/etc/config/dhcp
#/etc/dnsmasq.conf
endef

TARGET_CFLAGS+=$(if $(CONFIG_PACKAGE_efixo-libnbd),$(TARGET_CPPFLAGS) -DHAVE_LIBNBD)
EXTRA_LIBS+=$(if $(CONFIG_PACKAGE_efixo-libnbd),-lnbd -L$(STAGING_DIR)/usr/lib)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		LIBS="$(EXTRA_LIBS)" \
		BINDIR="/usr/sbin" MANDIR="/usr/man" \
		AWK="awk" \
		all
endef

define Package/dnsmasq/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/dnsmasq $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(if $(CONFIG_PACKAGE_efixo-rcc),,$(INSTALL_DATA) ./files/dhcp.conf $(1)/etc/config/dhcp)
	$(if $(CONFIG_PACKAGE_efixo-rcc),,$(INSTALL_DATA) ./files/dnsmasq.conf $(1)/etc/dnsmasq.conf)
	$(INSTALL_DIR) $(1)/etc/init.d
	$(if $(CONFIG_PACKAGE_efixo-rcc),,$(INSTALL_BIN) ./files/dnsmasq.init $(1)/etc/init.d/dnsmasq)
endef

$(eval $(call BuildPackage,dnsmasq))
