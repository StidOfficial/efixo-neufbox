#
# Copyright (C) 2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ip6calc
PKG_REV:=196
PKG_VERSION:=r$(PKG_REV)
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://silmor.de/svn/misc/ip6calc
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_PROTO:=svn

include $(INCLUDE_DIR)/package.mk

define Package/ip6calc
  SECTION:=ipv6
  CATEGORY:=IPv6
  TITLE:=IPv6 addresses calculation
  URL:=http://silmor.de/70
endef

define Package/ip6calc/description
  The ip6calc utility can be used to calculate network and host IDs from a full 
  IP-address plus mask, as well as calculating sub-classed networks - eg. for 
  combining a dynamic provider-assigned /48-prefix with the local network numbers 
  to create the actual local /64 network prefixes. 

  The ip4toip6 utility can be used to convert all local IPv4 addresses up 
  IPv6-mapped addresses and 6to4 prefixes.
endef


define Package/ip6calc/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ip6calc $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ip4toip6 $(1)/usr/bin/
endef

$(eval $(call BuildPackage,ip6calc))
