# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 17919 2010-10-04 09:35:12Z mgo $

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-wrapper
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

PKG_BUILD_DEPENDS:=PACKAGE_efixo-libnbd:efixo-libnbd \
	PACKAGE_efixo-libbackup:efixo-libbackup \
	PACKAGE_ezxml:ezxml
PKG_CONFIG_DEPENDS:=CONFIG_PACKAGE_efixo-libnbd \
	CONFIG_PACKAGE_efixo-libbackup \
	CONFIG_PACKAGE_ezxml

ifeq ($(DUMP),)
  STAMP_CONFIGURED:=$(strip $(STAMP_CONFIGURED))_$(shell grep '^CONFIG_efixo-wrapper-' $(TOPDIR)/.config | md5s)
endif

define Package/efixo-wrapper
  SECTION:=efixo
  CATEGORY:=Efixo applications
  TITLE:=neufbox wrapper
  MAINTAINER:=Miguel GAIO
  DEPENDS:=+librt +efixo-libetk
endef

define Package/efixo-wrapper/description
 This package contains an utility for neufbox voip
endef

define Package/efixo-wrapper/config
	menuconfig efixo-wrapper-plugins
		bool "Wrapper plugins"
		depends on PACKAGE_efixo-wrapper

	config efixo-wrapper-plugin-cmd
		bool "cmd plugin" if efixo-wrapper-plugins 

	config efixo-wrapper-plugin-dummy
		bool "dummy plugin" if efixo-wrapper-plugins

	config efixo-wrapper-plugin-shell
		bool "shell plugin" if efixo-wrapper-plugins

	config efixo-wrapper-plugin-data
		bool "data plugin" if efixo-wrapper-plugins

	config efixo-wrapper-plugin-hotspot
		bool "hotspot plugin" if efixo-wrapper-plugins

	config efixo-wrapper-plugin-ppp-adsl
		bool "ppp/adsl plugin" if efixo-wrapper-plugins
		depends on @neufbox_net_infra_adsl

	config efixo-wrapper-plugin-ppp-gprs
		bool "ppp/grps plugin" if efixo-wrapper-plugins
		depends on @neufbox_net_infra_gprs

	config efixo-wrapper-plugin-voip
		bool "voip plugin" if efixo-wrapper-plugins

	config efixo-wrapper-plugin-tv
		bool "tv plugin" if efixo-wrapper-plugins

	config efixo-wrapper-plugin-ipv6
		bool "ipv6 plugin" if efixo-wrapper-plugins
endef

plugins-$(CONFIG_efixo-wrapper-plugin-cmd)	+= cmd
plugins-$(CONFIG_efixo-wrapper-plugin-dummy)	+= dummy
plugins-$(CONFIG_efixo-wrapper-plugin-shell)	+= shell
plugins-$(CONFIG_efixo-wrapper-plugin-data)	+= data
plugins-$(CONFIG_efixo-wrapper-plugin-hotspot)	+= hotspot
plugins-$(CONFIG_efixo-wrapper-plugin-ppp-adsl)	+= ppp_adsl
plugins-$(CONFIG_efixo-wrapper-plugin-ppp-gprs)	+= ppp_gprs
plugins-$(CONFIG_efixo-wrapper-plugin-voip)	+= voip
plugins-$(CONFIG_efixo-wrapper-plugin-tv)	+= tvservices
plugins-$(CONFIG_efixo-wrapper-plugin-ipv6)	+= ipv6

MAKE_VARS += PLUGINS="$(plugins-y)"

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

define Package/efixo-wrapper/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wrapper $(1)/usr/sbin
endef

$(eval $(call BuildPackage,efixo-wrapper))
