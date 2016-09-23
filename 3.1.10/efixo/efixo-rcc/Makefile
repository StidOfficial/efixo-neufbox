#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-rcc
PKG_RELEASE:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_BUILD_DEPENDS_neufbox4:=efixo-bcm53xx
PKG_BUILD_DEPENDS_neufbox5:=efixo-bcm53xx
PKG_BUILD_DEPENDS_neufbox6:=realtek-rtl8370
PKG_BUILD_DEPENDS+= \
	$(foreach depend,$(PKG_BUILD_DEPENDS_neufbox4),TARGET_brcm63xx_nb4_main:$(depend)) \
	$(foreach depend,$(PKG_BUILD_DEPENDS_neufbox5),TARGET_octeon_nb5_main:$(depend)) \
	$(foreach depend,$(PKG_BUILD_DEPENDS_neufbox6),TARGET_brcm63xx_nb6_main:$(depend)) \

define Package/efixo-rcc
  SECTION:=efixo
  CATEGORY:=Efixo applications
  TITLE:=Neufbox RCC services
  MAINTAINER:=Arnaud ANDRE
  DEPENDS:=+efixo-headers +efixo-libnbd +efixo-libecom +efixo-libbackup +efixo-libetk
endef

define Package/efixo-rcc/description
 This package contains an utility for neufbox services gestion
endef

MAKE_VARS+=LINUX_DIR=$(LINUX_DIR)
EXTRA_CFLAGS += $(if $(CONFIG_PACKAGE_lighttpd), -DUSE_LIGHTTPD) -I$(STAGING_DIR)/usr/include/rtl83xx \
		-DLOCALDNS='\"$(CONFIG_LOCALDNS)\"' \
		-DNETBIOSNAME='\"$(shell echo "$(CONFIG_SAMBA_SERVICE_NAME)")\"'

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

define Package/efixo-rcc/install
	$(CP) $(PKG_INSTALL_DIR)/* $(1)
endef

$(eval $(call BuildPackage,efixo-rcc))
