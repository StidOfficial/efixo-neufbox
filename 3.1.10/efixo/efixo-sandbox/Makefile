# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z libnbu $

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-sandbox
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/efixo-sandbox
  TITLE:=Neufbox configuration daemon
  SECTION:=efixo
  CATEGORY:=Efixo applications
  DEPENDS:=+efixo-libnbd +efixo-libewf +efixo-libetk +libnl-tiny +libinklevel
  MAINTAINER:=Miguel GAIO
endef

define Package/efixo-sandbox/description
 This package contains sandbox apps for neufbox
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) src/* $(PKG_BUILD_DIR)
endef

MAKE_VARS += \
	LINUX_DIR="$(LINUX_DIR)" \
	STAGING_DIR="$(STAGING_DIR)"

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	$(call Build/Compile/Default)
	$(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR)/kernel modules
endef

define Package/efixo-sandbox/install
	@echo "efixo sandbox done"
endef

define Build/InstallDev
	$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR) BOX=$(BOX) install
endef

$(eval $(call BuildPackage,efixo-sandbox))
