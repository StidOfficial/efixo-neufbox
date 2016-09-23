# 
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tropicssl
PKG_VERSION:=0.0.1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://mirror.efixo.net/
#PKG_MD5SUM:=e99cd159bab90c121c895c1165411d95
PKG_RELEASE:=1

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/tropicssl/Default
  SUBMENU:=SSL
  TITLE:=Embedded SSL
  URL:=http://stackfoundry.com/tropicssl/
endef

define Package/libtropicssl/Default/description
TropicSSL is an adaptation and continuation of the BSD licensed PolarSSL code base. It aims to improve the functionality, improve testing, and continue maintenance of that code base. TropicSSL is a fundamentally smaller implementation of compared to heavyweights such as OpenSSL.
endef

define Package/libtropicssl
$(call Package/tropicssl/Default)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE+= (library)
endef

define Package/tropicssl-progs
$(call Package/tropicssl/Default)
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+libtropicssl
  TITLE+= (programs)
endef

define Build/Configure
endef

OBJS=aes.o md5.o sha2.o
TARGET_CFLAGS += $(FPIC)
MAKE_FLAGS += OFLAGS="$(TARGET_CFLAGS)" OBJS="${OBJS}"

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/include/tropicssl $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libtropicssl.{a,so} $(1)/usr/lib/
endef

define Package/libtropicssl/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/lib/libtropicssl.so $(1)/usr/lib/
endef

define Package/tropicssl-progs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/tropicssl_* $(1)/usr/bin/
endef

$(eval $(call BuildPackage,libtropicssl))
$(eval $(call BuildPackage,tropicssl-progs))
