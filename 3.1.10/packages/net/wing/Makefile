#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wing
PKG_VERSION:=20101023
PKG_RELEASE:=1
PKG_REV:=daffb8d7642c4a343951d67159504ff4f4da49ed

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://github.com/create-net/click-wing.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_PROTO:=git

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_DEPENDS:=wing/host

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk

define Package/wing
	TITLE:=Wireless mesh networking toolkit
	SECTION:=net
	CATEGORY:=Network
	MAINTAINER:=Roberto Riggio <roberto.riggio@create-net.org>
	DEPENDS:=+kmod-tun +libpcap +libstdcpp
	URL:=http://www.wing-project.org/
endef

define Package/wing/Description 
	Wing is a wireless mesh routing software. The routing protocol
	is derived from Roofnet. It supports multiple radio interfaces 
	and link quality routing using the ETX, ETT, or WCETT metric.
endef 

EXTRA_CFLAGS=-MD

CONFIGURE_ARGS += \
	--enable-tools=host \
	--enable-userlevel \
	--enable-wifi \
	--enable-wing \
	--disable-linuxmodule \
	--disable-dynamic-linking \

HOST_CONFIGURE_ARGS += \
	--enable-userlevel \
	--enable-wifi \
	--enable-wing \
	--disable-linuxmodule \

define Host/Compile
	$(call Host/Install/Default, tools elementmap.xml install)
endef

define Build/Compile
	(cd $(PKG_BUILD_DIR)/userlevel; \
		$(STAGING_DIR_HOST)/bin/click-mkmindriver -p $(PKG_NAME) -C $(STAGING_DIR_HOST) \
		-f $(PKG_BUILD_DIR)/conf/wing/sample.click \
		-A --all -E Discard -E Print -E Null \
		-E InfiniteSource -E RatedSource -E EtherEncap -E UDPIPEncap \
		-E RadiotapDecap -E RadiotapEncap \
		-E ProbeTXRate -E MadwifiRate -E AutoRateFallback -E Minstrel \
		-E RoundRobinSched -E DRRSched; \
	);
	$(call Build/Install/Default, MINDRIVER=$(PKG_NAME) install)
endef

define Package/wing/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/wing
	$(INSTALL_DIR) $(1)/usr/share/click
	$(CP) ./files/* $(1)/
	$(CP) $(PKG_BUILD_DIR)/conf/wing/click_config $(1)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/conf/wing/write_handler $(1)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/conf/wing/read_handler $(1)/usr/bin/
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/$(PKG_NAME)click $(1)/usr/bin/click
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/click-align $(1)/usr/bin/click-align
	$(CP) $(PKG_BUILD_DIR)/conf/wing/*click $(1)/etc/wing/
	$(CP) $(PKG_INSTALL_DIR)/usr/share/click/elementmap.xml $(1)/usr/share/click/elementmap.xml
endef

$(eval $(call HostBuild))
$(eval $(call BuildPackage,wing))

