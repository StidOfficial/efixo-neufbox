# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=broadcom-wireless_softs
PKG_RELEASE:=1

PATCH_DIR=./patches-$(CONFIG_BROADCOM_WIRELESS_VERSION)

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define Package/broadcom-wireless_softs
  SECTION:=broadcom
  CATEGORY:=Broadcom applications
  TITLE:=wireless driver setup utility
  DEPENDS:=kmod-broadcom-wireless +efixo-libnbd +efixo-libnbu +efixo-libetk +efixo-headers
endef

define Package/broadcom-wireless_softs/config
	menu "Configuration"
		depends on PACKAGE_broadcom-wireless_softs
		source "$(SOURCE)/Config.in"
	endmenu
endef

define Package/broadcom-wireless_softs/description
 This package contains an utility for initializing the Broadcom 
 wireless softwares.
endef

DRIVER_DIR := $(PKG_BUILD_DIR)
WLCTL	:= wl/exe
CRYPTO	:= bcmcrypto
SHARED	:= router/shared
NAS	:= router/nas
EAPD	:= router/eapd
WROSTAPD:= router/wrostapd
WPS	:= wps

# EXTRALIBDIR is used in nas, bcmupnp, eapd and wps
MAKE_VARS    += WIRELESS_DRIVER_PATH=$(DRIVER_DIR) \
		BUILD_WLCTL_SHLIB=1 \
		INSTALL_DIR=$(PKG_BUILD_DIR) \
		BUILD_DIR=$(PKG_BUILD_DIR) \
		EXTRALIBDIR=$(STAGING_DIR)/usr/lib \
		BRCM_CHIP=$(CONFIG_NEUFBOX_SOC_TYPE) \
		BRCM_BOARD=bcm963xx

EXTRA_CFLAGS += \
	-I$(STAGING_DIR)/usr/include/broadcom \
	-I$(STAGING_DIR)/usr/include/broadcom/linux \
	-I$(STAGING_DIR)/usr/include/broadcom/kernel \
	-I$(STAGING_DIR)/usr/include/ \
	-I$(STAGING_DIR)/usr/include/kernel \
	-I$(PKG_BUILD_DIR)/include \
	-I$(PKG_BUILD_DIR)/wl/sys \
	-DBRCM_WLAN \
	-fPIC \
	-DRADIUS_NAS_PORT_ID='\"${CONFIG_RADIUS_NAS_PORT_ID}\"' \
	-DRADIUS_WISPR_LOCATION_ID_NETWORK_PREFIX='\"${CONFIG_RADIUS_WISPR_LOCATION_ID_NETWORK_PREFIX}\"' \
	-DRADIUS_WISPR_LOCATION_NAME_PREFIX='\"${CONFIG_RADIUS_WISPR_LOCATION_NAME_PREFIX}\"'

ifeq ($(strip $(BOX)),"nb6")
EXTRA_CFLAGS += -DCONFIG_BOARD_NEUFBOX6
endif
ifeq ($(strip $(BOX)),"nb4")
EXTRA_CFLAGS += -DCONFIG_BOARD_NEUFBOX4
endif

ifeq ($(strip $(CONFIG_BROADCOM_WIRELESS_DEBUG)),y)
EXTRA_CFLAGS += \
	 -DCMS_LOG0
endif

define Build/Prepare
	$(CP) src-$(CONFIG_BROADCOM_WIRELESS_VERSION)/* $(PKG_BUILD_DIR)
	mkdir $(PKG_BUILD_DIR)/lib
	mkdir $(PKG_BUILD_DIR)/router/wrostapd
	$(CP) src-wrostapd/* $(PKG_BUILD_DIR)/router/wrostapd/
	$(call Build/Prepare/Default)
endef

define Build/Compile
# Compile crypto
	$(MAKE_VARS) \
		$(MAKE) -C $(PKG_BUILD_DIR)/$(CRYPTO) \
		$(MAKE_FLAGS) \
		install

# Compile shared
	$(MAKE_VARS) \
		$(MAKE) -C $(PKG_BUILD_DIR)/$(SHARED) \
		$(MAKE_FLAGS) \
		install

# Compile wlctl
	$(MAKE_VARS) \
		$(MAKE) -C $(PKG_BUILD_DIR)/$(WLCTL) \
		$(MAKE_FLAGS) \
		all
	$(CP) $(PKG_BUILD_DIR)/$(WLCTL)/libwlctl.so $(PKG_BUILD_DIR)/lib

# Compile nas
	$(MAKE_VARS) \
		$(MAKE) -C $(PKG_BUILD_DIR)/$(NAS) \
		$(MAKE_FLAGS) \
		nas

# Compile eapd
	$(MAKE_VARS) \
		$(MAKE) -C $(PKG_BUILD_DIR)/$(EAPD) \
		$(MAKE_FLAGS) \
		eapd

# Compile wrostapd
	$(MAKE_VARS) \
		$(MAKE) -C $(PKG_BUILD_DIR)/$(WROSTAPD) \
		$(MAKE_FLAGS)

# Compile wps
#	$(MAKE_VARS) \
#		$(MAKE) -C $(PKG_BUILD_DIR)/$(WPS) \
#		$(MAKE_FLAGS) \
#		dynamic
endef

define Package/broadcom-wireless_softs/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(WLCTL)/wlctl $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(NAS)/nas $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(EAPD)/eapd $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(WROSTAPD)/wrostapd $(1)/usr/sbin
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(WPS)/wps_ap $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/libwlbcmcrypto.so $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/libwlbcmshared.so $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/libwlctl.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,broadcom-wireless_softs))
