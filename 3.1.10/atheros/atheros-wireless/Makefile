# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 11868 2008-07-18 22:57:30Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=atheros-wireless
PKG_RELEASE:=1

PKG_CONFIG_DEPENDS:=CONFIG_ATHEROS_VERSION

PATCH_DIR=./patches-$(CONFIG_ATHEROS_VERSION)

include $(INCLUDE_DIR)/package.mk

ifneq ($(CONFIG_TARGET_atheros),)
  BUS:=AHB
else
  ifneq ($(CONFIG_PCI_SUPPORT),)
    BUS:=PCI
  endif
endif

# XXX: remove this check later when we have PCI support properly detected on all targets
ifneq ($(CONFIG_TARGET_ar7)$(CONFIG_TARGET_uml),)
  BUS:=
endif

ifeq ($(ARCH),mips)
  HAL_TARGET:=mips-be-elf
endif
ifeq ($(ARCH),mipsel)
  HAL_TARGET:=mips-le-elf
endif
ifeq ($(ARCH),i386)
  HAL_TARGET:=i386-elf
endif
ifeq ($(ARCH),i686)
  HAL_TARGET:=i386-elf
endif
ifeq ($(BOARD),ixp4xx)
  HAL_TARGET:=xscale-be-elf
endif
ifeq ($(BOARD),iop32x)
  HAL_TARGET:=xscale-le-elf
endif
ifeq ($(BOARD),orion)
  HAL_TARGET:=xscale-le-elf
endif
ifeq ($(ARCH),powerpc)
  HAL_TARGET:=powerpc-be-elf
endif
ifeq ($(BOARD),storm)
  HAL_TARGET:=armv4-le-elf
endif
ifneq ($(CONFIG_TARGET_atheros),)
  HAL_TARGET:=wisoc
endif

ifneq ($(CONFIG_TARGET_octeon),)
  HAL_TARGET:=mipsisa64-be-elf
endif

ifdef CONFIG_ATHEROS_RCA
  RATE_CONTROL:=atheros
endif

ifdef CONFIG_MADWIFI_RCA_MINSTREL
  RATE_CONTROL:=minstrel
endif

ifdef CONFIG_MADWIFI_RCA_ONOE
  RATE_CONTROL:=onoe
endif

ifdef CONFIG_MADWIFI_RCA_AMRR
  RATE_CONTROL:=amrr
endif

ifdef CONFIG_MADWIFI_RCA_SAMPLERATE
  RATE_CONTROL:=sample
endif

MADWIFI_FILES:= \
	$(PKG_BUILD_DIR)/wlan/core/ath_hal/ath_hal.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_scan_ap.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_scan_sta.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_acl.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_ccmp.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_tkip.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_wep.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/core/net80211/wlan_xauth.$(LINUX_KMOD_SUFFIX) \
	$(PKG_BUILD_DIR)/wlan/ratectrl11n/ath_rate_$(RATE_CONTROL).$(LINUX_KMOD_SUFFIX) \
	$(if $(CONFIG_ATHEROS_REMOVE_5G_SUPPORT),,$(PKG_BUILD_DIR)/wlan/dfs/ath_dfs.$(LINUX_KMOD_SUFFIX))

MADWIFI_AUTOLOAD:= \
	wlan \
	wlan_scan_ap \
	wlan_scan_sta \
	ath_hal \
	ath_rate_$(RATE_CONTROL) \
	wlan_acl \
	wlan_ccmp \
	wlan_tkip \
	wlan_wep \
	wlan_xauth \

ifeq ($(findstring AHB,$(BUS)),AHB)
  MADWIFI_FILES+= $(PKG_BUILD_DIR)/ath/ath_ahb.$(LINUX_KMOD_SUFFIX)
  MADWIFI_AUTOLOAD+= ath_ahb
endif
ifeq ($(findstring PCI,$(BUS)),PCI)
  MADWIFI_FILES+= $(PKG_BUILD_DIR)/wlan/core/ath/ath_pci.$(LINUX_KMOD_SUFFIX)
  MADWIFI_AUTOLOAD+= ath_pci
endif

MADWIFI_APPLETS:=80211stats,athchans,athctrl,athkey,athstats,wlanconfig,$(if $(CONFIG_MADWIFI_TESTING),ath_info/)ath_info
ifdef CONFIG_MADWIFI_DEBUG
  MADWIFI_APPLETS:=$(strip $(MADWIFI_APPLETS)),athdebug,80211debug
endif


define KernelPackage/atheros-wireless/config
	source "$(SOURCE)/Config.in"
endef

define KernelPackage/atheros-wireless
  SUBMENU:=Wireless Drivers
  TITLE:=Driver for Atheros wireless chipsets
  URL:=http://madwifi.org/
  DEPENDS:=+wireless-tools @PCI_SUPPORT||TARGET_atheros @!TARGET_ar7 @!TARGET_avr32 @!TARGET_etrax @!TARGET_uml +kmod-crypto-arc4 +kmod-crypto-aes +libopenssl
  FILES:=$(MADWIFI_FILES)
endef

define KernelPackage/atheros-wireless/description
 This package contains a driver for Atheros 802.11a/b/g/n chipsets.
endef

define Package/atheros-tools
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Atheros wireless debug tools
  DEPENDS:=kmod-atheros-wireless
endef

define Package/atheros-tools/description
 This Package contains Atheros debug tools
endef

#	ONLY_11N=1 \
#	ATH_NO_DEBUG=1 \
#	ATH_REMOVE_RADAR_DETECT=1 \
#	ATH_REMOVE_5G_RATE_TABLE=1 \
#	ATH_REMOVE_TURBO_RATE_TABLE=1 \
#	ATH_REMOVE_XR_RATE_TABLE=1 \
#	ATH_REMOVE_ADHOC_MONITOR_MODE=1 \
#	ATH_REMOVE_5G_RD_TABLE=1 \
#	ATH_REMOVE_2G_TURBO_RD_TABLE=1 \
#	ATH_REMOVE_STA_MODE=1 \

MAKE_ARGS:= \
	PATH="$(TARGET_PATH)" \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	TARGET="$(HAL_TARGET)" \
	TOOLPREFIX="$(KERNEL_CROSS)" \
	TOOLPATH="$(KERNEL_CROSS)" \
	KERNELPATH="$(LINUX_DIR)" \
	LDOPTS="--no-warn-mismatch " \
	DRIVER_DIR=$(PKG_BUILD_DIR)/wlan \
	APPS=$(PKG_BUILD_DIR)/apps \
	HAL=$(DRIVER_DIR)/core/hal/ \
	ATH_RATE=$(DRIVER_DIR)/ratectrl11n \
	DFS=$(DRIVER_DIR)/dfs \
	TX99=$(DRIVER_DIR)/tx99 \
	ATH_CARRPLTFRM_BASE=$(DRIVER_DIR)/carrier \
	ATH_DFS=$(DRIVER_DIR)/dfs \
	ATH_CARR_DIR=cavium \
	ATH_REMOVE_RADAR_DETECT=1 \
	ATH_USE_COMMONHAL=1 \
	AH_SUPPORT_OWL=1 \
	AH_SUPPORT_HOWL=0 \
	REMOVE_PKT_LOG=1 \
	$(if $(CONFIG_ATHEROS_REMOVE_5G_SUPPORT),ATH_PHYERR=$(PKG_BUILD_DIR)/wlan/dfs) \
	ATH_RATE="ath_rate/$(RATE_CONTROL)" \
	DO_MULTI=1 \
	HAL=$(PKG_BUILD_DIR)/wlan/core/hal \
	ATH_RATE=$(PKG_BUILD_DIR)/wlan/ratectrl11n \
	TX99=$(PKG_BUILD_DIR)/wlan/tx99


ifneq ($(CONFIG_MADWIFI_TESTING),)
  MAKE_ARGS += $(if $(CONFIG_MADWIFI_DEBUG),,ATH_DEBUG=)
else
  MAKE_ARGS += $(if $(CONFIG_MADWIFI_DEBUG),,DEBUG=) WARNINGS="-Wno-unused"
endif

MAKE_VARS:= \
	COPTS="-DCONFIG_ATHEROS_RATE_DEFAULT='\"$(RATE_CONTROL)\"' -DATH_REVERSE_ENGINEERING=1" \

PKG_TARFILE:=./CR-LSDK-WLAN-pb42-carrier-$(CONFIG_ATHEROS_VERSION).tgz
define Build/Prepare
	tar xzf $(PKG_TARFILE) -C $(PKG_BUILD_DIR)
	tar xfz CR-LSDK-WLAN-CAVIUM-pb42-carrier-1.3.1.146.tgz -C $(PKG_BUILD_DIR) || true
	touch $(PKG_BUILD_DIR)/wlan/carrier/cavium/Makefile.cust.inc
	chmod +w -R $(PKG_BUILD_DIR)
	$(SED) 's/## CONFIG_NO_UPNP=y/CONFIG_NO_UPNP=y/g' $(PKG_BUILD_DIR)/apps/wpa2/common/full.config
	$(call Build/Prepare/Default)
endef

ifeq ($(findstring AHB,$(BUS)),AHB)
  define Build/Compile/ahb
	$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR)/wlan $(MAKE_ARGS) BUS="AHB" modules
	$(MAKE) -C $(PKG_BUILD_DIR)/wlan $(MAKE_ARGS) CFLAGS="$(TARGET_CFLAGS)" tools
  endef
endif

ifeq ($(findstring PCI,$(BUS)),PCI)
  define Build/Compile/pci
	$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR)/wlan $(MAKE_ARGS) BUS="PCI"
	$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR)/wlan/tools $(MAKE_ARGS) BUS="PCI"
  endef
endif

define Build/Configure
	$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR)/wlan/core/hal/linux $(MAKE_ARGS)
	$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR)/wlan/core/hal/linux $(MAKE_ARGS) release
endef

MAKE_VARS+= \
	BUILD_WPA2_NO_WPA_SUPPLICANT=y \
	BUILD_WPA2_NO_APSTART=y \
	BUILD_WPA2_NO_EXAMPLES=y \


define Build/Compile
	$(call Build/Compile/ahb)
	$(call Build/Compile/pci)
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/lib
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/sbin
	INSTALL_ROOT=$(PKG_INSTALL_DIR) \
	MADWIFIPATH=$(PKG_BUILD_DIR)/wlan/core/ \
	$(MAKE_VARS) \
		$(MAKE) $(MAKE_FLAGS) -C $(PKG_BUILD_DIR)/apps/wpa2/common install
	INSTALL_ROOT=$(PKG_INSTALL_DIR) \
	MADWIFIPATH=$(PKG_BUILD_DIR)/wlan/core/ \
	$(MAKE_VARS) \
		$(MAKE) $(MAKE_FLAGS) -C $(PKG_BUILD_DIR)/apps/wpa2/hostapd install
	INSTALL_ROOT=$(PKG_INSTALL_DIR) \
	MADWIFIPATH=$(PKG_BUILD_DIR)/wlan/core/ \
	$(MAKE_VARS) \
		$(MAKE) $(MAKE_FLAGS) -C $(PKG_BUILD_DIR)/apps/wpa2/wpatalk install
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include/madwifi
	$(CP) $(PKG_BUILD_DIR)/wlan/core/include $(1)/usr/include/madwifi/
	mkdir -p $(1)/usr/include/madwifi/net80211
	$(CP) $(PKG_BUILD_DIR)/wlan/core/net80211/*.h $(1)/usr/include/madwifi/net80211/
endef

define KernelPackage/atheros-wireless/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/wlanconfig $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/wpa2/wpatalk/wpatalk $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/wpa2/hostapd/hostapd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/lib/
	$(CP) $(PKG_BUILD_DIR)/apps/wpa2/common/libwpa_common.so $(1)/lib/
	$(CP) $(PKG_BUILD_DIR)/apps/wpa2/common/libwpa_ctrl.so $(1)/lib/
	$(INSTALL_DIR) $(1)/etc/hostapd/
	$(CP) files/etc/hostapd/base.conf $(1)/etc/hostapd/
	$(CP) files/etc/hostapd/hostapd.eap_user $(1)/etc/hostapd/
endef

define Package/atheros-tools/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/athctrl $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/athstatsclr $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/athstats $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/athdebug $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/athcwm $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlan/tools/radartool $(1)/usr/bin
endef

$(eval $(call RequireCommand,uuencode, \
	Please install uuencode \
))

$(eval $(call KernelPackage,atheros-wireless))
$(eval $(call BuildPackage,atheros-tools))
