# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=broadcom-mgcp
PKG_RELEASE:=1
#PKG_INSTALL:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/broadcom-mgcp
  SECTION:=broadcom
  SUBMENU:=Voice over IP
  CATEGORY:=Broadcom applications
  TITLE:=Mgcp call client
  MAINTAINER:=Severin Lageder
  DEPENDS:=@TARGET_brcm63xx +efixo-libnbd +efixo-libetk +kmod-broadcom-endpointdrv +kmod-broadcom-headers
endef

define Package/broadcom-mgcp/description
 This package contains the mgcp call-client used on NB4
endef

MAKE_VARS += KERNEL_VERSION=2.6.21.7

define Package/broadcom-mgcp/config
    source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	$(CP) src/vodsl-$(CONFIG_VODSL_VERSION)/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

ifeq ($(BOX),nb6)
MAKE_VARS+= \
    BRCM_CHIP=6362 BRCM_BOARDID=96362ADVNG \
    XCHANGE_DIR=$(LINUX_DIR)/../broadcom-endpointdrv/xChange \
    OWRT_PKG_TOP_DIR=$(PKG_BUILD_DIR) \
    INC_BRCMCFM_PATH=   \
    BRCM_6362_SI32176=y    \
    BRCM_APP_PHONE=mgcp     \
    MGCPLOAD=1              \
    BRCM_VODSL_RANDOM_PORT=1   \
    INC_BRCMDRIVER_PRIV_PATH=$(STAGING_DIR)/usr/include/broadcom/kernel \
    INC_BRCMDRIVER_PUB_PATH=$(STAGING_DIR)/usr/include/broadcom/kernel\
    KERNEL_DIR=$(LINUX_DIR) \
    BUILD_DIR=$(BUILD_DIR) \
    XCHANGE_DSP_APP=all \
    XCHANGE_PROJ_DIR=$(LINUX_DIR)/../broadcom-endpointdrv \
    TOOLCHAIN=$(TOOLCHAIN_DIR_BIN)/.. \
    PROFILE=NB6_LOST

ifeq ($(CONFIG_VODSL_VERSION),"4.06.01")
MAKE_VARS+= \
			XCHANGE_BUILD_APP=Bcm6362uni
else
MAKE_VARS+= \
			XCHANGE_BUILD_APP=Bcm6362advng
endif


EXTRA_CFLAGS += \
	$(TARGET_CPPFLAGS) \
	-I$(STAGING_DIR)/usr/include/broadcom \
	-I$(STAGING_DIR)/usr/include/broadcom/linux \
	-I$(STAGING_DIR)/usr/include/broadcom/kernel \
	-DCMS_LOG0 \
	-DANNEX_A \
	-I$(LINUX_DIR)/arch/mips/include/asm/mach-bcm63xx \
	-I$(LINUX_DIR)/include/asm-mips/mach-bcm63xx \
    -DBRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 \
    -DBRCM_VRG_COUNTRY_CFG_FRANCE=1 \
    -DBRCM_VRG_COUNTRY_CFG_TAIWAN=0 \
    -DBRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 \
    -DCONFIG_BOARD_NEUFBOX6 \
    -DNBD_SUPPORT
    
else

MAKE_VARS+= \
    BRCM_CHIP=6358 BRCM_BOARDID=96358VW \
    XCHANGE_DIR=$(LINUX_DIR)/../broadcom-endpointdrv/xChange \
    OWRT_PKG_TOP_DIR=$(PKG_BUILD_DIR) \
    XCHANGE_BUILD_APP=Bcm6358vw_fxo \
    INC_BRCMCFM_PATH=   \
    BRCM_6358_G729_FXO=y    \
    BRCM_APP_PHONE=mgcp     \
    MGCPLOAD=1              \
    BRCM_VODSL_RANDOM_PORT=1   \
    INC_BRCMDRIVER_PRIV_PATH=$(STAGING_DIR)/usr/include/broadcom/kernel \
    INC_BRCMDRIVER_PUB_PATH=$(STAGING_DIR)/usr/include/broadcom/kernel\
    KERNEL_DIR=$(LINUX_DIR) \
    BUILD_DIR=$(BUILD_DIR) \
    XCHANGE_DSP_APP=all \
    XCHANGE_PROJ_DIR=$(LINUX_DIR)/../broadcom-endpointdrv \
    TOOLCHAIN=$(TOOLCHAIN_DIR_BIN)/.. \
    PROFILE=NB4_LOST
    
    
EXTRA_CFLAGS += \
	$(TARGET_CPPFLAGS) \
	-I$(STAGING_DIR)/usr/include/broadcom \
	-I$(STAGING_DIR)/usr/include/broadcom/linux \
	-I$(STAGING_DIR)/usr/include/broadcom/kernel \
	-DCMS_LOG0 \
	-DANNEX_A \
	-I$(LINUX_DIR)/arch/mips/include/asm/mach-bcm63xx \
	-I$(LINUX_DIR)/include/asm-mips/mach-bcm63xx \
    -DBRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 \
    -DBRCM_VRG_COUNTRY_CFG_FRANCE=1 \
    -DBRCM_VRG_COUNTRY_CFG_TAIWAN=0 \
    -DBRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 \
    -DCONFIG_BOARD_NEUFBOX4 \
	-DNBD_SUPPORT
endif

define Build/Compile
	# Compile voip_log
	$(_SINGLE)$(call Build/Compile/Default)
endef

define Package/broadcom-mgcp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vodsl $(1)/usr/sbin
endef

$(eval $(call BuildPackage,broadcom-mgcp))
