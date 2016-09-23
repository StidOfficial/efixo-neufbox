# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-endpointdrv
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-endpointdrv
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=Kernel driver for telephony hardware
  FILES:=$(PKG_BUILD_DIR)/bcmdrivers/broadcom/char/endpoint/impl1/endpointdd.$(LINUX_KMOD_SUFFIX) \
    $(PKG_BUILD_DIR)/bcmdrivers/broadcom/char/dspapp/impl1/dspdd.$(LINUX_KMOD_SUFFIX)
  DEPENDS:=+kmod-broadcom-headers
  AUTOLOAD:=$(call AutoLoad,60, dspdd endpointdd)
endef

define KernelPackage/broadcom-endpointdrv/description
 This package contains the proprietary endpoint driver for the Broadcom 963xx chips.
endef

define KernelPackage/broadcom-endpointdrv/config
    source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	cp -r $(shell pwd)/src/endpointdrv-$(CONFIG_ENDPTDRV_VERSION)/* $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/bcmdrivers/broadcom/include
	ln -fs $(STAGING_DIR)/usr/include/broadcom/kernel $(PKG_BUILD_DIR)/bcmdrivers/broadcom/include/bcm963xx
	$(call Build/Prepare/Default)
endef

# kernelland
BROADCOM_CONFIG := \
	CONFIG_BCM_BCMDSP=m \
	CONFIG_BCM_ENDPOINT=m

ifeq ($(BOX),nb4)
BROADCOM_CFLAGS := \
	-I$(STAGING_DIR)/usr/include/broadcom \
	-I$(STAGING_DIR)/usr/include/broadcom/kernel \
	-I$(LINUX_DIR)/include/asm-mips/mach-bcm63xx \
	-I$(LINUX_DIR)/include \
	-I$(PKG_BUILD_DIR)/driver/include \
	-DNUM_FXO_CHANNELS="1" \
	-DXCFG_G7231_SUPPORT=1 -DXCFG_G726_SUPPORT=1 -DXCFG_G729_SUPPORT=1 -DXCFG_FAX_SUPPORT=1 -DXCFG_GSMAMR_SUPPORT=1 \
	-DDBRCM_PSTN_SUPPORT=1 -DBRCM_6358_G729_FXO  \
	-DCONFIG_BOARD_NEUFBOX4 
	
BROADCOM_VARS := \
	BRCM_CHIP=6358 BRCM_BOARDID=96358VW \
	CXC_ZIP_LIBS_ARCHIVE=mips-linux-uclibc-ar AR=mips-linux-uclibc-ar \
	XCHANGE_DSP_APP=all \
	TOOLCHAIN=$(TOOLCHAIN_DIR_BIN)/.. \
	LOCALEFLAGS="-DBRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 -DBRCM_VRG_COUNTRY_CFG_FRANCE=1 -DBRCM_VRG_COUNTRY_CFG_TAIWAN=0 -DBRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 -DCONFIG_BOARD_NEUFBOX4" \
	LOCALEFLAGS_TYPE2="-D BRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 \
		-D BRCM_VRG_COUNTRY_CFG_FRANCE=1 \
		-D BRCM_VRG_COUNTRY_CFG_TAIWAN=0 \
		-D BRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 \
		-D BRCM_6358 \
		-D HAUS_OS_LINUXKERNEL \
		-D CONFIG_BOARD_NEUFBOX4 \
		-I$(STAGING_DIR)/usr/include/broadcom/kernel" \
	KERNEL_DIR=$(LINUX_DIR) \
	XCHANGE_PROJ_DIR=$(PKG_BUILD_DIR)
endif
ifeq ($(BOX),nb6)
BROADCOM_CFLAGS := \
	-I$(STAGING_DIR)/usr/include/broadcom \
	-I$(STAGING_DIR)/usr/include/broadcom/kernel \
	-I$(LINUX_DIR)/arch/mips/include/asm/mach-bcm63xx \
	-I$(LINUX_DIR)/include \
	-I$(PKG_BUILD_DIR)/driver/include \
	-DCONFIG_BOARD_NEUFBOX6
	
BROADCOM_VARS := \
	BRCM_CHIP=6362 BRCM_BOARDID=96362VW \
	CXC_ZIP_LIBS_ARCHIVE=mips-linux-uclibc-ar AR=mips-linux-uclibc-ar \
	XCHANGE_DSP_APP=all \
	TOOLCHAIN=$(TOOLCHAIN_DIR_BIN)/.. \
	LOCALEFLAGS="-DBRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 -DBRCM_VRG_COUNTRY_CFG_FRANCE=1 -DBRCM_VRG_COUNTRY_CFG_TAIWAN=0 -DBRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 -DCONFIG_BOARD_NEUFBOX6" \
	KERNEL_DIR=$(LINUX_DIR) \
	XCHANGE_PROJ_DIR=$(PKG_BUILD_DIR)

ifeq ($(CONFIG_ENDPTDRV_VERSION),"4.06.01")
BROADCOM_CFLAGS += \
	-DNUM_FXO_CHANNELS="0" -DNUM_CHANNELS="1" \
	-DXCFG_G711_SUPPORT=1 -DXCFG_G7231_SUPPORT=1 \
	-DXCFG_G726_SUPPORT=1 -DXCFG_G729_SUPPORT=1  \
	-DXCFG_FAX_SUPPORT=1 -DXCFG_GSMAMR_SUPPORT=1 \
	-DXCFG_AMRWB_SUPPORT=1 -DXCFG_G722_SUPPORT=1 
	-DXCFG_LPCMWB_SUPPORT=1

BROADCOM_VARS += \
	LOCALEFLAGS_TYPE2="-D BRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 \
		-D BRCM_VRG_COUNTRY_CFG_FRANCE=1 \
		-D BRCM_VRG_COUNTRY_CFG_TAIWAN=0 \
		-D BRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 \
		-D BRCM_6362 \
		-D HAUS_OS_LINUXKERNEL \
		-D CONFIG_BOARD_NEUFBOX6 \
		-D CONFIG_BCM96362 \
		-I$(STAGING_DIR)/usr/include/broadcom/kernel" 
else
BROADCOM_CFLAGS += \
	-DXCFG_G7231_SUPPORT=1 -DXCFG_G726_SUPPORT=1 \
	-DXCFG_G729_SUPPORT=1 -DXCFG_FAX_SUPPORT=1 \
	-DXCFG_GSMAMR_SUPPORT=1

BROADCOM_VARS += \
	LOCALEFLAGS_TYPE2="-D BRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE=1 \
		-D BRCM_VRG_COUNTRY_CFG_FRANCE=1 \
		-D BRCM_VRG_COUNTRY_CFG_TAIWAN=0 \
		-D BRCM_VRG_COUNTRY_CFG_NORTH_AMERICA=0 \
		-D BRCM_6362 \
		-D HAUS_OS_LINUXKERNEL \
		-D CONFIG_BOARD_NEUFBOX6 \
		-D CONFIG_BCM96362 \
		-I$(STAGING_DIR)/usr/include/broadcom/kernel" 
endif


endif

	
ifeq ("$(CONFIG_ENDPTDRV_WIDEBAND)", "y")
ifeq ($(BOX),nb4)
BROADCOM_VARS += \
	BRCM_DSP_HAL=vw_wb_fxo \
	XCHANGE_BUILD_APP=Bcm6358vw_wb_fxo \
	BRCM_6358_WIDEBAND=y
endif
else
ifeq ($(BOX),nb4)
BROADCOM_VARS += \
	BRCM_DSP_HAL=vw_fxo \
	XCHANGE_BUILD_APP=Bcm6358vw_fxo \
	BRCM_6358_G729_FXO=y
endif
ifeq ($(BOX),nb6)
ifeq ($(CONFIG_ENDPTDRV_VERSION),"4.06.01")
BROADCOM_VARS += \
	BRCM_DSP_HAL=uni \
	XCHANGE_BUILD_APP=Bcm6362uni \
	BRCM_6362_SI32176_PCM_MODE=1
else
BROADCOM_VARS += \
	BRCM_DSP_HAL=advng \
	XCHANGE_BUILD_APP=Bcm6362advng \
	BRCM_6362_SI32176_PCM_MODE=1
endif

ifeq ($(strip $(BRCM_DRIVER_DECT)),m)
	NUM_IDECT_CHANNELS := 4
ifeq ($(strip $(BRCM_IDECT_CALLMGR)),y)
	BRCM_IDECT_CALLMGR=1
	BRCM_VODSL_DECT=1
else
	BRCM_IDECT_CALLMGR=0
	BRCM_VODSL_DECT=0
endif
else
	BRCM_IDECT_CALLMGR=0
	BRCM_VODSL_DECT=0
	NUM_IDECT_CHANNELS=0
endif # BRCM_DRIVER_DECTL

endif # nb6

endif

KMAKE_VARS := \
	ARCH="$(LINUX_KARCH)" \
	PATH="$(TARGET_PATH)" \
	$(BROADCOM_CONFIG) \
	$(BROADCOM_VARS) \
	EXTRA_CFLAGS="$(BROADCOM_CFLAGS)" \
	EXTRA_CXXFLAGS="$(BROADCOM_CFLAGS)" \
	XCHANGE_DIR="$(PKG_BUILD_DIR)/xChange"

KMAKE_FLAGS := -C $(LINUX_DIR) \
	CROSS_COMPILE="$(KERNEL_CROSS)"

KMAKE := $(KMAKE_VARS) $(MAKE) $(KMAKE_FLAGS)

define Build/Compile
	# Compile the kernel part
	$(_SINGLE)$(KMAKE) M=$(PKG_BUILD_DIR)/bcmdrivers/broadcom/char/dspapp/impl1/ modules
	$(_SINGLE)$(KMAKE) M=$(PKG_BUILD_DIR)/bcmdrivers/broadcom/char/endpoint/impl1/ modules
	# generate & write the values for dsp memory space allocation

endef
#
#define Build/Clean
#    #Thats all quite useless, since the build dir is removed. nonetheless, if the build dir wasn't removed, this would be the right way to doing it
#    find $(PKG_BUILD_DIR)/bcmdrivers/broadcom/char/endpoint/ \( -name '*.o' -o -name '*.a' -o -name '*.lib' -o -name '*.ko' -o -name '*.cmd' -o -name '.*.cmd' -o -name '*.c' -o -name '*.mod' \) -print -exec rm -f "{}" ";"
#    find $(PKG_BUILD_DIR)/bcmdrivers/broadcom/char/dspapp/ \( -name '*.o' -o -name '*.a' -o -name '*.lib' -o -name '*.ko' -o -name '*.cmd' -o -name '.*.cmd' -o -name '*.mod' -o -name '*.mod.c' \) -print -exec rm -f "{}" ";"
#    rm -rf $(PKG_BUILD_DIR)/xChange/dslx/obj/LinuxKernel
#    rm -rf $(PKG_BUILD_DIR)/xChange/dslx/obj/LinuxUser
#    $(KMAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR)/xChange/dslx clean
#endef

$(eval $(call KernelPackage,broadcom-endpointdrv))


