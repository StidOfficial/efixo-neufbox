#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 10749 2008-04-07 00:24:19Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=efixo-sipclient
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package-bin-ipkg.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/efixo-sipclient
  SECTION:=efixo
  SUBMENU:=Voice over IP
  CATEGORY:=Efixo applications
  TITLE:=SIP stack
  MAINTAINER:=Severin Lageder
  DEPENDS:=+TARGET_brcm63xx:kmod-broadcom-endpointdrv +TARGET_octeon:kmod-d2tech-driver \
	   +efixo-libnbd +libezxml +libtropicssl +efixo-libecom +libpthread +efixo-libbackup \
           +efixo-libetk +PACKAGE_EFIXO-SIPCLIENT_DMALLOC:dmalloc-utils
endef

define Package/efixo-sipclient/description
 SIP stack for neufbox
endef

define Package/efixo-sipclient/config
config PACKAGE_EFIXO-SIPCLIENT_DMALLOC
	bool "enable dmalloc support"
	depends on PACKAGE_efixo-sipclient
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

ifeq ($(BOX),nb4)
    MAKE_VARS+= PROFILE=NB4
    MAKE_VARS+= \
        BRCMDRIVERS_DIR=$(LINUX_DIR)/../broadcom-endpointdrv/bcmdrivers \
        XCHANGE_DIR=$(LINUX_DIR)/../broadcom-endpointdrv/xChange \
        BACKUPD=y

    EXTRA_CFLAGS += \
        -I$(STAGING_DIR)/usr/include/broadcom \
        -I$(STAGING_DIR)/usr/include/broadcom/linux \
        -I$(STAGING_DIR)/usr/include/broadcom/kernel \
        -DCMS_LOG0 \
        -DANNEX_A \
        -I$(LINUX_DIR)/include/asm-mips/mach-bcm63xx \
        -I$(STAGING_DIR)/usr/kernel \
		-DPSTN_LIFE_LINE_SUPPORT
endif
ifeq ($(BOX),nb5)
    MAKE_VARS+= PROFILE=NB5 BACKUPD=y
endif
ifeq ($(BOX),nb6)
    MAKE_VARS+= PROFILE=NB6
    MAKE_VARS+= \
		BRCMDRIVERS_DIR=$(LINUX_DIR)/../broadcom-endpointdrv/bcmdrivers \
		XCHANGE_DIR=$(LINUX_DIR)/../broadcom-endpointdrv/xChange \
		BACKUPD=y

    EXTRA_CFLAGS += \
		-I$(STAGING_DIR)/usr/include/broadcom \
		-I$(STAGING_DIR)/usr/include/broadcom/linux \
		-I$(STAGING_DIR)/usr/include/broadcom/kernel \
		-DCMS_LOG0 \
		-DANNEX_A \
		-I$(LINUX_DIR)/arch/mips/include/asm/mach-bcm63xx \
		-I$(STAGING_DIR)/usr/kernel
endif

ifeq ($(CONFIG_PACKAGE_EFIXO-SIPCLIENT_DMALLOC), y)
	MAKE_VARS += DMALLOC=y
endif

MAKE_VARS+=KERNEL_DIR=$(LINUX_DIR) EGSM=y EGSM_MODULE_ZTE=y EGSM_MODULE_HUAWEI=y \
		NB_VERSION=3_0 EVOLUTION_DNS=y
MAKE_VARS += OCTEON_MODEL=OCTEON_CN50XX TROPICSSL=y
EXTRA_CFLAGS += -DREVISION="$(shell sh -c "svnversion  ./src")"

define Package/efixo-sipclient/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/clientSip $(1)/usr/sbin
endef

$(eval $(call BuildPackage,efixo-sipclient))
