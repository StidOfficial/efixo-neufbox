#
# Copyright (C) 2006-2010 Efixo
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-pktengine
PKG_RELEASE:=1

SRC_DIR=./src-$(call qstrip,$(CONFIG_NEUFBOX_SOC_TYPE))

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-pktengine
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=63xx pktflow driver
  FILES:=$(PKG_BUILD_DIR)/pktflow.$(LINUX_KMOD_SUFFIX)
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers
  AUTOLOAD:=$(call AutoLoad,48, pktflow)
endef

define KernelPackage/broadcom-pktengine/description
This package contains the proprietary pktengine (flowcache) for the
Broadcom 963xx chips.
endef

define Build/Prepare
	$(CP) $(SRC_DIR)/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
		$(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,broadcom-pktengine))
