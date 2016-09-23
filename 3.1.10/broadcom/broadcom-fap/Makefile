# 
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-fap
PKG_RELEASE:=1

PKG_CONFIG_DEPENDS+=CONFIG_PACKAGE_kmod-broadcom-ethernet
PKG_CONFIG_DEPENDS+=CONFIG_PACKAGE_kmod-broadcom-pktdma

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-fap
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=63xx FAP driver
  FILES:=$(PKG_BUILD_DIR)/bcmfap.$(LINUX_KMOD_SUFFIX) 
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers +kmod-broadcom-bcmlog
  AUTOLOAD:=$(call AutoLoad,49, bcmfap)
  KCONFIG:=CONFIG_BCM_FAP=y
endef

define KernelPackage/broadcom-fap/description
 This package contains the proprietary FAP for the Broadcom 963xx chips.
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,broadcom-fap))
