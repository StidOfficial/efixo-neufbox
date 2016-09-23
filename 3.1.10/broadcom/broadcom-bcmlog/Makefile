# 
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=broadcom-bcmlog
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-bcmlog
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=63xx bcmlog driver
  FILES:=$(PKG_BUILD_DIR)/bcmlog.$(LINUX_KMOD_SUFFIX) 
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers
  AUTOLOAD:=$(call AutoLoad,45, bcmlog)
endef

define KernelPackage/broadcom-bcmlog/description
 This package contains the proprietary bcmlog for the Broadcom 963xx chips.
endef

define Build/Prepare
	$(CP) src/* $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
	LINUX_DIR="$(LINUX_DIR)" \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,broadcom-bcmlog))
