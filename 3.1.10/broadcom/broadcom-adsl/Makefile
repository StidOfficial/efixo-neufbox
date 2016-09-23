
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/host-build.mk

PKG_CONFIG_DEPENDS+=CONFIG_NEUFBOX_SOC_TYPE

PKG_NAME:=broadcom-adsl
PKG_RELEASE:=1

HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/$(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))-$(call qstrip,$(CONFIG_NEUFBOX_SOC_TYPE))
PATCH_DIR:=./patches-$(call qstrip,$(CONFIG_NEUFBOX_SOC_TYPE))
SRC_DIR:=./src-$(call qstrip,$(CONFIG_NEUFBOX_SOC_TYPE))

include $(INCLUDE_DIR)/package-bin-ipkg.mk

define KernelPackage/broadcom-adsl
  SUBMENU:=Proprietary Broadcom 963xx platform drivers
  SUBMENUDEP:=@TARGET_brcm63xx
  TITLE:=Kernel driver for ADSL
  FILES:=$(PKG_BUILD_DIR)/adsldd.$(LINUX_KMOD_SUFFIX)
  DEPENDS:=@TARGET_brcm63xx +kmod-broadcom-headers
endef

define KernelPackage/broadcom-adsl/description
 This package contains the proprietary adsl driver for the Broadcom 963xx chips.
endef

define Package/adsl-phy
  SECTION:=broadcom
  CATEGORY:=Broadcom applications
  TITLE:=adsl driver
  DEPENDS:=kmod-broadcom-adsl
endef

define Package/adsl-phy/description
  This package install the adsl driver in the rootfs.
endef

define Build/Prepare
	$(CP) $(SRC_DIR)/* $(PKG_BUILD_DIR)/
	$(call Build/Prepare/Default)
endef

define Package/adsl-phy/install
	$(INSTALL_DIR) $(1)/etc/default
	$(CP) $(HOST_BUILD_DIR)/adsl_phy.bin $(1)/etc/default
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
define Build/Compile
	STAGING_DIR="$(STAGING_DIR)" \
		    $(MAKE) $(KERNEL_MAKEOPTS) M=$(PKG_BUILD_DIR) modules

endef

define Host/Prepare
	$(CP) $(SRC_DIR)/* $(HOST_BUILD_DIR)/
	$(call Host/Patch/Default)
	$(call Host/Prepare/Default)
endef

define Host/Compile
	$(MAKE) -C $(HOST_BUILD_DIR)
endef

define Host/Install
	$(CP) $(HOST_BUILD_DIR)/adsl_phy.bin $(BIN_DIR)/../adsl_phy-$(CONFIG_NEUFBOX_SOC_TYPE).bin 
endef


$(eval $(call KernelPackage,broadcom-adsl))
$(eval $(call BuildPackage,adsl-phy))
