#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=zaptel
PKG_VERSION:=1.4.12.1
PKG_RELEASE:=4

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://downloads.asterisk.org/pub/telephony/zaptel/releases/ \
        http://ftp.digium.com/pub/zaptel/releases/
PKG_MD5SUM:=71e83a020b020fa60905edecf70e95a3

include $(INCLUDE_DIR)/package.mk

define Package/zaptel14/Default
  TITLE:=Zaptel
  URL:=http://ftp.digium.com/pub/zaptel/releases
endef

define KernelPackage/zaptel14/Default
  TITLE:=Zaptel (kernel module)
  SUBMENU:=Other modules
endef

define KernelPackage/zaptel14
  $(call KernelPackage/zaptel14/Default)
  FILES:=$(PKG_BUILD_DIR)/kernel/zaptel.$(LINUX_KMOD_SUFFIX) \
  	$(PKG_BUILD_DIR)/kernel/ztdummy.$(LINUX_KMOD_SUFFIX)
  AUTOLOAD:=$(call AutoLoad,70,zaptel ztdummy)
endef

define KernelPackage/zaptel14/description
 This package contains the Zaptel core module and ztdummy driver.
endef

define KernelPackage/zaptel14-wcusb
  $(call KernelPackage/zaptel14/Default)
  DEPENDS += +kmod-zaptel14
  FILES:=$(PKG_BUILD_DIR)/kernel/wcusb.$(LINUX_KMOD_SUFFIX)
  AUTOLOAD:=$(call AutoLoad,71,wcusb)
endef

define KernelPackage/zaptel14-wcusb/description
 This package contains the Zaptel S100U usb driver.
endef

define KernelPackage/zaptel14-wctdm
  $(call KernelPackage/zaptel14/Default)
  DEPENDS += +kmod-zaptel14
  FILES:=$(PKG_BUILD_DIR)/kernel/wctdm.$(LINUX_KMOD_SUFFIX)
  AUTOLOAD:=$(call AutoLoad,71,wctdm)
endef

define KernelPackage/zaptel14-wctdm/description
 This package contains the Zaptel wctdm driver.
endef

define Package/zaptel14-util
  $(call Package/zaptel14/Default)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE+= utils
  DEPENDS += +kmod-zaptel14
endef

define Package/zaptel14-util/description
 This package contains the zaptel utils.
endef

define Package/zaptel14-libtonezone
  $(call Package/zaptel14/Default)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE+= libtonezone (library)
  DEPENDS += +kmod-zaptel14
endef

define Package/zaptel14-libtonezone/description
 This package contains the libraries for accessing zaptel/dummy drivers.
endef

MAKE_FLAGS:= \
	ARCH="$(LINUX_KARCH)" \
	CC="$(TARGET_CC) $(TARGET_CFLAGS)" \
	LD="$(TARGET_CROSS)ld" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	KVERS="$(LINUX_VERSION)" \
	KSRC="$(LINUX_DIR)" \
	TOPDIR_MODULES="zaptel ztdummy wcusb wctdm" \
	SUBDIR_MODULES=""

define Build/Compile/kmod
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(MAKE_FLAGS) \
		modules
endef

define Build/Compile/user
	$(MAKE) -C $(PKG_BUILD_DIR) \
	        ARCH="$(LINUX_KARCH)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		install-libs install-include zttest
endef

define Build/Compile
	$(call Build/Compile/kmod)
	$(call Build/Compile/user)
endef

define Build/InstallDev
	$(INSTALL_DIR)  $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/zaptel $(STAGING_DIR)/usr/include/
	$(INSTALL_DIR)  $(STAGING_DIR)/usr/lib
	$(CP)  $(PKG_INSTALL_DIR)/usr/lib/libtonezone.* $(STAGING_DIR)/usr/lib/
endef

define Package/zaptel14-util/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zttest $(1)/usr/bin/
endef

define Package/zaptel14-libtonezone/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtonezone.so.* $(1)/usr/lib/
endef

$(eval $(call KernelPackage,zaptel14))
$(eval $(call KernelPackage,zaptel14-wcusb))
$(eval $(call KernelPackage,zaptel14-wctdm))
$(eval $(call BuildPackage,zaptel14-util))
$(eval $(call BuildPackage,zaptel14-libtonezone))
