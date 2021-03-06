#
# Copyright (C) 2007-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=util-linux-ng
PKG_VERSION:=2.13.0.1
PKG_RELEASE:=2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@KERNEL/linux/utils/$(PKG_NAME)/v2.13
PKG_MD5SUM:=c841dc8743905c8f0db20c9db5094f57

PKG_BUILD_DEPENDS=e2fsprogs

include $(INCLUDE_DIR)/package.mk

define Package/util-linux/Default
  SECTION:=utils
  CATEGORY:=Utilities
  URL:=http://www.kernel.org/pub/linux/utils/util-linux-ng/
endef

define Package/fdisk
$(call Package/util-linux/Default)
  TITLE:=Partition table manipulation utility
  SUBMENU=disc
endef

define Package/fdisk/description
 This package contains a utility for managing disk partition tables.
endef

define Package/cfdisk
$(call Package/util-linux/Default)
  SUBMENU:=disc
  TITLE:=Partition table manipulation utility
  DEPENDS:= +libncurses
endef

define Package/cfdisk/description
 This package contains a utility for managing disk partition tables.
endef

define Package/losetup
$(call Package/util-linux/Default)
  TITLE:=Loopback devices setup and control utility
endef

define Package/losetup/description
 This package contains a utility for managing loopback devices.
endef

define Package/mount-utils
$(call Package/util-linux/Default)
  TITLE:=Devices mount/unmounting utilities
  DEPENDS+= +libblkid +libuuid
endef

define Package/mount-utils/description
 This package contains utilities to mount/unmount devices.
endef

define Package/swap-utils
$(call Package/util-linux/Default)
  SUBMENU:=disc
  TITLE:=Swap space management utilities
  DEPENDS+= +libblkid +libuuid
endef

define Package/swap-utils/description
 This package contains a collection of tools for managing swap space:
 - mkswap
 - swapon
 - swapoff
endef

define Package/hwclock
$(call Package/util-linux/Default)
  TITLE:=Utilities for managing the hardware clock
endef

define Package/hwclock/description
 This package contains a utility for managing the hardware clock.
endef

define Package/flock
$(call Package/util-linux/Default)
  TITLE:=Manage file locks from shell scripts
endef

define Package/flock/description
  This package contains a utility for managing file locks from shell scripts.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/disk-utils mkswap
	$(MAKE) -C $(PKG_BUILD_DIR)/mount swapon losetup umount mount
	$(MAKE) -C $(PKG_BUILD_DIR)/fdisk fdisk cfdisk
	$(MAKE) -C $(PKG_BUILD_DIR)/hwclock hwclock
	$(MAKE) -C $(PKG_BUILD_DIR)/sys-utils flock
endef

define Package/fdisk/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fdisk/fdisk $(1)/sbin/
endef

define Package/cfdisk/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fdisk/cfdisk $(1)/sbin/
endef

define Package/losetup/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mount/losetup $(1)/sbin/
endef

define Package/mount-utils/install
	$(INSTALL_DIR) $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mount/{u,}mount $(1)/bin
endef

define Package/swap-utils/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/disk-utils/mkswap $(PKG_BUILD_DIR)/mount/swapon $(1)/sbin/
	ln -sf swapon $(1)/sbin/swapoff
endef

define Package/hwclock/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hwclock/hwclock $(1)/sbin/
endef

define Package/flock/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sys-utils/flock $(1)/usr/bin/
endef

$(eval $(call BuildPackage,fdisk))
$(eval $(call BuildPackage,cfdisk))
$(eval $(call BuildPackage,losetup))
$(eval $(call BuildPackage,mount-utils))
$(eval $(call BuildPackage,swap-utils))
$(eval $(call BuildPackage,hwclock))
$(eval $(call BuildPackage,flock))
