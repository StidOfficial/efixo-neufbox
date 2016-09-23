
NETWORK_DEVICES_MENU:=Network Devices

define KernelPackage/cavium-octeon-ethernet
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Cavium Octeon Ethernet
  FILES:=$(LINUX_DIR)/drivers/net/cavium-ethernet/cavium-ethernet.$(LINUX_KMOD_SUFFIX)
  KCONFIG:=CONFIG_CAVIUM_ETHERNET
  DEPENDS:=@LINUX_2_6 @TARGET_octeon
endef

define KernelPackage/cavium-octeon-ethernet/description
 Kernel modules for Cavium Octeon Ethernet.
endef
$(eval $(call KernelPackage,cavium-octeon-ethernet))

