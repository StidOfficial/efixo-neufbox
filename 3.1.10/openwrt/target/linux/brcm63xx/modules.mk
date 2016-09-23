#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

NETWORK_DEVICES_MENU:=Network Devices
SPI_MENU:=SPI Support
HWMON_MENU:=Hardware Monitoring Support
OTHER_MENU:=Other modules

define KernelPackage/broadcom-xtmrt
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Broadcom XTMRT driver
  FILES:=$(LINUX_DIR)/drivers/net/bcmxtmrt.$(LINUX_KMOD_SUFFIX)
  KCONFIG:=CONFIG_BCM_XTMRT
  DEPENDS:=@LINUX_2_6 @TARGET_brcm63xx +kmod-atm
endef

define KernelPackage/broadcom-xtmrt/description
 Kernel modules for Broadcom XTMRT.
endef
$(eval $(call KernelPackage,broadcom-xtmrt))


define KernelPackage/broadcom-spi
  SUBMENU:=$(SPI_MENU)
  TITLE:=Broadcom SPI driver
  FILES:=$(LINUX_DIR)/drivers/spi/bcm_spi.$(LINUX_KMOD_SUFFIX)
  KCONFIG:= CONFIG_SPI=y \
	  CONFIG_SPI_MASTER=y\
	  CONFIG_SPI_BCM
  AUTOLOAD:=$(call AutoLoad,10,bcm_spi)
  DEPENDS:=@LINUX_2_6 @TARGET_brcm63xx
endef

define KernelPackage/broadcom-spi/description
 Kernel modules for Broadcom SPI.
endef
$(eval $(call KernelPackage,broadcom-spi))


define KernelPackage/broadcom-hsspi
  SUBMENU:=$(SPI_MENU)
  TITLE:=Broadcom High Speed SPI driver
  FILES:=$(LINUX_DIR)/drivers/spi/bcm63xx_hsspi.$(LINUX_KMOD_SUFFIX)
  KCONFIG:= CONFIG_SPI=y \
	  CONFIG_SPI_MASTER=y\
	  CONFIG_SPI_HS_BCM
  AUTOLOAD:=$(call AutoLoad,10,bcm63xx_hsspi)
  DEPENDS:=@LINUX_2_6 @TARGET_brcm63xx
endef

define KernelPackage/broadcom-hsspi/description
 Kernel modules for Broadcom SPI.
endef
$(eval $(call KernelPackage,broadcom-hsspi))


define KernelPackage/nb6hwmon
  SUBMENU:=$(HWMON_MENU)
  TITLE:=nb6 hwmon driver
  FILES:=$(LINUX_DIR)/drivers/hwmon/nb6_hwmon.$(LINUX_KMOD_SUFFIX)
  KCONFIG:=CONFIG_SENSORS_NB6
  AUTOLOAD:=$(call AutoLoad,60,nb6_hwmon)
  DEPENDS:=@LINUX_2_6 @TARGET_brcm63xx kmod-hwmon-core +kmod-i2c-core
endef

define KernelPackage/nb6hwmon/description
 Kernel modules for nb6 hwmon.
endef
$(eval $(call KernelPackage,nb6hwmon))

define KernelPackage/nb6pwm
  SUBMENU:=$(OTHER_MENU)
  TITLE:=nb6 pwm driver
  FILES:=$(LINUX_DIR)/drivers/misc/nb6_pwm.$(LINUX_KMOD_SUFFIX)
  KCONFIG:=CONFIG_NB6_PWM
  AUTOLOAD:=$(call AutoLoad,60,nb6_pwm)
  DEPENDS:=@LINUX_2_6 @TARGET_brcm63xx +kmod-i2c-core
endef

define KernelPackage/nb6pwm/description
 Kernel modules for nb6 pwm.
endef
$(eval $(call KernelPackage,nb6pwm))
