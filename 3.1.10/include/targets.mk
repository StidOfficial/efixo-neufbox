# globals
distclean: TARGET=distclean
distclean: openwrt/distclean
logs:
# <firmware>/<targets>
define OpenWRT/Firmware/Targets
$(1): openwrt/install
$(1)-prepare: openwrt/make
$(1)-clean: openwrt/make
$(1)-menuconfig: openwrt/make
$(1)-oldconfig: openwrt/make
$(1)-kernel_menuconfig: openwrt/make
$(1)-kernel_oldconfig: openwrt/make
endef
$(foreach fw,$(firmwares_list),$(eval $(call OpenWRT/Firmware/Targets,$(fw))))

define OpenWRT/Targets
$(1)-clean: TARGET=$(2)
$(1)-prepare: TARGET=$(2)
$(1)-compile: TARGET=$(2)
$(1)-refresh: TARGET=$(2)
$(1)-install: TARGET=$(2)
$(1)-clean: openwrt/make
$(1)-prepare: openwrt/make
$(1)-compile: openwrt/make
$(1)-refresh: openwrt/make
$(1)-install: $(3)
endef

# <firmware>/<{target,package}>/<targets>
$(foreach fw,$(firmwares_list),\
	$(foreach s,target package,\
	$(eval $(call OpenWRT/Targets,$(fw)-$(s),$(s)/$(TARGET),openwrt/install))))

# <firmware>/<package[/feeds/<feeds>]>/<package>/<targets>
pkg_list := $(foreach d,package/ $(foreach feeds,$(shell ls openwrt/package/feeds/),package/feeds/$(feeds)/),\
	$(foreach p,$(filter-out Makefile feeds, $(shell ls openwrt/$(d))),$(d)$(p)))
$(foreach fw,$(firmwares_list),\
	$(foreach p,$(pkg_list),\
	$(eval $(call OpenWRT/Targets,$(fw)-$(lastword $(call split2,$(p))),$(p)/$(TARGET),openwrt/make))))

# <box>/<targets>
define Efixo/Release/Targets
$(1)-bootloader: efixo/bootloader
$(1)-adsl-phy: efixo/adsl-phy
$(1)-release: efixo/release 
endef
$(foreach box,$(boxes_list),$(eval $(call Efixo/Release/Targets,$(box))))
