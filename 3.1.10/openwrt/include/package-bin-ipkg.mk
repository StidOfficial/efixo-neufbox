include $(INCLUDE_DIR)/package.mk

RELEASE:=$(shell echo $(CONFIG_FIRMWARE_RELEASE)|sed 's/.*R\(.*\)/\1/')
ifeq ($(DUMP),)
  define BuildTarget/ipkg
    IPKG_NAME_$(1):=$(1)_$(VERSION)_$(PKGARCH).ipk
    IPKG_$(1):=$(PACKAGE_DIR)/$$(IPKG_NAME_$(1))
    INFO_$(1):=$(IPKG_STATE_DIR)/info/$(1).list

    compile: $$(IPKG_$(1))
    ifeq ($(CONFIG_PACKAGE_$(1)),y)
       install: $$(INFO_$(1))
    endif

    $$(IPKG_$(1)):
	wget http://packages.efixo.net/$(RELEASE)/$(BOX)/$$(IPKG_NAME_$(1)) -P $(PACKAGE_DIR)

    $$(INFO_$(1)): $$(IPKG_$(1))
	@[ -d $(TARGET_DIR)/tmp ] || mkdir -p $(TARGET_DIR)/tmp
	$(OPKG) install $$(IPKG_$(1))
	$(if $(filter-out essential,$(PKG_FLAGS)),for flag in $(filter-out essential,$(PKG_FLAGS)); do $(OPKG) flag $$$$flag $(1); done)
  endef
endif

define Build/DefaultTargets
endef
