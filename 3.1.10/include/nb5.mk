
NB5_IPADDR		 ?= 192.168.22.1

NB5_BOOTLOADER		 = $(UBOX)-BOOTLOADER-R1.0.0
NB5_MAIN_FIRMWARE	 = $(GENERIC_MAIN_FIRMWARE)
NB5_RESCUE_FIRMWARE	 = $(GENERIC_RESCUE_FIRMWARE)
#--
NB5_IMAGE		 = $(GENERIC_IMAGE)
#--
NB5_CONFIG_VERSION	 = $(GENERIC_CONFIG_VERSION)

#---------------------------------------------------------
NB5_MAIN_MAX_SIZE	 = 12582912
NB5_RESCUE_MAX_SIZE	 = 2621440

define Efixo/nb5/Install
	$(call Exec,$(CP) $(TFTPBOOT_DIR)/openwrt-$(BOARD)-vmlinux.elf $(TFTPBOOT_DIR)/vmlinux.$(BOX) || true)
	$(call Exec,$(CP) $(BIN_DIR)/openwrt-$(BOARD)-nb5 $(TFTPBOOT_DIR)/$($(UBOX)_$(UPROFILE)_FIRMWARE))
endef

$(TFTPBOOT_DIR)/$(NB5_BOOTLOADER):
#	@$(call Exec,OCTEON_ROOT=$(UBOOT_DIR)/octeon_dir \
	OCTEON_MODEL=OCTEON_CN50XX \
	PATH=$(PATH):$(UBOOT_DIR)/octeon_dir/tools/bin \
	OCTEON_CPPFLAGS_GLOBAL_ADD="-DUSE_RUNTIME_MODEL_CHECKS=1 -DCVMX_ENABLE_PARAMETER_CHECKING=0 -DCVMX_ENABLE_CSR_ADDRESS_CHECKING=0 -DCVMX_ENABLE_POW_CHECKS=0" \
		$(MAKE) -C $(UBOOT_DIR) clobber)
#	@$(call Exec,OCTEON_ROOT=$(UBOOT_DIR)/octeon_dir \
	OCTEON_MODEL=OCTEON_CN50XX \
	PATH=$(PATH):$(UBOOT_DIR)/octeon_dir/tools/bin \
	OCTEON_CPPFLAGS_GLOBAL_ADD="-DUSE_RUNTIME_MODEL_CHECKS=1 -DCVMX_ENABLE_PARAMETER_CHECKING=0 -DCVMX_ENABLE_CSR_ADDRESS_CHECKING=0 -DCVMX_ENABLE_POW_CHECKS=0" \
		$(MAKE) -C $(UBOOT_DIR) octeon_nb5_config)
#	@$(call Exec,OCTEON_ROOT=$(UBOOT_DIR)/octeon_dir \
	OCTEON_MODEL=OCTEON_CN50XX \
	PATH=$(PATH):$(UBOOT_DIR)/octeon_dir/tools/bin \
	OCTEON_CPPFLAGS_GLOBAL_ADD="-DUSE_RUNTIME_MODEL_CHECKS=1 -DCVMX_ENABLE_PARAMETER_CHECKING=0 -DCVMX_ENABLE_CSR_ADDRESS_CHECKING=0 -DCVMX_ENABLE_POW_CHECKS=0" \
		$(MAKE) -C $(UBOOT_DIR))
	@$(call Exec,$(MAKE) -C $(TOOLS_DIR)/make-bootloader BOX=$(BOX))
	@$(call Exec,$(TOOLS_DIR)/make-bootloader/src/make-bootloader-$(BOX) $(PWD)/u-boot/u-boot-octeon_nb5.bin $@)

$(TFTPBOOT_DIR)/$(NB5_ADSL_FIRMWARE):

$(TFTPBOOT_DIR)/$(NB5_IMAGE):
	$(call Efixo/Release/Check,$($(UBOX)_BOOTLOADER))
	$(call Efixo/Release/Check,$($(UBOX)_MAIN_FIRMWARE))
	$(call Efixo/Release/Check,$($(UBOX)_RESCUE_FIRMWARE))
#	fill with ones
	@$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=128k of=$@ count=128 seek=0)
#	bootloader
	@$(call Exec,dd bs=128k of=$@ if=$(TFTPBOOT_DIR)/$(NB5_BOOTLOADER) seek=0)
#	bootloader nvram
#	@$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=128k of=$@ count=1 seek=3)
#	main firmware
	@$(call Exec,dd bs=128k of=$@ if=$(TFTPBOOT_DIR)/$(NB5_MAIN_FIRMWARE) seek=4)
#	rescue firmware
	@$(call Exec,dd bs=128k of=$@ if=$(TFTPBOOT_DIR)/$(NB5_RESCUE_FIRMWARE) seek=100)
#	config
	@$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=128k of=$@ count=8 seek=120)
#	install release

