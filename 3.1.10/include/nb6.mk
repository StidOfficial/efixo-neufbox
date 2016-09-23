
NB6_IPADDR		 ?= localhost

NB6_BOOTLOADER		 = $(UBOX)-BOOTLOADER-R1.34.0
NB6_MAIN_FIRMWARE	 = $(GENERIC_MAIN_FIRMWARE)
NB6_RESCUE_FIRMWARE      = $(GENERIC_RESCUE_FIRMWARE)
NB6_ADSL_FIRMWARE	 = $(UBOX)-ADSL-A2pD030q
NB6_OPENWRT_FIRMWARE	 = $(GENERIC_FIRMWARE)
NB6_NEXT_FIRMWARE	 = $(GENERIC_FIRMWARE)
#--
NB6_IMAGE		 = $(GENERIC_IMAGE)_$(NB6_ADSL_FIRMWARE)
#--
NB6_CONFIG_VERSION	 = $(GENERIC_CONFIG_VERSION)

#---------------------------------------------------------
NB6_OPENWRT_MAX_SIZE	= 11993088
NB6_MAIN_MAX_SIZE	= 11993088
NB6_RESCUE_MAX_SIZE	= 2031616

define Efixo/nb6/Install
	$(call Exec,$(CP) $(TFTPBOOT_DIR)/openwrt-$(BOARD)-vmlinux.elf $(TFTPBOOT_DIR)/vmlinux.$(BOX) || true)
	$(call Exec,$(CP) $(BIN_DIR)/openwrt-nb6-initramfs-cfe.bin $(TFTPBOOT_DIR)/$($(UBOX)_$(UPROFILE)_FIRMWARE))
endef

$(TFTPBOOT_DIR)/$(NB6_BOOTLOADER):
	@$(call Exec,env -u EFIXO_BUILD $(MAKE) -C $(PWD) $(BOX)-main-prepare)
	@$(call Exec,TOOLS=$(PWD)/openwrt/staging_dir/toolchain-mips_gcc-4.3.4_uClibc-0.9.30.1/usr/bin/mips-openwrt-linux- \
		BOOTLOADER_RELEASE=$(NB6_BOOTLOADER) \
		$(MAKE) -C $(CFE_DIR) $(BOX)-bootloader)
#	$(call Exec,BOOTLOADER_RELEASE=$(NB6_BOOTLOADER) \
		       $(MAKE) -C $(CFE_DIR) $(BOX)-bootloader)
	@$(call Exec,$(MAKE) -C $(TOOLS_DIR)/make-bootloader BOX=$(BOX))
	@$(call Exec,mv -f $(CFE_DIR)/images/cfe6362.bin $@)
#	$(TOOLS_DIR)/make-bootloader/src/make-bootloader-$(BOX) $(CFE_DIR)/images/cfe6362.bin $@
	@$(call trace,"tftp -g -r $(NB6_BOOTLOADER) $(HOST)")
	@$(call trace,"flashcp -v $(NB6_BOOTLOADER) /dev/mtd-bootloader")

$(TFTPBOOT_DIR)/$(NB6_ADSL_FIRMWARE):
#	Build adsl firmware
	@$(call Exec,$(MAKE) -C $(TOOLS_DIR)/make-adsl-firmware)
	@$(call Exec,$(TOOLS_DIR)/make-adsl-firmware/src/make-adsl-firmware $(OPENWRT_DIR)/bin/adsl_phy-6362.bin $@)
	@$(call Exec,$(MAKE) -C $(TOOLS_DIR)/make-adsl-firmware clean)
	@$(call trace,"tftp -g -r $(NB6_ADSL_FIRMWARE) $(HOST)")
	@$(call trace,"flashcp -v $(NB6_ADSL_FIRMWARE) /dev/mtd-adslphy")

$(TFTPBOOT_DIR)/$(NB6_IMAGE):
#	$(call Efixo/Release/Check,$($(UBOX)_BOOTLOADER))
	$(call Efixo/Release/Check,$($(UBOX)_MAIN_FIRMWARE))
	$(call Efixo/Release/Check,$($(UBOX)_RESCUE_FIRMWARE))
	$(call Efixo/Release/Check,$($(UBOX)_ADSL_FIRMWARE))
#	fill with ones
	@$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=64k of=$@ count=256 seek=0)
#	bootloader
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB6_BOOTLOADER) seek=0)
#	main firmware
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB6_MAIN_FIRMWARE) seek=1)
#	config
#	$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=64k of=$@ count=24 seek=184)
#	adsl phy
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB6_ADSL_FIRMWARE) seek=208)
#	rescue firmware
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB6_RESCUE_FIRMWARE) seek=224)
#	bootcounter
	@$(call Exec,dd if=/dev/zero bs=64k of=$@ count=1 seek=255)
#	install release

