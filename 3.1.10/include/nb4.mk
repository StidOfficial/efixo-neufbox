
NB4_IPADDR		 ?= localhost

NB4_BOOTLOADER		 = $(UBOX)-05-CFE
NB4_MAIN_FIRMWARE	 = $(GENERIC_MAIN_FIRMWARE)
NB4_RESCUE_FIRMWARE      = $(GENERIC_RESCUE_FIRMWARE)
NB4_ADSL_FIRMWARE	 = $(UBOX)-ADSL-A2pB024k2
#--
NB4_IMAGE		 = $(GENERIC_IMAGE)_$(NB4_ADSL_FIRMWARE)
#--
NB4_CONFIG_VERSION	 = $(GENERIC_CONFIG_VERSION)
NB4_SEED_VERSION	 = $(GENERIC_SEED_VERSION)

#---------------------------------------------------------
NB4_MAIN_MAX_SIZE	 = 5570560
NB4_RESCUE_MAX_SIZE	 = 1572864

TOOLS=/opt/specifix/broadcom_2004d_341/i686-pc-linux-gnu/bin/
define Efixo/nb4/Install
	$(call Exec,$(CP) $(TFTPBOOT_DIR)/openwrt-$(BOARD)-vmlinux.elf $(TFTPBOOT_DIR)/vmlinux.$(BOX) || true)
	$(call Exec,$(CP) $(BIN_DIR)/openwrt-nb4-squashfs-cfe.bin $(TFTPBOOT_DIR)/$($(UBOX)_$(UPROFILE)_FIRMWARE))
endef

$(TFTPBOOT_DIR)/$(NB4_BOOTLOADER):
#	@$(call Exec,$(MAKE) -rs -C $(CFE_DIR))
#	@$(call Exec,$(MAKE) -rs -C $(TOOLS_DIR)/make-bootloader BOX=$(BOX))
#	@$(call Exec,$(TOOLS_DIR)/make-bootloader/src/make-bootloader-$(BOX) $(CFE_DIR)/images/cfe6358.bin $@)
	@$(call Exec,$(CP) $(CFE_DIR)/images/$(NB4_BOOTLOADER) $@)

$(TFTPBOOT_DIR)/$(NB4_ADSL_FIRMWARE):
#	Build adsl firmware
	@$(call Exec,$(MAKE) -C $(TOOLS_DIR)/make-adsl-firmware)
	@$(call Exec,$(TOOLS_DIR)/make-adsl-firmware/src/make-adsl-firmware $(OPENWRT_DIR)/bin/adsl_phy-6358.bin $@)
	@$(call Exec,$(MAKE) -C $(TOOLS_DIR)/make-adsl-firmware clean)
	@$(call trace,"tftp -g -r $(NB4_ADSL_FIRMWARE) $(HOST)")
	@$(call trace,"flashcp -v $(NB4_ADSL_FIRMWARE) /dev/mtd-adslphy")

$(TFTPBOOT_DIR)/$(NB4_IMAGE):
	$(call Efixo/Release/Check,$($(UBOX)_BOOTLOADER))
	$(call Efixo/Release/Check,$($(UBOX)_MAIN_FIRMWARE))
	$(call Efixo/Release/Check,$($(UBOX)_RESCUE_FIRMWARE))
	$(call Efixo/Release/Check,$($(UBOX)_ADSL_FIRMWARE))
#	fill with ones
	@$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=64k of=$@ count=128 seek=0)
#	bootloader
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB4_BOOTLOADER) seek=0)
#	main firmware
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB4_MAIN_FIRMWARE) seek=1)
#	config
#	@$(call Exec,cat /dev/zero | tr '\000' '\377' | dd bs=64k of=$@ count=10 seek=86)
#	rescue firmware
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB4_RESCUE_FIRMWARE) seek=96)
#	adsl phy
	@$(call Exec,dd bs=64k of=$@ if=$(TFTPBOOT_DIR)/$(NB4_ADSL_FIRMWARE) seek=120)
#	bootcounter
	@$(call Exec,dd if=/dev/zero bs=64k of=$@ count=1 seek=127)
#	install release

