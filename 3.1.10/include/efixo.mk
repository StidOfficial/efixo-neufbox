ifneq ($(strip $(findstring $(BOX),$(boxes_list))),)

TOOLS_DIR	:= $(PWD)/tools
UBOOT_DIR	:= $(PWD)/u-boot
CFE_DIR		:= $(PWD)/cfe
TFTPBOOT_DIR	?= /tftpboot
HOST		?= $(shell ip route show | sed -n -e 's/.*scope link \+src \+\([^ ]\+\).*$$/\1/p')
EFIXO_REVISION	 = $(shell $(OPENWRT_DIR)/scripts/getver.sh)

include include/$(BOX).mk

define Efixo/Size/Check
	if [ "`stat -c%s $(2)`" -gt "$(1)" ]; then \
		echo "firmware to big stat -c%s $(2) > $(1)"; false; \
	fi
endef

define Efixo/Install
	$(call Exec,$(CP) $(BIN_DIR)/openwrt-$(BOARD)-vmlinux.elf $(TFTPBOOT_DIR)/ || true)
	$(call Exec,$(CP) $(BIN_DIR)/system-$(BOX).xml $(TFTPBOOT_DIR)/$($(UBOX)_CONFIG_VERSION) || true)
	$(if $($(UBOX)_SEED_VERSION),$(call Exec,xxd -c 64 -ps $(BIN_DIR)/seed-$(BOX).bin > $(TFTPBOOT_DIR)/$($(UBOX)_SEED_VERSION) || true))
	$(call Efixo/$(BOX)/Install)
	$(call Exec,$(CP) $(TFTPBOOT_DIR)/$($(UBOX)_$(UPROFILE)_FIRMWARE) $(TFTPBOOT_DIR)/openwrt-$(FIRMWARE))
	$(call Exec,$(CP) $(TFTPBOOT_DIR)/openwrt-$(FIRMWARE) $(BIN_DIR)/openwrt-$(FIRMWARE))
	$(if $(NO_REV),,$(call Exec,$(CP) $(TFTPBOOT_DIR)/$($(UBOX)_$(UPROFILE)_FIRMWARE) $(TFTPBOOT_DIR)/$($(UBOX)_$(UPROFILE)_FIRMWARE)-$(EFIXO_REVISION)))
	$(call Efixo/Size/Check,$($(UBOX)_$(UPROFILE)_MAX_SIZE),$(TFTPBOOT_DIR)/openwrt-$(FIRMWARE))
	$(call trace,$(foreach h,$(HOST),"tftp -b 20000 -g -r $($(UBOX)_$(UPROFILE)_FIRMWARE) $(h)"))
	$(call trace,$(foreach h,$(HOST),"tftp -b 20000 -g -r openwrt-$(FIRMWARE) $(h)"))
	$(call trace,"flashcp -v openwrt-$(FIRMWARE) /dev/mtd-$(PROFILE)")
endef

# Generic targets
.PHONY: $(TFTPBOOT_DIR)/$($(UBOX)_BOOTLOADER)

.PHONY: $(TFTPBOOT_DIR)/$($(UBOX)_MAIN_FIRMWARE)
$(TFTPBOOT_DIR)/$($(UBOX)_MAIN_FIRMWARE):
	@$(call Exec,env -u EFIXO_BUILD -u VALID RELEASE_BUILD=1 $(MAKE) -rs -C $(PWD) $(BOX)-main)

.PHONY: $(TFTPBOOT_DIR)/$($(UBOX)_RESCUE_FIRMWARE)
$(TFTPBOOT_DIR)/$($(UBOX)_RESCUE_FIRMWARE):
	@$(call Exec,env -u EFIXO_BUILD -u VALID RELEASE_BUILD=1 $(MAKE) -rs -C $(PWD) $(BOX)-rescue)

.PHONY: $(TFTPBOOT_DIR)/$($(UBOX)_ADSL_FIRMWARE)
$(TFTPBOOT_DIR)/$($(UBOX)_ADSL_FIRMWARE): $(TFTPBOOT_DIR)/$($(UBOX)_MAIN_FIRMWARE)

.PHONY: $(TFTPBOOT_DIR)/$($(UBOX)_IMAGE)
ifneq ($(I_DO_NOT_WANT_REBUILD),1)
$(TFTPBOOT_DIR)/$($(UBOX)_IMAGE): efixo/bootloader efixo/main-firmware efixo/rescue-firmware efixo/adsl-phy
endif

efixo/bootloader: $(TFTPBOOT_DIR)/$($(UBOX)_BOOTLOADER)
efixo/main-firmware: $(TFTPBOOT_DIR)/$($(UBOX)_MAIN_FIRMWARE)
efixo/rescue-firmware: $(TFTPBOOT_DIR)/$($(UBOX)_RESCUE_FIRMWARE)
efixo/adsl-phy: $(TFTPBOOT_DIR)/$($(UBOX)_ADSL_FIRMWARE)
efixo/image: $(TFTPBOOT_DIR)/$($(UBOX)_IMAGE)
-include include/note.mk
efixo/release: efixo/image
	@$(call Efixo/Release)

$(BOX)-note:
	@$(call Efixo/Release)
endif

string="azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN0123456789\.,;:!\*&~\"/\#'{([+-|\`_^@)]=}%$$"
.PHONY: passwd
passwd:
	makepasswd --chars 14 --count 40 --crypt-md5 --string=${string}
