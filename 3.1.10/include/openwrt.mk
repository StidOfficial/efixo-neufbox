OPENWRT_REVISION:= r24540

CONFIG_DIR	:= $(PWD)/config
STAMP_DIR	:= $(PWD)/stamp
OPENWRT_DIR	:= $(PWD)/openwrt
LOGS_DIR	:= $(OPENWRT_DIR)/logs
DOT_CONFIG	:= $(OPENWRT_DIR)/.config

BOX		:= $(word 1,$(call split,$(MAKECMDGOALS)))
PROFILE		:= $(word 2,$(call split,$(MAKECMDGOALS)))
TARGET		:= $(if $(word 3,$(call split,$(MAKECMDGOALS))),$(lastword $(call split,$(MAKECMDGOALS))))
FIRMWARE	:= $(BOX)-$(PROFILE)

upper		 = $(shell echo $(1) | tr "[:lower:]" "[:upper:]")
UBOX		:= $(strip $(call upper,$(BOX)))
UPROFILE	:= $(strip $(call upper,$(PROFILE)))

define OpenWRT/Script/Env
	$(if $(ENV),$(call Exec,cd $(OPENWRT_DIR) && ./scripts/env $(1)),true)
endef

#---------------------------------------------------------
ifneq ($(strip $(findstring $(FIRMWARE),$(firmwares_list))),)
PROFILE_CONFIG	:= $(CONFIG_DIR)/$(BOX)/$(if $(OPERATOR),$(OPERATOR))$(PROFILE).config

BOARD		:= $(shell sed -n -e 's/^CONFIG_TARGET_BOARD=\"\(.*\)\"/\1/p' $(PROFILE_CONFIG))
BIN_DIR		:= $(OPENWRT_DIR)/bin/$(BOARD)

MAKE_VARS	+= OPENWRT_REVISION=$(OPENWRT_REVISION)
MAKE_VARS	+= EFIXO_REVISION=$(EFIXO_REVISION)
ifeq ($(V),)
JOBS_PER_CORE	:= 4
MAKE_JOBS	?= -j$(shell echo $$(($(JOBS_PER_CORE)$(foreach i,$(shell seq 1 $(JOBS_PER_CORE)),+$(shell cut -d '-' -f 2 /sys/devices/system/cpu/online)))))
MAKE_VARS	+= MAKE_JOBS=$(MAKE_JOBS)
MAKE_FLAGS	:= $(MAKE_JOBS) BUILD_LOG=1
endif

ifneq ($(EFIXO_BUILD),1)
  override EFIXO_BUILD=1
  export EFIXO_BUILD

define OpenWRT/Setup/Config
	@echo "** [Efixo revision $(EFIXO_REVISION)] [OpenWRT revision $(OPENWRT_REVISION)]"
	@echo "** [BOX=$(BOX)] [PROFILE=$(PROFILE)] [TARGET=$(TARGET)]"
	@echo
	$(call Exec,$(RM) $(LOGS_DIR))
	$(call OpenWRT/Script/Env,switch $(FIRMWARE))
	$(call Exec,$(CP) $(PROFILE_CONFIG) $(DOT_CONFIG))
	$(call Exec,$(SED) 's|\(CONFIG_FIRMWARE_RELEASE=\).*|\1\"$($(UBOX)_$(UPROFILE)_FIRMWARE)\"|' $(DOT_CONFIG))
	$(call Exec,$(SED) 's|\(CONFIG_CONFIG_VERSION=\).*|\1\"$($(UBOX)_CONFIG_VERSION)\"|' $(DOT_CONFIG))
	$(if $(NFS),$(call Exec,$(SED) 's|\(CONFIG_PACKAGE_kmod-fs-nfs=\).*|\1y|' $(DOT_CONFIG)))
	$(if $(NFS),$(call Exec,$(SED) 's|\(CONFIG_PACKAGE_kmod-fs-nfs-common=\).*|\1y|' $(DOT_CONFIG)))
	$(call Exec,$(SED) 's|\(^CONFIG_.*=\)\"\(./tools/toolchains.*\)\"|\1\"$(PWD)/\2\"|' $(DOT_CONFIG))
	$(if $(VALID),$(call Exec,$(SED) 's|\(.*CONFIG_VALID.*\)|CONFIG_VALID=y|' $(DOT_CONFIG)))
endef
define OpenWRT/Save/Config
	if [ -n "`grep '^\#.*(.*).*' $(DOT_CONFIG)`" ]; then \
		$(call Exec,$(SED) 's|\(^\#.*\)(.*).*|\1|' -e '4 s|\(^#\).*|\1|' $(DOT_CONFIG)); \
		$(call Exec,$(SED) 's|\(^CONFIG_.*=\)\".*\(\./tools/toolchains\/.*\)\"|\1\"\2\"|' $(DOT_CONFIG)); \
		$(call Exec,$(SED) 's|\(.*CONFIG_VALID.*\)|# CONFIG_VALID is not set|' $(DOT_CONFIG)); \
		$(call Exec,$(CP) $(DOT_CONFIG) $(PROFILE_CONFIG)); \
		$(call OpenWRT/Script/Env,save); \
	else \
		$(call OpenWRT/Script/Env,revert); \
	fi
endef
endif
endif

#---------------------------------------------------------
openwrt/scripts/env/init:
	$(foreach fw,$(firmwares_list),$(call OpenWRT/Script/Env,new $(fw)))

include include/feeds.mk
include include/profiling.mk
.PHONY: openwrt/make
openwrt/make: $(STAMP_DIR)/feeds.md5
	@$(call OpenWRT/Setup/Config)
	@$(call Profiling/Start)
	@$(call Exec,$(MAKE_VARS) $(MAKE) -rs $(MAKE_FLAGS) -C $(OPENWRT_DIR) $(TARGET)) || ($(MAKE) -rs logs && false)
	@$(call Profiling/Stop)
	@$(call OpenWRT/Save/Config)

.PHONY: openwrt/install
openwrt/install: openwrt/make
	@$(call Efixo/Install)

.PHONY: openwrt/distclean
openwrt/distclean: openwrt/make
	@$(call Exec,$(RM) $(STAMP_DIR))

ERROR_EXCLUDE:=bosError|(ignored)|checking|insserv
ERROR_PATTERNS:=error:|warnings being treated as errors|failed!|relocation truncated|undefined reference| *** No rule to make target|Error
.PHONY: logs
logs:
	@find $(LOGS_DIR) -type f | xargs ls -ult | head
	@$(call warn,"--------------------------------------------------------------------------------")
	@find $(LOGS_DIR) -type f | grep -v libtool | \
		xargs grep -v -E '$(ERROR_EXCLUDE)' | grep --color -rn -B 3 -A 3 -E '$(ERROR_PATTERNS)' || true
	@$(call warn,"--------------------------------------------------------------------------------")
