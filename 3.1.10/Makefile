LANG	:=C
export LANG
PWD	:= $(shell pwd)
CP	:= cp -fpR
SED	:= sed -i -e
RM	:= rm -rf
empty	 =
space	 = $(empty) $(empty)
split	 = $(subst -,$(space),$(1))
split2	 = $(subst /,$(space),$(1))
qstrip	 = $(strip $(subst ",,$(1)))
#"))

boxes_list	:= $(sort $(shell ls config/))
firmwares_list  := $(shell find config/ -type f -name "*\.config" | sed -e 's|config/\(.*\)/\(.*\)\.config|\1-\2|g')

#---------------------------------------------------------
help usage:
	cat README
	@echo "   boxes: $(boxes_list)"
	@echo "   firmwares: $(firmwares_list)"

#---------------------------------------------------------
ifeq ($(words $(MAKECMDGOALS)),1)
include include/vt102.mk
Exec	 = $(call trace,"$(1)"); $(1)
include include/openwrt.mk
include include/version.mk
include include/efixo.mk
endif
include include/targets.mk
