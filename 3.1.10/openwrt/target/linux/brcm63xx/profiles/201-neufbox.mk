#
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Profile/neufbox
  NAME:=neufbox
  PACKAGES:=
endef

define Profile/neufbox/Description
	Packages set for neufbox firmware
endef
$(eval $(call Profile,neufbox))

