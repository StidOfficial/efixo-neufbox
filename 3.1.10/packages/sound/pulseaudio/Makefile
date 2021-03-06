#
# Copyright (C) 2007-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pulseaudio
PKG_VERSION:=0.9.22
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://0pointer.de/lennart/projects/pulseaudio/
PKG_MD5SUM:=ca85ab470669b05e100861654cf5eb3c

PKG_FIXUP = libtool

PKG_INSTALL = 1

include $(INCLUDE_DIR)/package.mk

#TODO: split pulse into executable and library (or even better into several libraries since they're used as loadable modules, so not linked into)
define Package/pulseaudio
  SECTION:=sound
  CATEGORY:=Sound
  DEPENDS:=+libspeexdsp +libgdbm +liboil +libsamplerate +libsndfile +libatomicops +libltdl +dbus +libpthread +librt +libintl +libiconv intltool/host @BROKEN
  TITLE:=Network sound server
  URL:=http://www.pulseaudio.org
endef

define Package/pa-tools
  SECTION:=sound
  CATEGORY:=Sound
  DEPENDS:=+libgdbm +libsndfile +pulseaudio #+libpulse
  TITLE:=Tools for Pulseaudio
  URL:=http://www.pulseaudio.org
endef

CONFIGURE_ARGS += \
	--with-system-user=root \
	--with-system-group=root \
	--with-realtime-group=root \
	--with-access-group=root \
	--without-x \
	--disable-dbus \
	--disable-hal \
	--disable-gconf \
	--disable-tcpwrap \
	--disable-nls \
	--disable-solaris \
	--disable-glib2 \
	--disable-jack \
	--disable-asyncns \
	--disable-polkit \
	--disable-samplerate \
	--disable-lirc \
	--disable-bluez \
	--without-caps


CONFIGURE_VARS += \
	PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig"

#SUPP_LIBS:=-L$(STAGING_DIR)/usr/lib/libintl/lib -L$(STAGING_DIR)/usr/lib/libiconv/lib
TARGET_CFLAGS += -std=gnu99

define Package/pulseaudio/install
	$(INSTALL_DIR) \
		$(1)/usr/bin \
		$(1)/usr/lib \
		$(1)/usr/lib/pulse-$(PKG_VERSION)/modules \
		$(1)/etc/pulse

	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/usr/bin/pulseaudio \
		$(1)/usr/bin/pulseaudio

	$(INSTALL_CONF) \
		$(PKG_INSTALL_DIR)/etc/pulse/* \
		$(1)/etc/pulse

	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/*.so* \
		$(1)/usr/lib/

	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/pulse-$(PKG_VERSION)/modules/*.so \
		$(1)/usr/lib/pulse-$(PKG_VERSION)/modules/
endef

define Package/pa-tools/install
	$(INSTALL_DIR) \
		$(1)/usr/bin

	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/usr/bin/pa* \
		$(1)/usr/bin/
endef

$(eval $(call BuildPackage,pulseaudio))
$(eval $(call BuildPackage,pa-tools))
