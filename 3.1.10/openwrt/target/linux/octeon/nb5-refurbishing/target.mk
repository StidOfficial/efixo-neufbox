ARCH:=mips64
BOARDNAME:=nb5 reburbishing
FEATURES:=jffs2 pci usb gpio pcmcia

LINUX_VERSION:=2.6.21.7

DEFAULT_PACKAGES +=

CFLAGS:=-Os -pipe -march=octeon -DOCTEON_TARGET=linux_64 -mabi=64 -funit-at-a-time -DVOIP_DSCP=0x2D -DTV_DSCP=0x24
