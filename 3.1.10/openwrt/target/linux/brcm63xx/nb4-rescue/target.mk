BOARDNAME:=nb4 rescue firmware
LINUX_VERSION:=2.6.21.7

CFLAGS:=-Os -pipe -mips32 -mtune=mips32 -funit-at-a-time -DVOIP_DSCP=0x2D -DTV_DSCP=0x24 -DNB4 -DNB4_RESCUE
