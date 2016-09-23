BOARDNAME:=nb6 main firmware
LINUX_VERSION:=2.6.30.10

CFLAGS:=-Os -pipe -mips32 -mtune=mips32 -funit-at-a-time -DVOIP_DSCP=0x2D -DTV_DSCP=0x24 -DNB6 -DNB6_MAIN
