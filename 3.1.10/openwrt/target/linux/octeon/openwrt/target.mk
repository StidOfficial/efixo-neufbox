
ARCH:=mips

CFLAGS:=-Os -pipe -mtune=octeon -funit-at-a-time -DOCTEON_TARGET=linux_uclibc -DVOIP_DSCP=0x2D -DTV_DSCP=0x24 -DNB5 -DNB5_MAIN
