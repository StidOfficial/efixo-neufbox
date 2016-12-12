#!/bin/sh
cat /dev/zero | tr '\000' '\377' | dd bs=64k of=NB4-MAIN-FULL count=128 seek=0
dd bs=64k of=NB4-MAIN-FULL if=./bin/brcm63xx/openwrt-brcm63xx-generic-NEUFBOX4-SER-squashfs-cfe.bin seek=1
dd if=/dev/zero bs=64k of=NB4-MAIN-FULL count=1 seek=127
