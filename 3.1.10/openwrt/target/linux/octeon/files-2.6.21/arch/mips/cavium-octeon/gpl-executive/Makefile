#
# Makefile for the Cavium Octeon specific kernel interface routines
# under Linux.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2005-2007 Cavium Networks
#

source:=$(srctree)/$(src)

EXTRA_CFLAGS += -I $(obj)/config -I $(source)/config

executive-files := cvmx-bootmem.o
executive-files += cvmx-cmd-queue.o
executive-files += cvmx-dma-engine.o
executive-files += cvmx-fpa.o
executive-files += cvmx-helper.o
executive-files += cvmx-helper-board.o
executive-files += cvmx-helper-errata.o
executive-files += cvmx-helper-fpa.o
executive-files += cvmx-helper-loop.o
executive-files += cvmx-helper-npi.o
executive-files += cvmx-helper-rgmii.o
executive-files += cvmx-helper-sgmii.o
executive-files += cvmx-helper-spi.o
executive-files += cvmx-helper-util.o
executive-files += cvmx-helper-xaui.o
executive-files += cvmx-l2c.o
executive-files += cvmx-mgmt-port.o
executive-files += cvmx-pcie.o
executive-files += cvmx-pko.o
executive-files += cvmx-raid.o
executive-files += cvmx-spi4000.o
executive-files += cvmx-spi.o
executive-files += cvmx-sysinfo.o
executive-files += cvmx-tra.o
executive-files += cvmx-twsi.o
executive-files += cvmx-warn.o
executive-files += octeon-model.o
executive-files += octeon-pci-console.o

obj-y := $(executive-files) cvmx-linux-kernel-exports.o 

executive-obj-files := $(executive-files:%=$(obj)/%)
executive-src-files := $(executive-obj-files:%.o=%.c)
cvmx-linux-kernel-exports.o $(executive-src-files): $(obj)/config/cvmx-config.h

#$(executive-src-files):
#	$(Q)ln -fs $(@:$(obj)/%.c=$(OCTEON_ROOT)/executive/%.c) $@

$(obj)/config/cvmx-config.h: $(source)/config/executive-config.h
#	cd $(obj) && cvmx-config $< 

clean:
	rm -f *.o $(executive-src-files)

