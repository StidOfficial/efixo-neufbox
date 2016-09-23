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

obj-y := setup.o serial.o irq.o hal.o perf_counters.o octeon_info.o
obj-y += dma-octeon.o userio.o flash_setup.o
obj-y += pci_console.o
obj-y += simulator.o

obj-$(CONFIG_SMP)                     += smp.o
obj-$(CONFIG_CAVIUM_OCTEON_BOOTBUS_COMPACT_FLASH) += ebt3000_cf.o
obj-$(CONFIG_PCI)                     += pci-common.o
obj-$(CONFIG_PCI)                     += pci.o pci_chips.o i8259.o
obj-$(CONFIG_PCI_MSI)                 += msi.o
ifndef CONFIG_CAVIUM_OCTEON_2ND_KERNEL
obj-$(CONFIG_PCI)                     += pcie.o
endif
obj-$(CONFIG_CAVIUM_OCTEON_POW_ONLY_ETHERNET) += ethernet-pow.o
obj-$(CONFIG_CAVIUM_OCTEON_WATCHDOG)  += watchdog.o watchdog_nmi.o
obj-$(CONFIG_CAVIUM_OCTEON_MGMT_PORT_ETHERNET) += ethernet-mgmt-port.o
obj-$(CONFIG_CAVIUM_OCTEON_TRA)       += octeon-tra.o
obj-$(CONFIG_CAVIUM_OCTEON_GPIO)      += octeon-gpio.o

obj-y		+= boards/

clean:
	rm -f *.o

