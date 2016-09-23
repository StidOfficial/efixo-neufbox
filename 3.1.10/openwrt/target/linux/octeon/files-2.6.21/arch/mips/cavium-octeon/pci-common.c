/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2005-2007 Cavium Networks
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <asm/time.h>
#include <asm/delay.h>
#include "pci-common.h"
#include "hal.h"

typeof(pcibios_map_irq) * octeon_pcibios_map_irq = NULL;
octeon_dma_bar_type_t octeon_dma_bar_type = OCTEON_DMA_BAR_TYPE_INVALID;

/**
 * Map a PCI device to the appropriate interrupt line
 *
 * @param dev    The Linux PCI device structure for the device to map
 * @param slot   The slot number for this device on __BUS 0__. Linux
 *               enumerates through all the bridges and figures out the
 *               slot on Bus 0 where this device eventually hooks to.
 * @param pin    The PCI interrupt pin read from the device, then swizzled
 *               as it goes through each bridge.
 * @return Interrupt number for the device
 */
int __init pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	if (octeon_pcibios_map_irq)
		return octeon_pcibios_map_irq(dev, slot, pin);
	else
		panic("octeon_pcibios_map_irq doesn't point to a pcibios_map_irq() function");
}


/**
 * Called to perform platform specific PCI setup
 *
 * @param dev
 * @return
 */
int pcibios_plat_dev_init(struct pci_dev *dev)
{
	/* Force the Cache line setting to 64 bytes. The standard Linux bus
	   scan doesn't seem to set it. Octeon really has 128 byte lines, but
	   Intel bridges get really upset if you try and set values above 64
	   bytes. Value is specified in 32bit words */
	pci_write_config_byte(dev, PCI_CACHE_LINE_SIZE, 64 / 4);
	/* Set latency timers for all devices */
	pci_write_config_byte(dev, PCI_LATENCY_TIMER, 48);
	if (dev->subordinate) {
		uint16_t config;

		/* Set latency timers on sub bridges */
		pci_write_config_byte(dev, PCI_SEC_LATENCY_TIMER, 48);
		/* Enable parity checking and error reporting */
		pci_read_config_word(dev, PCI_COMMAND, &config);
		config |= PCI_COMMAND_PARITY | PCI_COMMAND_SERR;
		pci_write_config_word(dev, PCI_COMMAND, config);
		/* More bridge error detection */
		pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &config);
		config |= PCI_BRIDGE_CTL_PARITY | PCI_BRIDGE_CTL_SERR;
		/* Reporting master aborts also causes SERR. Normally it
		   creates too much noise, but it might be useful in the future
		 */
		// config |= PCI_BRIDGE_CTL_MASTER_ABORT;
		pci_write_config_word(dev, PCI_BRIDGE_CONTROL, config);
	}
	return 0;
}
