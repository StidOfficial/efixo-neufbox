/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Maxime Bizon <mbizon@freebox.fr>
 */

#include <linux/types.h>
#include <linux/pci.h>
#include <bcm63xx_cpu.h>

#include <bcmpci.h>
#include <bcm_intr.h>
#include <bcm_map_part.h>

static void bcm63xx_fixup_final(struct pci_dev *dev)
{
#if defined(CONFIG_BCM63XX_CPU_6358)
	uint32 resno;

	if (dev->bus->number == BCM_BUS_PCI) {
		switch (PCI_SLOT(dev->devfn)) {
		case 0:   
			// Move device in slot 0 to a different memory range
			// In case this is a CB device, it will be accessed via l2pmremap1
			// which will have CARDBUS_MEM bit set
			for (resno = 0; resno < 6; resno++) {
				if (dev->resource[resno].end && (dev->resource[resno].start < BCM_CB_MEM_BASE)) {
					dev->resource[resno].start += (BCM_CB_MEM_BASE - BCM_PCI_MEM_BASE);
					dev->resource[resno].end += (BCM_CB_MEM_BASE - BCM_PCI_MEM_BASE);
					dev->resource[resno].flags |= IORESOURCE_PCI_FIXED; // prevent linux from reallocating resources
				}
			}
			break;
		}
	}
#endif
#if defined(CONFIG_BCM63XX_CPU_6362)
	if (dev->bus->number == BCM_BUS_PCIE_DEVICE) {
		switch (PCI_SLOT(dev->devfn)) {
		case WLAN_ONCHIP_DEV_SLOT:
			if (((dev->device << 16) | dev->vendor) == WLAN_ONCHIP_PCI_ID) {
				dev->resource[0].start = WLAN_CHIPC_BASE;
				dev->resource[0].end = WLAN_CHIPC_BASE + WLAN_ONCHIP_RESOURCE_SIZE - 1;
			}
			break;
		}
	}
#endif
}
DECLARE_PCI_FIXUP_FINAL(PCI_ANY_ID, PCI_ANY_ID, bcm63xx_fixup_final);

static char irq_tab_bcm63xx[] __initdata = {
#if defined(CONFIG_BCM63XX_CPU_6358)
	[0] = INTERRUPT_ID_MPI,
	[1] = INTERRUPT_ID_MPI,
	[2] = INTERRUPT_ID_MPI,
#endif
#if defined(CONFIG_BCM63XX_CPU_6362)
	[WLAN_ONCHIP_DEV_SLOT] = INTERRUPT_ID_WLAN,
#endif
};

int pcibios_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
#if defined(CONFIG_BCM63XX_CPU_6362)
	if (dev->bus->number == BCM_BUS_PCIE_DEVICE)
		return bcm63xx_get_irq_number(IRQ_PCIE_RC);
#endif
	return irq_tab_bcm63xx[slot];
}

int pcibios_plat_dev_init(struct pci_dev *dev)
{
	return 0;
}
