/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 Cavium Networks
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <asm/time.h>
#include <asm/delay.h>
#include "hal.h"
#include "cvmx-pcie.h"
#include "pci-common.h"


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
int __init octeon_pcie_pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	/* The EBH5600 board with the PCI to PCIe bridge mistakenly wires the
	   first slot for both device id 2 and interrupt A. According to the
	   PCI spec, device id 2 should be C. The following kludge attempts to
	   fix this */
	if (strstr(octeon_board_type_string(), "EBH5600") &&
	    dev->bus && dev->bus->parent) {
		/* Iterate all the way up the device chain and find the root
		   bus */
		while (dev->bus && dev->bus->parent)
			dev = to_pci_dev(dev->bus->bridge);
		/* If the root bus is number 0 and the PEX 8114 is the root,
		   assume we are behind the miswired bus. We need to correct
		   the swizzle level by two. Yuck */
		if ((dev->bus->number == 0) &&
		    (dev->vendor == 0x10b5) && (dev->device == 0x8114)) {
			/* The pin field is one based, not zero. We need to
			   swizzle it by minus two */
			pin = ((pin - 3) & 3) + 1;
		}
	}
	/* The -1 is because pin starts with one, not zero. It might be that
	   this equation needs to include the slot number, but I don't have
	   hardware to check that against */
	return pin - 1 + OCTEON_IRQ_PCI_INT0;
}

/**
 * Read a value from configuration space
 *
 * @param bus
 * @param devfn
 * @param reg
 * @param size
 * @param val
 * @return
 */
static inline int octeon_pcie_read_config(int pcie_port, struct pci_bus *bus,
					  unsigned int devfn, int reg, int size,
					  u32 * val)
{
	octeon_cvmemctl_t cvmmemctl;
	octeon_cvmemctl_t cvmmemctl_save;
	int bus_number = bus->number;

	/* We need to force the bus number to be zero on the root bus. Linux
	   numbers the 2nd root bus to start after all busses on root 0 */
	if (bus->parent == NULL)
		bus_number = 0;

	/* PCIe only has a single device connected to Octeon. It is always
	   device ID 0. Don't bother doing reads for other device IDs on the
	   first segment */
	if ((bus_number == 0) && (devfn >> 3 != 0))
		return PCIBIOS_FUNC_NOT_SUPPORTED;

	/* The following is a workaround for the CN57XX, CN56XX, CN55XX, and
	   CN54XX errata with PCIe config reads from non existent devices.
	   These chips will hang the PCIe link if a config read is performed
	   that causes a UR response */
	if (OCTEON_IS_MODEL(OCTEON_CN56XX_PASS1) ||
	    OCTEON_IS_MODEL(OCTEON_CN56XX_PASS1_1)) {
		/* For our EBH5600 board, port 0 has a bridge with two PCI-X
		   slots. We need a new special checks to make sure we only
		   probe valid stuff */
		/* The PCIe->PCI-X bridge only respondes to device ID 0,
		   function 0-1 */
		if ((bus_number == 0) && (devfn >= 2))
			return PCIBIOS_FUNC_NOT_SUPPORTED;
		/* The PCI-X slots are device ID 2,3. Assume soemone is
		   plugging something into the first slot and allow device ID
		   2. If the second slot is being used, this if statement must
		   be updated */
		if ((bus_number == 1) && (devfn >> 3 != 2))
			return PCIBIOS_FUNC_NOT_SUPPORTED;
		/* Version of the above "if" for using both slots */
		if ((bus_number == 1) &&
		    !((devfn >> 3 == 2) || (devfn >> 3 == 3)))
			return PCIBIOS_FUNC_NOT_SUPPORTED;

		/* Shorten the DID timeout so bus errors for PCIe config reads
		   from non existent devices happen faster. This allows us to
		   continue booting even if the above "if" checks are wrong.
		   Once one of these errors happens, the PCIe port is dead */
		cvmmemctl_save.u64 = __read_64bit_c0_register($11, 7);
		cvmmemctl.u64 = cvmmemctl_save.u64;
		cvmmemctl.s.didtto = 2;
		__write_64bit_c0_register($11, 7, cvmmemctl.u64);
	}

#if PCI_CONFIG_SPACE_DELAY
	udelay(PCI_CONFIG_SPACE_DELAY);
#endif
	// printk("octeon_pcie_read_config(pcie_port=%d, bus=%d, devfn=0x%x,
	// reg=0x%x, size=%d, val=%p)\n",
	// pcie_port, bus_number, devfn, reg, size, val);

	switch (size) {
	case 4:
		*val = cvmx_pcie_config_read32(pcie_port, bus_number,
					       devfn >> 3, devfn & 0x7, reg);
		break;
	case 2:
		*val = cvmx_pcie_config_read16(pcie_port, bus_number,
					       devfn >> 3, devfn & 0x7, reg);
		break;
	case 1:
		*val = cvmx_pcie_config_read8(pcie_port, bus_number, devfn >> 3,
					      devfn & 0x7, reg);
		break;
	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}
	// printk("octeon_pcie_read_config val=0x%x\n", *val);
	if (OCTEON_IS_MODEL(OCTEON_CN56XX_PASS1) ||
	    OCTEON_IS_MODEL(OCTEON_CN56XX_PASS1_1))
		__write_64bit_c0_register($11, 7, cvmmemctl_save.u64);
	return PCIBIOS_SUCCESSFUL;
}

static int octeon_pcie0_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 * val)
{
	return octeon_pcie_read_config(0, bus, devfn, reg, size, val);
}

static int octeon_pcie1_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 * val)
{
	return octeon_pcie_read_config(1, bus, devfn, reg, size, val);
}



/**
 * Write a value to PCI configuration space
 *
 * @param bus
 * @param devfn
 * @param reg
 * @param size
 * @param val
 * @return
 */
static inline int octeon_pcie_write_config(int pcie_port, struct pci_bus *bus,
					   unsigned int devfn, int reg,
					   int size, u32 val)
{
	int bus_number = bus->number;
	/* We need to force the bus number to be zero on the root bus. Linux
	   numbers the 2nd root bus to start after all busses on root 0 */
	if (bus->parent == NULL)
		bus_number = 0;

#if PCI_CONFIG_SPACE_DELAY
	udelay(PCI_CONFIG_SPACE_DELAY);
#endif
	// printk("octeon_pcie_write_config(pcie_port=%d, bus=%d, devfn=0x%x,
	// reg=0x%x, size=%d, val=0x%x)\n",
	// pcie_port, bus_number, devfn, reg, size, val);
	switch (size) {
	case 4:
		cvmx_pcie_config_write32(pcie_port, bus_number, devfn >> 3,
					 devfn & 0x7, reg, val);
		return PCIBIOS_SUCCESSFUL;
	case 2:
		cvmx_pcie_config_write16(pcie_port, bus_number, devfn >> 3,
					 devfn & 0x7, reg, val);
		return PCIBIOS_SUCCESSFUL;
	case 1:
		cvmx_pcie_config_write8(pcie_port, bus_number, devfn >> 3,
					devfn & 0x7, reg, val);
		return PCIBIOS_SUCCESSFUL;
	}
	return PCIBIOS_FUNC_NOT_SUPPORTED;
}

static int octeon_pcie0_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val)
{
	return octeon_pcie_write_config(0, bus, devfn, reg, size, val);
}

static int octeon_pcie1_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val)
{
	return octeon_pcie_write_config(1, bus, devfn, reg, size, val);
}

static struct pci_ops octeon_pcie0_ops = {
	octeon_pcie0_read_config,
	octeon_pcie0_write_config,
};

static struct resource octeon_pcie0_mem_resource = {
	.name = "Octeon PCIe0 MEM",
	.flags = IORESOURCE_MEM,
};

static struct resource octeon_pcie0_io_resource = {
	.name = "Octeon PCIe0 IO",
	.flags = IORESOURCE_IO,
};

static struct pci_controller octeon_pcie0_controller = {
	.pci_ops = &octeon_pcie0_ops,
	.mem_resource = &octeon_pcie0_mem_resource,
	.io_resource = &octeon_pcie0_io_resource,
};

static struct pci_ops octeon_pcie1_ops = {
	octeon_pcie1_read_config,
	octeon_pcie1_write_config,
};

static struct resource octeon_pcie1_mem_resource = {
	.name = "Octeon PCIe1 MEM",
	.flags = IORESOURCE_MEM,
};

static struct resource octeon_pcie1_io_resource = {
	.name = "Octeon PCIe1 IO",
	.flags = IORESOURCE_IO,
};

static struct pci_controller octeon_pcie1_controller = {
	.pci_ops = &octeon_pcie1_ops,
	.mem_resource = &octeon_pcie1_mem_resource,
	.io_resource = &octeon_pcie1_io_resource,
};


/**
 * Initialize the Octeon PCIe controllers
 *
 * @return
 */
static int __init octeon_pcie_setup(void)
{
	cvmx_npei_ctl_status_t npei_ctl_status;
	int result;

	/* These chips don't have PCIe */
	if (!octeon_has_feature(OCTEON_FEATURE_PCIE))
		return 0;

	/* Point pcibios_map_irq() to the PCIe version of it */
	octeon_pcibios_map_irq = octeon_pcie_pcibios_map_irq;

	/* Use the PCIe based DMA mappings */
	octeon_dma_bar_type = OCTEON_DMA_BAR_TYPE_PCIE;

	/* Mark the Octeon CSR region as IO */
	iomem_resource.start = (1ull << 48);
	iomem_resource.end = (2ull << 48) - 1;

	/* PCIe I/O range. It is based on port 0 but includes up until port 1's
	   end */
	set_io_port_base(CVMX_ADD_IO_SEG(cvmx_pcie_get_io_base_address(0)));
	ioport_resource.start = 0;
	ioport_resource.end =
		cvmx_pcie_get_io_base_address(1) -
		cvmx_pcie_get_io_base_address(0) + cvmx_pcie_get_io_size(1) - 1;

	npei_ctl_status.u64 = cvmx_read_csr(CVMX_PEXP_NPEI_CTL_STATUS);
	if (npei_ctl_status.s.host_mode) {
		printk("PCIe: Initializing port 0\n");
		result = cvmx_pcie_rc_initialize(0);
		if (result == 0) {
			/* Memory offsets are physical addresses */
			octeon_pcie0_controller.mem_offset =
				cvmx_pcie_get_mem_base_address(0);
			/* IO offsets are Mips virtual addresses */
			octeon_pcie0_controller.io_map_base =
				CVMX_ADD_IO_SEG(cvmx_pcie_get_io_base_address
						(0));
			octeon_pcie0_controller.io_offset = 0;
			/* To keep things similar to PCI, we start device
			   addresses at the same place as PCI uisng big bar
			   support. This normally translates to 4GB-256MB,
			   which is the same as most x86 PCs */
			octeon_pcie0_controller.mem_resource->start =
				cvmx_pcie_get_mem_base_address(0) +
				(4ul << 30) - (OCTEON_PCI_BAR1_HOLE_SIZE << 20);
			octeon_pcie0_controller.mem_resource->end =
				cvmx_pcie_get_mem_base_address(0) +
				cvmx_pcie_get_mem_size(0) - 1;
			/* Ports must be above 16KB for the ISA bus filtering
			   in the PCI-X to PCI bridge */
			octeon_pcie0_controller.io_resource->start = 4 << 10;
			octeon_pcie0_controller.io_resource->end =
				cvmx_pcie_get_io_size(0) - 1;
			register_pci_controller(&octeon_pcie0_controller);
		}
	} else
		printk("PCIe: Port 0 in endpoint mode, skipping.\n");

	/* Skip the 2nd port on CN52XX if port 0 is in 4 lane mode */
	if (OCTEON_IS_MODEL(OCTEON_CN52XX)) {
		cvmx_npei_dbg_data_t npei_dbg_data;
		npei_dbg_data.u64 = cvmx_read_csr(CVMX_PEXP_NPEI_DBG_DATA);
		if (npei_dbg_data.cn52xx.qlm0_link_width)
			return 0;
	}

	printk("PCIe: Initializing port 1\n");
	result = cvmx_pcie_rc_initialize(1);
	if (result == 0) {
		/* Memory offsets are physical addresses */
		octeon_pcie1_controller.mem_offset =
			cvmx_pcie_get_mem_base_address(1);
		/* IO offsets are Mips virtual addresses */
		octeon_pcie1_controller.io_map_base =
			CVMX_ADD_IO_SEG(cvmx_pcie_get_io_base_address(1));
		octeon_pcie1_controller.io_offset =
			cvmx_pcie_get_io_base_address(1) -
			cvmx_pcie_get_io_base_address(0);
		/* To keep things similar to PCI, we start device addresses at
		   the same place as PCI uisng big bar support. This normally
		   translates to 4GB-256MB, which is the same as most x86 PCs */
		octeon_pcie1_controller.mem_resource->start =
			cvmx_pcie_get_mem_base_address(1) + (4ul << 30) -
			(OCTEON_PCI_BAR1_HOLE_SIZE << 20);
		octeon_pcie1_controller.mem_resource->end =
			cvmx_pcie_get_mem_base_address(1) +
			cvmx_pcie_get_mem_size(1) - 1;
		/* Ports must be above 16KB for the ISA bus filtering in the
		   PCI-X to PCI bridge */
		octeon_pcie1_controller.io_resource->start =
			cvmx_pcie_get_io_base_address(1) -
			cvmx_pcie_get_io_base_address(0);
		octeon_pcie1_controller.io_resource->end =
			octeon_pcie1_controller.io_resource->start +
			cvmx_pcie_get_io_size(1) - 1;
		register_pci_controller(&octeon_pcie1_controller);
	}
	return 0;
}

arch_initcall(octeon_pcie_setup);
