/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2005-2007 Cavium Networks
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/msi.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include "hal.h"
#include "pci-common.h"

static uint64_t msi_free_irq_bitmask = 0;
static DEFINE_SPINLOCK(msi_free_irq_bitmask_lock);

int arch_setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
	struct msi_msg msg;
	int irq;

	/* We're going to search msi_free_irq_bitmask_lock for a zero bit. This
	   represents an MSI interrupt number that isn't in use */
	spin_lock(&msi_free_irq_bitmask_lock);
	for (irq = 0; irq < 64; irq++) {
		if ((msi_free_irq_bitmask & (1ull << irq)) == 0) {
			msi_free_irq_bitmask |= 1ull << irq;
			break;
		}
	}
	spin_unlock(&msi_free_irq_bitmask_lock);

	/* If we went through all of the bits without finding a free one then
	   panic. It may be possible to share MSI interrupts, but I can't image
	   an Octeon needing more than 64 MSI interrupts */
	if (irq == 64)
		panic("Unable to find a free MSI interrupt");

	/* MSI interrupts start at logical IRQ OCTEON_IRQ_MSI_BIT0 */
	irq += OCTEON_IRQ_MSI_BIT0;

	switch (octeon_dma_bar_type) {
	case OCTEON_DMA_BAR_TYPE_SMALL:
		/* When not using big bar, Bar 0 is based at 128MB */
		msg.address_lo =
			((128ul << 20) + CVMX_PCI_MSI_RCV) & 0xffffffff;
		msg.address_hi = ((128ul << 20) + CVMX_PCI_MSI_RCV) >> 32;
	case OCTEON_DMA_BAR_TYPE_BIG:
		/* When using big bar, Bar 0 is based at 0 */
		msg.address_lo = (0 + CVMX_PCI_MSI_RCV) & 0xffffffff;
		msg.address_hi = (0 + CVMX_PCI_MSI_RCV) >> 32;
		break;
	case OCTEON_DMA_BAR_TYPE_PCIE:
		/* When using PCIe, Bar 0 is based at 0 */
		// FIXME CVMX_NPEI_MSI_RCV* other than 0?
		msg.address_lo = (0 + CVMX_NPEI_PCIE_MSI_RCV) & 0xffffffff;
		msg.address_hi = (0 + CVMX_NPEI_PCIE_MSI_RCV) >> 32;
		break;
	default:
		panic("arch_setup_msi_irq: Invalid octeon_dma_bar_type\n");
	}
	msg.data = irq - OCTEON_IRQ_MSI_BIT0;

	set_irq_msi(irq, desc);
	write_msi_msg(irq, &msg);
	return irq;
}

void arch_teardown_msi_irq(unsigned int irq)
{
	uint64_t bitmask;
	printk("arch_teardown_msi_irq(irq=%d)\n", irq);

	if ((irq < OCTEON_IRQ_MSI_BIT0) || (irq > OCTEON_IRQ_MSI_BIT63))
		panic("Attempted to teardown illegal MSI interrupt (%d)", irq);

	bitmask = 1ull << (irq - OCTEON_IRQ_MSI_BIT0);
	if ((msi_free_irq_bitmask & bitmask) == 0)
		panic("Attempted to teardown MSI interrupt (%d) not in use",
		      irq);

	spin_lock(&msi_free_irq_bitmask_lock);
	msi_free_irq_bitmask ^= bitmask;
	spin_unlock(&msi_free_irq_bitmask_lock);
}

static irqreturn_t octeon_msi_interrupt(int cpl, void *dev_id)
{
	uint64_t msi_bits;
	int irq;

	if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_PCIE)
		msi_bits = cvmx_read_csr(CVMX_PEXP_NPEI_MSI_RCV0);
	else
		msi_bits = cvmx_read_csr(CVMX_NPI_NPI_MSI_RCV);
	irq = fls64(msi_bits);
	if (irq) {
		irq += OCTEON_IRQ_MSI_BIT0 - 1;
		if (irq_desc[irq].action) {
			do_IRQ(irq);
			return IRQ_HANDLED;
		} else {
			printk("Spurious MSI interrupt %d\n", irq);
			if (octeon_has_feature(OCTEON_FEATURE_PCIE)) {
				/* These chips have PCIe */
				cvmx_write_csr(CVMX_PEXP_NPEI_MSI_RCV0,
					       1ull << (irq -
							OCTEON_IRQ_MSI_BIT0));
			} else {
				/* These chips have PCI */
				cvmx_write_csr(CVMX_NPI_NPI_MSI_RCV,
					       1ull << (irq -
							OCTEON_IRQ_MSI_BIT0));
			}
		}
	}
	return IRQ_NONE;
}

int octeon_msi_initialize(void)
{
	if (octeon_has_feature(OCTEON_FEATURE_PCIE)) {
		request_irq(OCTEON_IRQ_PCI_MSI0, octeon_msi_interrupt, SA_SHIRQ,
			    "MSI[0:63]", octeon_msi_interrupt);
	} else if (octeon_is_pci_host()) {
		request_irq(OCTEON_IRQ_PCI_MSI0, octeon_msi_interrupt, SA_SHIRQ,
			    "MSI[0:15]", octeon_msi_interrupt);
		request_irq(OCTEON_IRQ_PCI_MSI1, octeon_msi_interrupt, SA_SHIRQ,
			    "MSI[16:31]", octeon_msi_interrupt);
		request_irq(OCTEON_IRQ_PCI_MSI2, octeon_msi_interrupt, SA_SHIRQ,
			    "MSI[32:47]", octeon_msi_interrupt);
		request_irq(OCTEON_IRQ_PCI_MSI3, octeon_msi_interrupt, SA_SHIRQ,
			    "MSI[48:63]", octeon_msi_interrupt);
	}
	return 0;
}

subsys_initcall(octeon_msi_initialize);
