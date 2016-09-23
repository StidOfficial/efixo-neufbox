/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2000  Ani Joshi <ajoshi@unixbox.com>
 * Copyright (C) 2000, 2001  Ralf Baechle <ralf@gnu.org>
 * Copyright (C) 2005 Ilya A. Volynets-Evenbakh <ilya@total-knowledge.com>
 * swiped from i386, and cloned for MIPS by Geert, polished by Ralf.
 * IP32 changes by Ilya.
 * Cavium Networks: Create new dma setup for Cavium Networks Octeon based on
 * the kernels original.
 */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>

#include <asm/cache.h>
#include <asm/io.h>
#include <asm/ip32/crime.h>

#include "hal.h"
#include "pci-common.h"

#define BAR2_PCI_ADDRESS 0x8000000000ul

typedef struct {
	int16_t ref_count;	/* Number of PCI mappings using this index */
	int16_t address_bits;	/* Upper bits of physical address. This is
				   shifted 22 bits */
} bar1_index_state_t;

#ifdef CONFIG_PCI
static spinlock_t bar1_lock = SPIN_LOCK_UNLOCKED;
static bar1_index_state_t bar1_state[32] = { {0, 0}, };
#endif

void *dma_alloc_noncoherent(struct device *dev, size_t size,
			    dma_addr_t * dma_handle, unsigned int __nocast gfp)
	__attribute__ ((alias("dma_alloc_coherent")));

EXPORT_SYMBOL(dma_alloc_noncoherent);


void *dma_alloc_coherent(struct device *dev, size_t size,
			 dma_addr_t * dma_handle, unsigned int __nocast gfp)
{
	void *ret;
	/* Ignore region specifiers. The Octeon Bar1 register can be used to
	   map any memory on the system. As long as we don't fill up the 32
	   entry table, memory can be anywhere */
	gfp &= ~(__GFP_DMA | __GFP_HIGHMEM);

	ret = (void *) __get_free_pages(gfp, get_order(size));
	if (likely(ret != NULL)) {
		memset(ret, 0, size);
		/* By default, PCI devices can't get to memory. dma_map_single
		   changes the Bar mapping to allow access to this region */
		*dma_handle = dma_map_single(dev, ret, size, DMA_BIDIRECTIONAL);
	}

	return ret;
}

EXPORT_SYMBOL(dma_alloc_coherent);


void dma_free_noncoherent(struct device *dev, size_t size, void *vaddr,
			  dma_addr_t dma_handle)
	__attribute__ ((alias("dma_free_coherent")));

EXPORT_SYMBOL(dma_free_noncoherent);


void dma_free_coherent(struct device *dev, size_t size, void *vaddr,
		       dma_addr_t dma_handle)
{
	/* Free the Bar mappings */
	dma_unmap_single(dev, dma_handle, size, DMA_BIDIRECTIONAL);
	free_pages((unsigned long) vaddr, get_order(size));
}

EXPORT_SYMBOL(dma_free_coherent);


dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size,
			  enum dma_data_direction direction)
{
#ifndef CONFIG_PCI
	/* Without PCI/PCIe this function can be called for Octeon internal
	   devices such as USB. These devices all support 64bit addressing */
	return virt_to_phys(ptr);
#else
	unsigned long flags;
	uint64_t dma_mask;
	int64_t start_index;
	dma_addr_t result = -1;
	uint64_t physical = virt_to_phys(ptr);
	int64_t index;

	BUG_ON(direction == DMA_NONE);

	/* Use the DMA masks to determine the allowed memory region. For us it
	   doesn't limit the actual memory, just the address visible over PCI.
	   Devices with limits need to use lower indexed Bar1 entries. */
	if (dev) {
		dma_mask = dev->coherent_dma_mask;
		if (dev->dma_mask)
			dma_mask = *dev->dma_mask;
	} else
		dma_mask = 0xfffffffful;

	/* Platform devices, such as the internal USB, skip all translation and
	   use Octeon physical addresses directly */
	if (dev->bus == &platform_bus_type)
		return physical;

	switch (octeon_dma_bar_type) {
	case OCTEON_DMA_BAR_TYPE_PCIE:
		if (unlikely(physical < (16ul << 10)))
			panic("dma_map_single: Not allowed to map first 16KB. It interferes with BAR0 special area\n");
		else if ((physical + size >= (256ul << 20)) &&
			 (physical < (512ul << 20)))
			panic("dma_map_single: Not allowed to map bootbus\n");
		else if ((physical + size >= 0x400000000ull) &&
			 physical < 0x410000000ull)
			panic("dma_map_single: Attempt to map illegal memory address 0x%lx\n", physical);
		else if (physical >= 0x420000000ull)
			panic("dma_map_single: Attempt to map illegal memory address 0x%lx\n", physical);
		/* The 2nd 256MB is mapped at 256<<20 instead of 0x410000000 */
		if ((physical >= 0x410000000ull) && physical < 0x420000000ull)
			result = physical - 0x400000000ull;
		else
			result = physical;
		goto done;

	case OCTEON_DMA_BAR_TYPE_BIG:
#ifdef CONFIG_64BIT
		/* If the device supports 64bit addressing, then use BAR2 */
		if (dma_mask > BAR2_PCI_ADDRESS) {
			result = physical + BAR2_PCI_ADDRESS;
			goto done;
		}
#endif
		if (unlikely(physical < (4ul << 10))) {
			panic("dma_map_single: Not allowed to map first 4KB. It interferes with BAR0 special area\n");
		} else if (physical < (256ul << 20)) {
			if (unlikely(physical + size > (256ul << 20)))
				panic("dma_map_single: Requested memory spans Bar0 0:256MB and bootbus\n");
			result = physical;
			goto done;
		} else if (unlikely(physical < (512ul << 20))) {
			panic("dma_map_single: Not allowed to map bootbus\n");
		} else if (physical < (2ul << 30)) {
			if (unlikely(physical + size > (2ul << 30)))
				panic("dma_map_single: Requested memory spans Bar0 512MB:2GB and BAR1\n");
			result = physical;
			goto done;
		} else if (physical < (2ul << 30) + (128 << 20)) {
			/* Fall through */
		} else if (physical <
			   (4ul << 30) - (OCTEON_PCI_BAR1_HOLE_SIZE << 20)) {
			if (unlikely
			    (physical + size >
			     (4ul << 30) - (OCTEON_PCI_BAR1_HOLE_SIZE << 20)))
				panic("dma_map_single: Requested memory extends past Bar1 (4GB-%luMB)\n", OCTEON_PCI_BAR1_HOLE_SIZE);
			result = physical;
			goto done;
		} else if ((physical >= 0x410000000ull) &&
			   (physical < 0x420000000ull)) {
			if (unlikely(physical + size > 0x420000000ull))
				panic("dma_map_single: Requested memory spans non existant memory\n");
			result = physical - 0x400000000ull;	/* BAR0 fixed
								   mapping
								   256MB:512MB
								   ->
								   16GB+256MB:16GB+512MB
								 */
			goto done;
		} else {
			/* Continued below switch statement */
		}
		break;

	case OCTEON_DMA_BAR_TYPE_SMALL:
#ifdef CONFIG_64BIT
		/* If the device supports 64bit addressing, then use BAR2 */
		if (dma_mask > BAR2_PCI_ADDRESS) {
			result = physical + BAR2_PCI_ADDRESS;
			goto done;
		}
#endif
		/* Continued below switch statement */
		break;

	default:
		panic("dma_map_single: Invalid octeon_dma_bar_type\n");
	}

	/* Don't allow mapping to span multiple Bar entries. The hardware guys
	   won't guarantee that DMA across boards work */
	if (unlikely((physical >> 22) != ((physical + size - 1) >> 22)))
		panic("dma_map_single: Requested memory spans more than one Bar1 entry\n");

	if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_BIG)
		start_index = 31;
	else if (unlikely(dma_mask < (1ul << 27)))
		start_index = (dma_mask >> 22);
	else
		start_index = 31;

	/* Only one processor can access the Bar register at once */
	spin_lock_irqsave(&bar1_lock, flags);

	/* Look through Bar1 for existing mapping that will work */
	for (index = start_index; index >= 0; index--) {
		if ((bar1_state[index].address_bits == physical >> 22) &&
		    (bar1_state[index].ref_count)) {
			/* An existing mapping will work, use it */
			bar1_state[index].ref_count++;
			if (unlikely(bar1_state[index].ref_count < 0))
				panic("dma_map_single: Bar1[%d] reference count overflowed\n", (int) index);
			result = (index << 22) | (physical & ((1 << 22) - 1));
			/* Large BAR1 is offset at 2GB */
			if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_BIG)
				result += 2ul << 30;
			goto done_unlock;
		}
	}

	/* No existing mappings, look for a free entry */
	for (index = start_index; index >= 0; index--) {
		if (unlikely(bar1_state[index].ref_count == 0)) {
			cvmx_pci_bar1_indexx_t bar1_index;
			/* We have a free entry, use it */
			bar1_state[index].ref_count = 1;
			bar1_state[index].address_bits = physical >> 22;
			bar1_index.u32 = 0;
			bar1_index.s.addr_idx = physical >> 22;	/* Address bits
								   [35:22] sent
								   to L2C */
			bar1_index.s.ca = 1;	/* Don't put PCI accesses in
						   L2. */
			bar1_index.s.end_swp = 1;	/* Endian Swap Mode */
			bar1_index.s.addr_v = 1;	/* Set '1' when the
							   selected address
							   range is valid. */
			octeon_npi_write32(CVMX_NPI_PCI_BAR1_INDEXX(index),
					   bar1_index.u32);
			/* An existing mapping will work, use it */
			result = (index << 22) | (physical & ((1 << 22) - 1));
			/* Large BAR1 is offset at 2GB */
			if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_BIG)
				result += 2ul << 30;
			goto done_unlock;
		}
	}

	printk("dma_map_single: Can't find empty BAR1 index for physical mapping 0x%llx\n", (unsigned long long) physical);

      done_unlock:
	spin_unlock_irqrestore(&bar1_lock, flags);
      done:
	// printk("dma_map_single 0x%lx->0x%lx\n", physical, result);
	return result;
#endif
}

EXPORT_SYMBOL(dma_map_single);


void dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
		      enum dma_data_direction direction)
{
#ifndef CONFIG_PCI
	/* Without PCI/PCIe this function can be called for Octeon internal
	   devices such as USB. These devices all support 64bit addressing */
	return;
#else
	unsigned long flags;
	uint64_t index;

	BUG_ON(direction == DMA_NONE);

	/* Platform devices, such as the internal USB, skip all translation and
	   use Octeon physical addresses directly */
	if (dev->bus == &platform_bus_type)
		return;

	switch (octeon_dma_bar_type) {
	case OCTEON_DMA_BAR_TYPE_PCIE:
		/* Nothing to do, all mappings are static */
		goto done;

	case OCTEON_DMA_BAR_TYPE_BIG:
#ifdef CONFIG_64BIT
		/* Nothing to do for addresses using BAR2 */
		if (dma_addr >= BAR2_PCI_ADDRESS)
			goto done;
#endif
		if (unlikely(dma_addr < (4ul << 10)))
			panic("dma_unmap_single: Unexpect DMA address 0x%lx\n",
			      dma_addr);
		else if (dma_addr < (2ul << 30))
			goto done;	/* Nothing to do for addresses using
					   BAR0 */
		else if (dma_addr < (2ul << 30) + (128ul << 20))
			index = (dma_addr - (2ul << 30)) >> 22;	/* Need to
								   unmap, fall
								   through */
		else if (dma_addr <
			 (4ul << 30) - (OCTEON_PCI_BAR1_HOLE_SIZE << 20))
			goto done;	/* Nothing to do for the rest of BAR1 */
		else
			panic("dma_unmap_single: Unexpect DMA address 0x%lx\n",
			      dma_addr);
		/* Continued below switch statement */
		break;

	case OCTEON_DMA_BAR_TYPE_SMALL:
#ifdef CONFIG_64BIT
		/* Nothing to do for addresses using BAR2 */
		if (dma_addr >= BAR2_PCI_ADDRESS)
			goto done;
#endif
		index = dma_addr >> 22;
		/* Continued below switch statement */
		break;

	default:
		panic("dma_unmap_single: Invalid octeon_dma_bar_type\n");
	}

	if (unlikely(index > 31))
		panic("dma_unmap_single: Attempt to unmap an invalid address (0x%llx)\n", (unsigned long long) dma_addr);

	spin_lock_irqsave(&bar1_lock, flags);
	bar1_state[index].ref_count--;
	if (bar1_state[index].ref_count == 0)
		octeon_npi_write32(CVMX_NPI_PCI_BAR1_INDEXX(index), 0);
	else if (unlikely(bar1_state[index].ref_count < 0))
		panic("dma_unmap_single: Bar1[%u] reference count < 0\n",
		      (int) index);
	spin_unlock_irqrestore(&bar1_lock, flags);
      done:
	// printk("dma_unmap_single 0x%lx\n", dma_addr);
	return;
#endif
}

EXPORT_SYMBOL(dma_unmap_single);


int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
	       enum dma_data_direction direction)
{
	int i;
	for (i = 0; i < nents; i++, sg++)
		sg->dma_address =
			dma_map_page(dev, sg->page, sg->offset, sg->length,
				     direction);

	return nents;
}

EXPORT_SYMBOL(dma_map_sg);


dma_addr_t dma_map_page(struct device * dev, struct page * page,
			unsigned long offset, size_t size,
			enum dma_data_direction direction)
{
	return dma_map_single(dev, page_address(page) + offset, size,
			      direction);
}

EXPORT_SYMBOL(dma_map_page);


void dma_unmap_page(struct device *dev, dma_addr_t dma_address, size_t size,
		    enum dma_data_direction direction)
{
	dma_unmap_single(dev, dma_address, size, direction);
}

EXPORT_SYMBOL(dma_unmap_page);


void dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nhwentries,
		  enum dma_data_direction direction)
{
	int i;
	for (i = 0; i < nhwentries; i++, sg++)
		dma_unmap_page(dev, sg->dma_address, sg->length, direction);
}

EXPORT_SYMBOL(dma_unmap_sg);


void dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
			     size_t size, enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_sync_single_for_cpu);


void dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle,
				size_t size, enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_sync_single_for_device);


void dma_sync_single_range_for_cpu(struct device *dev, dma_addr_t dma_handle,
				   unsigned long offset, size_t size,
				   enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_sync_single_range_for_cpu);


void dma_sync_single_range_for_device(struct device *dev, dma_addr_t dma_handle,
				      unsigned long offset, size_t size,
				      enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_sync_single_range_for_device);


void dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg, int nelems,
			 enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_sync_sg_for_cpu);


void dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
			    int nelems, enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_sync_sg_for_device);


int dma_mapping_error(dma_addr_t dma_addr)
{
	return (dma_addr == -1);
}

EXPORT_SYMBOL(dma_mapping_error);


int dma_supported(struct device *dev, u64 mask)
{
	return 1;
}

EXPORT_SYMBOL(dma_supported);


int dma_is_consistent(struct device *dev, dma_addr_t dma_addr)
{
	return 1;
}

EXPORT_SYMBOL(dma_is_consistent);


void dma_cache_sync(struct device *dev, void *vaddr, size_t size,
		    enum dma_data_direction direction)
{
	mb();
}

EXPORT_SYMBOL(dma_cache_sync);
