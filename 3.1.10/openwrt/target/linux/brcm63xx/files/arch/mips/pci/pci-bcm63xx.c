/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Maxime Bizon <mbizon@freebox.fr>
 */

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/bootinfo.h>

#include "pci-bcm63xx.h"

#include <bcmpci.h>
#include <bcm_intr.h>
#include <bcm_map_part.h>

#define DIR_U2P_NOSWAP          0x00000002

/*
 * Allow PCI to be disabled at runtime depending on board nvram
 * configuration
 */
int bcm63xx_pci_enabled;

static struct resource bcm_pci_mem_resource = {
	.name   = "bcm63xx PCI memory space",
	.start  = BCM_PCI_MEM_BASE_PA,
	.end    = BCM_PCI_MEM_END_PA,
	.flags  = IORESOURCE_MEM
};

static struct resource bcm_pci_io_resource = {
	.name   = "bcm63xx PCI IO space",
	.start  = BCM_PCI_IO_BASE_PA,
#ifdef CONFIG_CARDBUS
	.end    = BCM_PCI_IO_HALF_PA,
#else
	.end    = BCM_PCI_IO_END_PA,
#endif
	.flags  = IORESOURCE_IO
};

struct pci_controller bcm63xx_controller = {
	.pci_ops	= &bcm63xx_pci_ops,
	.io_resource	= &bcm_pci_io_resource,
	.mem_resource	= &bcm_pci_mem_resource,
};

/*
 * We handle cardbus  via a fake Cardbus bridge,  memory and io spaces
 * have to be  clearly separated from PCI one  since we have different
 * memory decoder.
 */
#ifdef CONFIG_CARDBUS
static struct resource bcm_cb_mem_resource = {
	.name   = "bcm63xx Cardbus memory space",
	.start  = BCM_CB_MEM_BASE_PA,
	.end    = BCM_CB_MEM_END_PA,
	.flags  = IORESOURCE_MEM
};

static struct resource bcm_cb_io_resource = {
	.name   = "bcm63xx Cardbus IO space",
	.start  = BCM_PCI_IO_HALF_PA + 1,
	.end    = BCM_PCI_IO_END_PA,
	.flags  = IORESOURCE_IO
};

struct pci_controller bcm63xx_cb_controller = {
	.pci_ops	= &bcm63xx_cb_ops,
	.io_resource	= &bcm_cb_io_resource,
	.mem_resource	= &bcm_cb_mem_resource,
};
#endif

#if defined(CONFIG_BCM63XX_CPU_6362)
extern struct pci_ops bcm63xx_pcie_ops;
static struct resource bcm_pcie_io_resource = {
	.name   = "bcm63xx pcie null io space",
	.start  = BCM_PCI_IO_BASE + BCM_PCI_IO_SIZE ,
	.end    = BCM_PCI_IO_BASE + BCM_PCI_IO_SIZE ,
	.flags  = 0
};

static struct resource bcm_pcie_mem_resource = {
	.name   = "bcm63xx pcie memory space",
	.start  = BCM_PCIE_MEM1_BASE,
	.end    = BCM_PCIE_MEM1_BASE + BCM_PCIE_MEM1_SIZE - 1,
	.flags  = IORESOURCE_MEM
};

struct pci_controller bcm63xx_pcie_controller = {
	.pci_ops	= &bcm63xx_pcie_ops,
	.io_resource	= &bcm_pcie_io_resource,
	.mem_resource	= &bcm_pcie_mem_resource,
};
#endif

#if defined(CONFIG_BCM63XX_CPU_6358)
static u32 bcm63xx_int_cfg_readl(u32 reg)
{
	u32 tmp;

	tmp = reg & MPI_PCICFGCTL_CFGADDR_MASK;
	tmp |= MPI_PCICFGCTL_WRITEEN_MASK;
	bcm_mpi_writel(tmp, MPI_PCICFGCTL_REG);
	iob();
	return bcm_mpi_readl(MPI_PCICFGDATA_REG);
}

static void bcm63xx_int_cfg_writel(u32 val, u32 reg)
{
	u32 tmp;

	tmp = reg & MPI_PCICFGCTL_CFGADDR_MASK;
	tmp |=  MPI_PCICFGCTL_WRITEEN_MASK;
	bcm_mpi_writel(tmp, MPI_PCICFGCTL_REG);
	bcm_mpi_writel(val, MPI_PCICFGDATA_REG);
}
#endif

void __iomem *pci_iospace_start;

static int __init bcm63xx_pci_init(void)
{
#if defined(CONFIG_BCM63XX_CPU_6358)
	unsigned int mem_size;
	u32 val;
#endif

	if (!BCMCPU_IS_6348() && !BCMCPU_IS_6358() && !BCMCPU_IS_6362())
		return -ENODEV;

	if (!bcm63xx_pci_enabled)
		return -ENODEV;

#if defined(CONFIG_BCM63XX_CPU_6362)
	/* adjust global io port range */
	ioport_resource.start = BCM_PCI_IO_BASE;
	ioport_resource.end = BCM_PCI_IO_BASE + BCM_PCI_IO_SIZE;
#endif
#if defined(CONFIG_BCM63XX_CPU_6358)
	/*
	 * configuration  access are  done through  IO space,  remap 4
	 * first bytes to access it from CPU.
	 *
	 * this means that  no io access from CPU  should happen while
	 * we do a configuration cycle,  but there's no way we can add
	 * a spinlock for each io access, so this is currently kind of
	 * broken on SMP.
	 */
	pci_iospace_start = ioremap_nocache(BCM_PCI_IO_BASE_PA, 4);
	if (!pci_iospace_start)
		return -ENOMEM;

	/* setup local bus to PCI access (PCI memory) */
	val = BCM_PCI_MEM_BASE_PA & MPI_L2P_BASE_MASK;
	bcm_mpi_writel(val, MPI_L2PMEMBASE1_REG);
	bcm_mpi_writel(~(BCM_PCI_MEM_SIZE - 1), MPI_L2PMEMRANGE1_REG);
	bcm_mpi_writel(val | MPI_L2PREMAP_ENABLED_MASK, MPI_L2PMEMREMAP1_REG);

	/* set Cardbus IDSEL (type 0 cfg access on primary bus for
	 * this IDSEL will be done on Cardbus instead) */
	val = PCMCIA_C1_EN_CARDBUS_MASK | PCMCIA_C1_EN_PCMCIA_GPIO_MASK;
	bcm_pcmcia_writel(val, PCMCIA_C1_REG);

#ifdef CONFIG_CARDBUS
	/* setup local bus to PCI access (Cardbus memory) */
	val = BCM_CB_MEM_BASE_PA & MPI_L2P_BASE_MASK;
	bcm_mpi_writel(val, MPI_L2PMEMBASE2_REG);
	bcm_mpi_writel(~(BCM_CB_MEM_SIZE - 1), MPI_L2PMEMRANGE2_REG);
	val = BCM_PCI_MEM_BASE_PA & MPI_L2P_BASE_MASK;
	val |= MPI_L2PREMAP_ENABLED_MASK | MPI_L2PREMAP_IS_CARDBUS_MASK;
	bcm_mpi_writel(val, MPI_L2PMEMREMAP2_REG);
#else
	/* disable second access windows */
	bcm_mpi_writel(0, MPI_L2PMEMREMAP2_REG);
#endif

	/* setup local bus  to PCI access (IO memory),  we have only 1
	 * IO window  for both PCI  and cardbus, but it  cannot handle
	 * both  at the  same time,  assume standard  PCI for  now, if
	 * cardbus card has  IO zone, PCI fixup will  change window to
	 * cardbus */
	val = BCM_PCI_IO_BASE_PA & MPI_L2P_BASE_MASK;
	bcm_mpi_writel(val, MPI_L2PIOBASE_REG);
	bcm_mpi_writel(~(BCM_PCI_IO_SIZE - 1), MPI_L2PIORANGE_REG);
	bcm_mpi_writel(val | MPI_L2PREMAP_ENABLED_MASK, MPI_L2PIOREMAP_REG);

	/* enable PCI related GPIO pins */
	bcm_mpi_writel(MPI_LOCBUSCTL_EN_PCI_GPIO_MASK | DIR_U2P_NOSWAP, MPI_LOCBUSCTL_REG);

	/* setup PCI to local bus access, used by PCI device to target
	 * local RAM while bus mastering */
	bcm63xx_int_cfg_writel(0x10000000, PCI_BASE_ADDRESS_3);
	if (BCMCPU_IS_6358())
		val = MPI_SP0_REMAP_ENABLE_MASK;
	else
		val = 0;
	bcm_mpi_writel(val, MPI_SP0_REMAP_REG);

	bcm63xx_int_cfg_writel(0x0, PCI_BASE_ADDRESS_4);
	bcm_mpi_writel(val, MPI_SP1_REMAP_REG);

	mem_size = bcm63xx_get_memory_size();

	/* 6348 before rev b0 exposes only 16 MB of RAM memory through
	 * PCI, throw a warning if we have more memory */
	if (BCMCPU_IS_6348() && (bcm63xx_get_cpu_rev() & 0xf0) == 0xa0) {
		if (mem_size > (16 * 1024 * 1024))
			printk(KERN_WARNING "bcm63xx: this CPU "
			       "revision cannot handle more than 16MB "
			       "of RAM for PCI bus mastering\n");
	} else {
		/* setup sp0 range to local RAM size */
		bcm_mpi_writel(~(mem_size - 1), MPI_SP0_RANGE_REG);
		bcm_mpi_writel(~(mem_size - 1), MPI_SP1_RANGE_REG);
	}

	/* change  host bridge  retry  counter to  infinite number  of
	 * retry,  needed for  some broadcom  wifi cards  with Silicon
	 * Backplane bus where access to srom seems very slow  */
	val = bcm63xx_int_cfg_readl(BCMPCI_REG_TIMERS);
	val &= ~REG_TIMER_RETRY_MASK;
	val |= 0x00000080;
	bcm63xx_int_cfg_writel(val, BCMPCI_REG_TIMERS);

	/* enable memory decoder and bus mastering */
	val = bcm63xx_int_cfg_readl(PCI_COMMAND);
	val |= (PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	bcm63xx_int_cfg_writel(val, PCI_COMMAND);

	/* enable read prefetching for bus
	 * mastering transfers */
	val = bcm_mpi_readl(MPI_PCIMODESEL_REG);
#if 0
	val &= ~MPI_PCIMODESEL_BAR1_NOSWAP_MASK;
	val &= ~MPI_PCIMODESEL_BAR2_NOSWAP_MASK;
#endif
	val &= ~MPI_PCIMODESEL_PREFETCH_MASK;
	val |= (16 << MPI_PCIMODESEL_PREFETCH_SHIFT);
	bcm_mpi_writel(val, MPI_PCIMODESEL_REG);

	/* enable pci interrupt */
	val = bcm_mpi_readl(MPI_LOCINT_REG);
	val |= MPI_LOCINT_MASK(MPI_LOCINT_EXT_PCI_INT);
	bcm_mpi_writel(val, MPI_LOCINT_REG);

	mpi_DetectPcCard();
#endif
	register_pci_controller(&bcm63xx_controller);

#if defined(CONFIG_BCM63XX_CPU_6362)
	PCIEH_BRIDGE_REGS->bridgeOptReg1 |=
		(PCIE_BRIDGE_OPT_REG1_en_l1_int_status_mask_polarity |
		 PCIE_BRIDGE_OPT_REG1_en_pcie_bridge_hole_detection |
		 PCIE_BRIDGE_OPT_REG1_en_rd_reply_be_fix |
		 PCIE_BRIDGE_OPT_REG1_enable_rd_be_opt);

	PCIEH_BRIDGE_REGS->rcInterruptMask |=
		(PCIE_BRIDGE_INTERRUPT_MASK_int_a_MASK |
		 PCIE_BRIDGE_INTERRUPT_MASK_int_b_MASK |
		 PCIE_BRIDGE_INTERRUPT_MASK_int_c_MASK |
		 PCIE_BRIDGE_INTERRUPT_MASK_int_c_MASK);

	/* enable credit checking and error checking */
	PCIEH_BRIDGE_REGS->bridgeOptReg2 |=
		(PCIE_BRIDGE_OPT_REG2_enable_tx_crd_chk_MASK |
		 PCIE_BRIDGE_OPT_REG2_dis_ubus_ur_decode_MASK);

	/* set device bus/func/func */
	PCIEH_BRIDGE_REGS->bridgeOptReg2 |=
		((BCM_BUS_PCIE_DEVICE <<
		  PCIE_BRIDGE_OPT_REG2_cfg_type1_bus_no_SHIFT) |
		 PCIE_BRIDGE_OPT_REG2_cfg_type1_bd_sel_MASK);

	/* setup class code, as bridge */
	PCIEH_BLK_428_REGS->idVal3 &= ~PCIE_IP_BLK428_ID_VAL3_CLASS_CODE_MASK;
	PCIEH_BLK_428_REGS->idVal3 |= (PCI_CLASS_BRIDGE_PCI << 8);
	/* disable bar0 size */
	PCIEH_BLK_404_REGS->config2 &= ~PCIE_IP_BLK404_CONFIG_2_BAR1_SIZE_MASK;
	/*bus 1 and 2 */
	register_pci_controller(&bcm63xx_pcie_controller);
#endif
#if defined(CONFIG_BCM63XX_CPU_6358)
#ifdef CONFIG_CARDBUS
	register_pci_controller(&bcm63xx_cb_controller);
#endif

	/* mark memory space used for IO mapping as reserved */
	request_mem_region(BCM_PCI_IO_BASE_PA, BCM_PCI_IO_SIZE,
			   "bcm63xx PCI IO space");
#endif
	return 0;
}

arch_initcall(bcm63xx_pci_init);
