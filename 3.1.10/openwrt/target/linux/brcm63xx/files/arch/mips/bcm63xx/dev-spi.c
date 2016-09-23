/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2009 Florian Fainelli <florian@openwrt.org>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#include <bcm63xx_cpu.h>
#include <bcm63xx_dev_spi.h>
#include <bcm63xx_regs.h>

#ifdef BCMCPU_RUNTIME_DETECT
/*
 * register offsets
 */
static const unsigned long bcm96338_regs_spi[] = {
	[SPI_CMD]		= SPI_BCM_6338_SPI_CMD,
	[SPI_INT_STATUS]	= SPI_BCM_6338_SPI_INT_STATUS,
	[SPI_INT_MASK_ST]	= SPI_BCM_6338_SPI_MASK_INT_ST,
	[SPI_INT_MASK]		= SPI_BCM_6338_SPI_INT_MASK,
	[SPI_ST]		= SPI_BCM_6338_SPI_ST,
	[SPI_CLK_CFG]		= SPI_BCM_6338_SPI_CLK_CFG,
	[SPI_FILL_BYTE]		= SPI_BCM_6338_SPI_FILL_BYTE,
	[SPI_MSG_TAIL]		= SPI_BCM_6338_SPI_MSG_TAIL,
	[SPI_RX_TAIL]		= SPI_BCM_6338_SPI_RX_TAIL,
	[SPI_MSG_CTL]		= SPI_BCM_6338_SPI_MSG_CTL,
	[SPI_MSG_DATA]		= SPI_BCM_6338_SPI_MSG_DATA,
	[SPI_RX_DATA]		= SPI_BCM_6338_SPI_RX_DATA,
};

static const unsigned long bcm96348_regs_spi[] = {
	[SPI_CMD]		= SPI_BCM_6348_SPI_CMD,
	[SPI_INT_STATUS]	= SPI_BCM_6348_SPI_INT_STATUS,
	[SPI_INT_MASK_ST]	= SPI_BCM_6348_SPI_MASK_INT_ST,
	[SPI_INT_MASK]		= SPI_BCM_6348_SPI_INT_MASK,
	[SPI_ST]		= SPI_BCM_6348_SPI_ST,
	[SPI_CLK_CFG]		= SPI_BCM_6348_SPI_CLK_CFG,
	[SPI_FILL_BYTE]		= SPI_BCM_6348_SPI_FILL_BYTE,
	[SPI_MSG_TAIL]		= SPI_BCM_6348_SPI_MSG_TAIL,
	[SPI_RX_TAIL]		= SPI_BCM_6348_SPI_RX_TAIL,
	[SPI_MSG_CTL]		= SPI_BCM_6348_SPI_MSG_CTL,
	[SPI_MSG_DATA]		= SPI_BCM_6348_SPI_MSG_DATA,
	[SPI_RX_DATA]		= SPI_BCM_6348_SPI_RX_DATA,
};

static const unsigned long bcm96358_regs_spi[] = {
	[SPI_CMD]		= SPI_BCM_6358_SPI_CMD,
	[SPI_INT_STATUS]	= SPI_BCM_6358_SPI_INT_STATUS,
	[SPI_INT_MASK_ST]	= SPI_BCM_6358_SPI_MASK_INT_ST,
	[SPI_INT_MASK]		= SPI_BCM_6358_SPI_INT_MASK,
	[SPI_ST]		= SPI_BCM_6358_SPI_STATUS,
	[SPI_CLK_CFG]		= SPI_BCM_6358_SPI_CLK_CFG,
	[SPI_FILL_BYTE]		= SPI_BCM_6358_SPI_FILL_BYTE,
	[SPI_MSG_TAIL]		= SPI_BCM_6358_SPI_MSG_TAIL,
	[SPI_RX_TAIL]		= SPI_BCM_6358_SPI_RX_TAIL,
	[SPI_MSG_CTL]		= SPI_BCM_6358_MSG_CTL,
	[SPI_MSG_DATA]		= SPI_BCM_6358_SPI_MSG_DATA,
	[SPI_RX_DATA]		= SPI_BCM_6358_SPI_RX_DATA,
};

const unsigned long *bcm63xx_regs_spi;
EXPORT_SYMBOL(bcm63xx_regs_spi);

static __init void bcm63xx_spi_regs_init(void)
{
	if (BCMCPU_IS_6338())
		bcm63xx_regs_spi = bcm96338_regs_spi;
	if (BCMCPU_IS_6348())
		bcm63xx_regs_spi = bcm96348_regs_spi;
	if (BCMCPU_IS_6358() || BCMCPU_IS_6362())
		bcm63xx_regs_spi = bcm96358_regs_spi;
}
#else
static __init void bcm63xx_spi_regs_init(void) { }
#endif

static struct resource spi_resources[] = {
	{
		.start		= -1, /* filled at runtime */
		.end		= -1, /* filled at runtime */
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= -1, /* filled at runtime */
		.flags		= IORESOURCE_IRQ,
	},
};

static struct bcm63xx_spi_pdata spi_pdata = {
	.bus_num		= 0,
	.num_chipselect		= 8,
	.speed_hz		= 50000000,	/* Fclk */
};

static struct platform_device bcm63xx_spi_device = {
#if 0
	.name		= "bcm63xx-spi",
#else
	.name		= "bcmleg_spi",
#endif
	.id		= 0,
	.num_resources	= ARRAY_SIZE(spi_resources),
	.resource	= spi_resources,
	.dev		= {
		.platform_data = &spi_pdata,
	},
};

int __init bcm63xx_spi_register(void)
{
	spi_resources[0].start = bcm63xx_regset_address(RSET_SPI);
	spi_resources[0].end = spi_resources[0].start;
	spi_resources[0].end += RSET_SPI_SIZE - 1;
	spi_resources[1].start = bcm63xx_get_irq_number(IRQ_SPI);

	/* Fill in platform data */
	if (BCMCPU_IS_6338() || BCMCPU_IS_6348())
		spi_pdata.fifo_size = SPI_BCM_6338_SPI_MSG_DATA_SIZE;

	if (BCMCPU_IS_6358() || BCMCPU_IS_6362())
		spi_pdata.fifo_size = SPI_BCM_6358_SPI_MSG_DATA_SIZE;

	bcm63xx_spi_regs_init();

	return platform_device_register(&bcm63xx_spi_device);
}
