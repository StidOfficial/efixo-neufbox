
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#include <bcm63xx_cpu.h>
#include <bcm63xx_dev_spi.h>
#include <bcm63xx_regs.h>

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
	.bus_num		= 1,
	.num_chipselect		= 8,
	.speed_hz		= 400000000,	/* Fclk */
};

static struct platform_device bcm63xx_spi_device = {
	.name		= "bcm63xx-hsspi",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(spi_resources),
	.resource	= spi_resources,
	.dev		= {
		.platform_data = &spi_pdata,
	},
};

int __init bcm63xx_hsspi_register(void)
{
	spi_resources[0].start = bcm63xx_regset_address(RSET_HSSPI);
	spi_resources[0].end = spi_resources[0].start;
	spi_resources[0].end += RSET_HSSPI_SIZE - 1;
	spi_resources[1].start = bcm63xx_get_irq_number(IRQ_HSSPI);

	/* Fill in platform data */
	if (BCMCPU_IS_6362())
		spi_pdata.fifo_size = 0x21e;
	
	return platform_device_register(&bcm63xx_spi_device);
}
