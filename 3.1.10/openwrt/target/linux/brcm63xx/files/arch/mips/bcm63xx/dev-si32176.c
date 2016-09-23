/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2010 Tanguy Bouzeloc <tanguy.bouzeloc@efixo.com> 
 */

#include <linux/kernel.h>
#include <linux/platform_device.h>

static struct resource si32176_resources[] = {
	{
		.start		= -1, /* filled at runtime */
		.flags		= IORESOURCE_IRQ,
	},
};

static struct platform_device bcm63xx_si32176_device = {
	.name = "si32176",
	.id   = 0,
	.num_resources	= ARRAY_SIZE(si32176_resources),
	.resource	= si32176_resources,
};

int __init bcm63xx_si32176_register(void)
{
	if(!BCMCPU_IS_6362())
		return 0;

	/* 
	 * TODO : add gpio abstraction layer and update code to support
	 * irq to gpio convertion
	 */
	si32176_resources[0].start = 31;
	return platform_device_register(&bcm63xx_si32176_device);
}
