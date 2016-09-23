/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Maxime Bizon <mbizon@freebox.fr>
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <asm/bootinfo.h>
#include <asm/time.h>
#include <bcm63xx_board.h>
#include <bcm63xx_cpu.h>
#include <bcm63xx_io.h>
#include <bcm63xx_regs.h>
#include <bcm63xx_gpio.h>

void __init prom_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	u32 reg, mask;
#endif

	bcm63xx_cpu_init();

	/* stop any running watchdog */
	bcm_wdt_writel(WDT_STOP_1, WDT_CTL_REG);
	bcm_wdt_writel(WDT_STOP_2, WDT_CTL_REG);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	/* disable all hardware blocks clock for now */
	if (BCMCPU_IS_6338())
		mask = CKCTL_6338_ALL_SAFE_EN;
	else if (BCMCPU_IS_6345())
		mask = CKCTL_6345_ALL_SAFE_EN;
	else if (BCMCPU_IS_6348())
		mask = CKCTL_6348_ALL_SAFE_EN;
	else if (BCMCPU_IS_6358())
		mask = CKCTL_6358_ALL_SAFE_EN;
	else
		/* BCMCPU_IS_6362() */
		mask = CKCTL_6362_ALL_SAFE_EN;

	reg = bcm_perf_readl(PERF_CKCTL_REG);
	reg &= ~mask;
	bcm_perf_writel(reg, PERF_CKCTL_REG);
#else
	bcm_perf_writel(0, PERF_IRQMASK_REG);

	mips_hpt_frequency = bcm63xx_get_cpu_freq() / 2;

	mips_machgroup = MACH_GROUP_BRCM;
	mips_machtype = MACH_BCM963XX;
#endif

	/* assign command line from kernel config */
	strcpy(arcs_cmdline, CONFIG_CMDLINE);

	/* register gpiochip */
	bcm63xx_gpio_init();

	/* do low level board init */
	board_prom_init();
}

void __init prom_free_prom_memory(void)
{
}
