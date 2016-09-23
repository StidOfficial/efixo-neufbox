/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Maxime Bizon <mbizon@freebox.fr>
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <linux/pm.h>
#include <asm/bootinfo.h>
#include <asm/time.h>
#include <asm/reboot.h>
#include <asm/cacheflush.h>
#include <bcm63xx_board.h>
#include <bcm63xx_cpu.h>
#include <bcm63xx_regs.h>
#include <bcm63xx_io.h>

#if defined(CONFIG_BOARD_NEUFBOX4)
#define ADSL_SDRAM_IMAGE_SIZE 0x200000
#elif defined(CONFIG_BOARD_NEUFBOX6)
#define ADSL_PHY_SDRAM_BIAS 0x100000
#define ADSL_PHY_SDRAM_PAGE_SIZE 0x200000
#define ADSL_SDRAM_IMAGE_SIZE (ADSL_PHY_SDRAM_PAGE_SIZE - ADSL_PHY_SDRAM_BIAS)
#else
#define ADSL_SDRAM_IMAGE_SIZE 0
#endif

void bcm63xx_machine_halt(void)
{
	printk(KERN_INFO "System halted\n");
	while (1)
		;
}

static void bcm6348_a1_reboot(void)
{
	u32 reg;

	/* soft reset all blocks */
	printk(KERN_INFO "soft-reseting all blocks ...\n");
	reg = bcm_perf_readl(PERF_6348_SOFTRESET_REG);
	reg &= ~SOFTRESET_6348_ALL;
	bcm_perf_writel(reg, PERF_6348_SOFTRESET_REG);
	mdelay(10);

	reg = bcm_perf_readl(PERF_6348_SOFTRESET_REG);
	reg |= SOFTRESET_6348_ALL;
	bcm_perf_writel(reg, PERF_6348_SOFTRESET_REG);
	mdelay(10);

	/* Jump to the power on address. */
	printk(KERN_INFO "jumping to reset vector.\n");
	/* set high vectors (base at 0xbfc00000 */
	set_c0_status(ST0_BEV | ST0_ERL);
	/* run uncached in kseg0 */
	change_c0_config(CONF_CM_CMASK, CONF_CM_UNCACHED);
	__flush_cache_all();
	/* remove all wired TLB entries */
	write_c0_wired(0);
	__asm__ __volatile__(
		"jr\t%0"
		:
		: "r" (0xbfc00000));
	while (1)
		;
}

void bcm63xx_machine_reboot(void)
{
	u32 reg;

	/* mask and clear all external irq */
	reg = bcm_perf_readl(PERF_EXTIRQ_CFG_REG);
	reg &= ~EXTIRQ_CFG_MASK_ALL;
	reg |= EXTIRQ_CFG_CLEAR_ALL;
	bcm_perf_writel(reg, PERF_EXTIRQ_CFG_REG);

	if (BCMCPU_IS_6348() && (bcm63xx_get_cpu_rev() == 0xa1))
		bcm6348_a1_reboot();

	printk(KERN_INFO "triggering watchdog soft-reset...\n");
	reg = bcm_perf_readl(PERF_SYS_PLL_CTL_REG);
	reg |= SYS_PLL_SOFT_RESET;
	bcm_perf_writel(reg, PERF_SYS_PLL_CTL_REG);
	while (1)
		;
}

static void __bcm63xx_machine_reboot(char *p)
{
	bcm63xx_machine_reboot();
}

/*
 * return system type in /proc/cpuinfo
 */
const char *get_system_type(void)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "bcm63xx/%s (0x%04x/0x%04X)",
		 board_get_name(),
		 bcm63xx_get_cpu_id(), bcm63xx_get_cpu_rev());
	return buf;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
void __init plat_time_init(void)
{
	mips_hpt_frequency = bcm63xx_get_cpu_freq() / 2;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)
void __init plat_timer_setup(struct irqaction *irq)
{
	setup_irq(7, irq);
	set_c0_status(IE_IRQ5);
}
#endif

void __init plat_mem_setup(void)
{
	add_memory_region(0, bcm63xx_get_memory_size() - ADSL_SDRAM_IMAGE_SIZE, BOOT_MEM_RAM);

	_machine_halt = bcm63xx_machine_halt;
	_machine_restart = __bcm63xx_machine_reboot;
	pm_power_off = bcm63xx_machine_halt;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)
	set_io_port_base(KSEG1);
#else
	set_io_port_base(0);
#endif
	ioport_resource.start = 0;
	ioport_resource.end = ~0;

	board_setup();
}

int __init bcm63xx_register_devices(void)
{
	return board_register_devices();
}

arch_initcall(bcm63xx_register_devices);
