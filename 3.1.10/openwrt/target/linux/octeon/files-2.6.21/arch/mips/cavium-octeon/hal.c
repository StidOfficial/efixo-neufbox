/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2004 - 2007 Cavium Networks
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <asm/time.h>
#include <octeon-app-init.h>

#ifndef CONFIG_CAVIUM_RESERVE32
#define CONFIG_CAVIUM_RESERVE32 0
#endif

#include "hal.h"

#include "cvmx-bootmem.h"
#include "cvmx-app-init.h"
#include "cvmx-sysinfo.h"
#include "cvmx-l2c.h"
#include "cvmx-spinlock.h"

/* Set to non-zero, so it is not in .bss section and is not zeroed */
volatile octeon_boot_descriptor_t *octeon_boot_desc_ptr = (void *) 0xEADBEEFULL;
cvmx_bootinfo_t *octeon_bootinfo;

/* This must not be static since inline functions access it */
spinlock_t octeon_led_lock;

#if CONFIG_CAVIUM_RESERVE32
uint64_t octeon_reserve32_memory = 0;
#endif


/**
 * Write to the LCD display connected to the bootbus. This display
 * exists on most Cavium evaluation boards. If it doesn't exist, then
 * this function doesn't do anything.
 *
 * @param s      String to write
 */
void octeon_write_lcd(const char *s)
{
	if (octeon_bootinfo->led_display_base_addr) {
		volatile char *lcd_address =
			cvmx_phys_to_ptr(octeon_bootinfo->
					 led_display_base_addr);
		int i;
		for (i = 0; i < 8; i++) {
			if (*s)
				lcd_address[i] = *s++;
			else
				lcd_address[i] = ' ';
		}
	}
}


/**
 * Check the hardware BIST results for a CPU
 */
void octeon_check_cpu_bist(void)
{
	const int coreid = cvmx_get_core_num();
	unsigned long long mask;
	unsigned long long bist_val;

	/* Check BIST results for COP0 registers */
	mask = 0x1f00000000ull;
	bist_val = __read_64bit_c0_register($27, 0);
	if (bist_val & mask)
		printk("Core%d BIST Failure: CacheErr(icache) = 0x%llx\n",
		       coreid, bist_val);

	bist_val = __read_64bit_c0_register($27, 1);
	if (bist_val & 1)
		printk("Core%d L1 Dcache parity error: CacheErr(dcache) = 0x%llx\n", coreid, bist_val);

	mask = 0xfc00000000000000ull;
	bist_val = __read_64bit_c0_register($11, 7);
	if (bist_val & mask)
		printk("Core%d BIST Failure: COP0_CVM_MEM_CTL = 0x%llx\n",
		       coreid, bist_val);

	__write_64bit_c0_register($27, 1, 0);
}


/**
 * Return non zero of we are currently running in the Octeon simulator
 *
 * @return
 */
int octeon_is_simulation(void)
{
	return (octeon_bootinfo->board_type == CVMX_BOARD_TYPE_SIM);
}


/**
 * Return true if Octeon is in PCI Host mode. This means
 * Linux can control the PCI bus.
 *
 * @return Non zero if Octeon in host mode
 */
int octeon_is_pci_host(void)
{
#ifdef CONFIG_PCI
	return (octeon_bootinfo->
		config_flags & CVMX_BOOTINFO_CFG_FLAG_PCI_HOST);
#else
	return 0;
#endif
}


/**
 * This function returns if the USB clock uses 12/24/48MHz 3.3V
 * reference clock at the USB_REF_CLK pin. Result is non zero
 * if it does, If it uses 12MHz crystal as clock source at USB_XO
 * and USB_XI, then the return value is zero. This function will
 * need update for new boards.
 *
 * @return True is USB is using a reference clock
 */
int octeon_usb_is_ref_clk(void)
{
	switch (octeon_bootinfo->board_type) {
	case CVMX_BOARD_TYPE_BBGW_REF:
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(octeon_usb_is_ref_clk);

/**
 * Get the clock rate of Octeon
 *
 * @return Clock rate in HZ
 */
uint64_t octeon_get_clock_rate(void)
{
	if (octeon_is_simulation())
		octeon_bootinfo->eclock_hz = 6000000;
	return octeon_bootinfo->eclock_hz;
}


/**
 * Return the board name as a constant string
 *
 * @return board name
 */
const char *octeon_board_type_string(void)
{
	static char name[80];
	sprintf(name, "%s (%s)",
		cvmx_board_type_to_string(octeon_bootinfo->board_type),
		octeon_model_get_string(read_c0_prid()));
	return name;
}


/**
 * Return the mapping of PCI device number to IRQ line. Each
 * character in the return string represents the interrupt
 * line for the device at that position. Device 1 maps to the
 * first character, etc. The characters A-D are used for PCI
 * interrupts.
 *
 * @return PCI interrupt mapping
 */
const char *octeon_get_pci_interrupts(void)
{
	/* Returning an empty string causes the interrupts to be routed based
	   on the PCI specification. From the PCI spec:

	   INTA# of Device Number 0 is connected to IRQW on the system board.
	   (Device Number has no significance regarding being located on the
	   system board or in a connector.) INTA# of Device Number 1 is
	   connected to IRQX on the system board. INTA# of Device Number 2 is
	   connected to IRQY on the system board. INTA# of Device Number 3 is
	   connected to IRQZ on the system board. The table below describes how
	   each agent's INTx# lines are connected to the system board interrupt
	   lines. The following equation can be used to determine to which
	   INTx# signal on the system board a given device's INTx# line(s) is
	   connected.

	   MB = (D + I) MOD 4 MB = System board Interrupt (IRQW = 0, IRQX = 1,
	   IRQY = 2, and IRQZ = 3) D = Device Number I = Interrupt Number
	   (INTA# = 0, INTB# = 1, INTC# = 2, and INTD# = 3) */
	switch (octeon_bootinfo->board_type) {	/* Device ID
		   1111111111222222222233 *//* 01234567890123456789012345678901 */
		// case CVMX_BOARD_TYPE_NAO38: return
		// "AAAAAADBAAAAAAAAAAAAAAAAAAAAAAAA";
	case CVMX_BOARD_TYPE_NAO38:
		return "AAAAADABAAAAAAAAAAAAAAAAAAAAAAAA";	/* This is
								   really the
								   NAC38 */
	case CVMX_BOARD_TYPE_THUNDER:
		return "";
	case CVMX_BOARD_TYPE_EBH3000:
		return "";
	case CVMX_BOARD_TYPE_EBH3100:
	case CVMX_BOARD_TYPE_CN3010_EVB_HS5:
	case CVMX_BOARD_TYPE_CN3005_EVB_HS5:
		return "AAABAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        case CVMX_BOARD_TYPE_BBGW_REF:
            return "AABCD";
	default:
		return "";
	}
}


/**
 * Return the interrupt line for the i8259 in the southbridge
 *
 * @return
 */
int octeon_get_southbridge_interrupt(void)
{
	switch (octeon_bootinfo->board_type) {
	case CVMX_BOARD_TYPE_EBH3000:
		return 47;	/* PCI INDD */
	case CVMX_BOARD_TYPE_NAC38:
		return 39;	/* GPIO 15 */
	default:
		return 0;	/* No southbridge */
	}
}


/**
 * Get the coremask Linux was booted on.
 *
 * @return Core mask
 */
int octeon_get_boot_coremask(void)
{
	return octeon_boot_desc_ptr->core_mask;
}


/**
 * Return the number of arguments we got from the bootloader
 *
 * @return argc
 */
int octeon_get_boot_num_arguments(void)
{
	return octeon_boot_desc_ptr->argc;
}


/**
 * Return the console uart passed by the bootloader
 *
 * @return uart   (0 or 1)
 */
int octeon_get_boot_uart(void)
{
#if OCTEON_APP_INIT_H_VERSION >= 1	/* The UART1 flag is new */
	return !!(octeon_boot_desc_ptr->flags & OCTEON_BL_FLAG_CONSOLE_UART1);
#else
	return 0;
#endif
}

/**
 * Return the debug flag passed by the bootloader
 *
 * @return debug flag (0 or 1)
 */
int octeon_get_boot_debug_flag(void)
{
	return !!(octeon_boot_desc_ptr->flags & OCTEON_BL_FLAG_DEBUG);
}

/**
 * Get an argument from the bootloader
 *
 * @param arg    argument to get
 * @return argument
 */
const char *octeon_get_boot_argument(int arg)
{
	return cvmx_phys_to_ptr(octeon_boot_desc_ptr->argv[arg]);
}


/**
 * Called very early in the initial C code to initialize the Octeon
 * HAL layer.
 */
void octeon_hal_init(void)
{
	cvmx_sysinfo_t *sysinfo;

	/* Make sure we got the boot descriptor block */
	if ((octeon_boot_desc_ptr == (void *) 0xEADBEEFULL))
		panic("Boot descriptor block wasn't passed properly\n");

	octeon_bootinfo =
		cvmx_phys_to_ptr(octeon_boot_desc_ptr->cvmx_desc_vaddr);
	cvmx_bootmem_init(cvmx_phys_to_ptr(octeon_bootinfo->phy_mem_desc_addr));

	spin_lock_init(&octeon_led_lock);
	/* Only enable the LED controller if we're running on a CN38XX, CN58XX,
	   or CN56XX. The CN30XX and CN31XX don't have an LED controller */
	if (!octeon_is_simulation() &&
	    octeon_has_feature(OCTEON_FEATURE_LED_CONTROLLER)) {
		cvmx_write_csr(CVMX_LED_EN, 0);
		cvmx_write_csr(CVMX_LED_PRT, 0);
		cvmx_write_csr(CVMX_LED_DBG, 0);
		cvmx_write_csr(CVMX_LED_PRT_FMT, 0);
		cvmx_write_csr(CVMX_LED_UDD_CNTX(0), 32);
		cvmx_write_csr(CVMX_LED_UDD_CNTX(1), 32);
		cvmx_write_csr(CVMX_LED_UDD_DATX(0), 0);
		cvmx_write_csr(CVMX_LED_UDD_DATX(1), 0);
		cvmx_write_csr(CVMX_LED_EN, 1);
	}
#if CONFIG_CAVIUM_RESERVE32
	{
		int64_t addr = -1;
		/* We need to temporarily allocate all memory in the reserve32
		   region. This makes sure the kernel doesn't allocate this
		   memory when it is getting memory from the bootloader. Later,
		   after the memory allocations are complete, the reserve32
		   will be freed */
#ifdef CONFIG_CAVIUM_RESERVE32_USE_WIRED_TLB
		if (CONFIG_CAVIUM_RESERVE32 & 0x1ff)
			printk("CAVIUM_RESERVE32 isn't a multiple of 512MB. This is required if CAVIUM_RESERVE32_USE_WIRED_TLB is set\n");
		else
			addr = cvmx_bootmem_phy_named_block_alloc
				(CONFIG_CAVIUM_RESERVE32 << 20, 0, 0, 512 << 20,
				 "CAVIUM_RESERVE32", 0);
#else
		/* Allocate memory for RESERVED32 aligned on 2MB boundary. This
		   is in case we later use hugetlb entries with it */
		addr = cvmx_bootmem_phy_named_block_alloc
			(CONFIG_CAVIUM_RESERVE32 << 20, 0, 0, 2 << 20,
			 "CAVIUM_RESERVE32", 0);
#endif
		if (addr < 0)
			printk("Failed to allocate CAVIUM_RESERVE32 memory area\n");
		else
			octeon_reserve32_memory = addr;

	}
#endif

#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2
	if (cvmx_read_csr(CVMX_L2D_FUS3) & (3ull << 34)) {
		printk("Skipping L2 locking due to reduced L2 cache size\n");
	} else {
		extern asmlinkage void handle_int(void);
		extern asmlinkage void plat_irq_dispatch(void);
		uint32_t ebase = read_c0_ebase() & 0x3ffff000;
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_TLB
		cvmx_l2c_lock_mem_region(ebase, 0x100);	/* TLB refill */
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_EXCEPTION
		cvmx_l2c_lock_mem_region(ebase + 0x180, 0x80);	/* General
								   exception */
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_LOW_LEVEL_INTERRUPT
		cvmx_l2c_lock_mem_region(ebase + 0x200, 0x80);	/* Interrupt
								   handler */
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_INTERRUPT
		cvmx_l2c_lock_mem_region(0x1fffffff & (long) handle_int, 0x100);
		cvmx_l2c_lock_mem_region(0x1fffffff & (long) plat_irq_dispatch,
					 0x80);
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_MEMCPY
		cvmx_l2c_lock_mem_region(0x1fffffff & (long) memcpy, 0x480);
#endif
	}
#endif

	sysinfo = cvmx_sysinfo_get();
	memset(sysinfo, 0, sizeof(*sysinfo));
	sysinfo->system_dram_size = octeon_bootinfo->dram_size << 20;
	sysinfo->phy_mem_desc_ptr =
		cvmx_phys_to_ptr(octeon_bootinfo->phy_mem_desc_addr);
	sysinfo->core_mask = octeon_bootinfo->core_mask;
	sysinfo->exception_base_addr = octeon_bootinfo->exception_base_addr;
	sysinfo->cpu_clock_hz = octeon_bootinfo->eclock_hz;
	sysinfo->dram_data_rate_hz = octeon_bootinfo->dclock_hz * 2;
	sysinfo->board_type = octeon_bootinfo->board_type;
	sysinfo->board_rev_major = octeon_bootinfo->board_rev_major;
	sysinfo->board_rev_minor = octeon_bootinfo->board_rev_minor;
	memcpy(sysinfo->mac_addr_base, octeon_bootinfo->mac_addr_base,
	       sizeof(sysinfo->mac_addr_base));
	sysinfo->mac_addr_count = octeon_bootinfo->mac_addr_count;
	memcpy(sysinfo->board_serial_number,
	       octeon_bootinfo->board_serial_number,
	       sizeof(sysinfo->board_serial_number));
	sysinfo->compact_flash_common_base_addr =
		octeon_bootinfo->compact_flash_common_base_addr;
	sysinfo->compact_flash_attribute_base_addr =
		octeon_bootinfo->compact_flash_attribute_base_addr;
	sysinfo->led_display_base_addr = octeon_bootinfo->led_display_base_addr;
	sysinfo->dfa_ref_clock_hz = octeon_bootinfo->dfa_ref_clock_hz;
	sysinfo->bootloader_config_flags = octeon_bootinfo->config_flags;
}


#ifdef CONFIG_CAVIUM_RESERVE32_USE_WIRED_TLB
/**
 * Called on every core to setup the wired tlb entry needed
 * if CONFIG_CAVIUM_RESERVE32_USE_WIRED_TLB is set.
 *
 * @param unused
 */
static void octeon_hal_setup_per_cpu_reserved32(void *unused)
{
	/* The config has selected to wire the reserve32 memory for all
	   userspace applications. We need to put a wired TLB entry in for each
	   512MB of reserve32 memory. We only handle double 256MB pages here,
	   so reserve32 must be multiple of 512MB */
	extern void add_wired_entry(unsigned long entrylo0,
				    unsigned long entrylo1,
				    unsigned long entryhi,
				    unsigned long pagemask);
	uint32_t size = CONFIG_CAVIUM_RESERVE32;
	uint32_t entrylo0 =
		0x7 | ((octeon_reserve32_memory & ((1ul << 40) - 1)) >> 6);
	uint32_t entrylo1 = entrylo0 + (256 << 14);
	uint32_t entryhi = (0x80000000UL - (CONFIG_CAVIUM_RESERVE32 << 20));
	while (size >= 512) {
		// printk("CPU%d: Adding double wired TLB entry for 0x%lx\n",
		// smp_processor_id(), entryhi);
		add_wired_entry(entrylo0, entrylo1, entryhi, PM_256M);
		entrylo0 += 512 << 14;
		entrylo1 += 512 << 14;
		entryhi += 512 << 20;
		size -= 512;
	}
}
#endif				/* CONFIG_CAVIUM_RESERVE32_USE_WIRED_TLB */

/**
 * Called to release the named block which was used to made sure
 * that nobody used the memory for something else during
 * init. Now we'll free it so userspace apps can use this
 * memory region with bootmem_alloc.
 *
 * This function is called only once from prom_free_prom_memory().
 */
void octeon_hal_setup_reserved32(void)
{
#ifdef CONFIG_CAVIUM_RESERVE32_USE_WIRED_TLB
	on_each_cpu(octeon_hal_setup_per_cpu_reserved32, NULL, 0, 1);
#endif
}


/**
 * Poweroff the Octeon board if possible.
 */
void octeon_poweroff(void)
{
	switch (octeon_bootinfo->board_type) {
	case CVMX_BOARD_TYPE_NAO38:
		/* Driving a 1 to GPIO 12 shuts off this board */
		cvmx_write_csr(CVMX_GPIO_BIT_CFGX(12), 1);
		cvmx_write_csr(CVMX_GPIO_TX_SET, 0x1000);
		break;
	default:
		octeon_write_lcd("PowerOff");
		break;
	}
}


/**
 * Enable access to Octeon's COP2 crypto hardware for kernel use.
 * Wrap any crypto operations in calls to
 * octeon_crypto_enable/disable in order to make sure the state of
 * COP2 isn't corrupted if userspace is also performing hardware
 * crypto operations. Allocate the state parameter on the stack.
 *
 * @param state  State structure to store current COP2 state in
 *
 * @return Flags to be passed to octeon_crypto_disable()
 */
unsigned long octeon_crypto_enable(struct octeon_cop2_state *state)
{
	extern void octeon_cop2_save(struct octeon_cop2_state *);
	int status;
	unsigned long flags;

	local_irq_save(flags);
	status = read_c0_status();
	write_c0_status(status | ST0_CU2);
	if (KSTK_STATUS(current) & ST0_CU2)
	{
		octeon_cop2_save(&(current->thread.cp2));
		KSTK_STATUS(current) &= ~ST0_CU2;
		status &= ~ST0_CU2;
	} else if (status & ST0_CU2)
		octeon_cop2_save(state);
	local_irq_restore(flags);
	return status & ST0_CU2;
}
EXPORT_SYMBOL(octeon_crypto_enable);


/**
 * Disable access to Octeon's COP2 crypto hardware in the kernel.
 * This must be called after an octeon_crypto_enable() before any
 * context switch or return to userspace.
 *
 * @param state  COP2 state to restore
 * @param flags  Return value from octeon_crypto_enable()
 */
void octeon_crypto_disable(struct octeon_cop2_state *state, unsigned long crypto_flags)
{
	extern void octeon_cop2_restore(struct octeon_cop2_state *);
	unsigned long flags;

	local_irq_save(flags);
	if (crypto_flags & ST0_CU2)
		octeon_cop2_restore(state);
	else
                write_c0_status(read_c0_status() & ~ST0_CU2);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(octeon_crypto_disable);



/* Misc exports */
EXPORT_SYMBOL(octeon_is_simulation);
EXPORT_SYMBOL(octeon_bootinfo);
EXPORT_SYMBOL(mips_hpt_frequency);
#if CONFIG_CAVIUM_RESERVE32
EXPORT_SYMBOL(octeon_reserve32_memory);
#endif

EXPORT_SYMBOL(octeon_get_clock_rate);
