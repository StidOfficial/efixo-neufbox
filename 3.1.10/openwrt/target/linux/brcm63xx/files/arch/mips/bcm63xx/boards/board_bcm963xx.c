/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Maxime Bizon <mbizon@freebox.fr>
 * Copyright (C) 2008 Florian Fainelli <florian@openwrt.org>
 * Copyright (C) 2010 Miguel Gaio <miguel.gaio@efixo.com>
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/mtd/physmap.h>
#include <linux/gpio_buttons.h>
#include <linux/input.h>
#include <linux/spi/spi.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#include <linux/spi/spi_gpio.h>
#include <linux/spi/74x164.h>
#endif
#if defined(CONFIG_BOARD_NEUFBOX4)
#include <linux/74x164.h>
#elif defined(CONFIG_BOARD_NEUFBOX6)
#include <linux/spi/flash.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/i2c-gpio.h>
#include <linux/leds.h>
#include <linux/leds_pwm.h>
#include <linux/rtl8367r.h>
#endif
#include <linux/ring_logs.h>
#include <linux/proc_fs.h>
#include <asm/addrspace.h>
#include <bcm63xx_board.h>
#include <bcm63xx_cpu.h>
#include <bcm63xx_dev_uart.h>
#include <bcm63xx_regs.h>
#include <bcm63xx_io.h>
#include <bcm63xx_dev_pci.h>
#include <bcm63xx_dev_enet.h>
#include <bcm63xx_dev_dsp.h>
#include <bcm63xx_dev_pcmcia.h>
#include <bcm63xx_dev_usb_ohci.h>
#include <bcm63xx_dev_usb_ehci.h>
#include <bcm63xx_dev_usb_udc.h>
#include <bcm63xx_dev_spi.h>
#include <bcm63xx_dev_wlan.h>
#include <bcm63xx_dev_fap.h>
#include <bcm63xx_dev_si32176.h>
#include <bcm63xx_dev_tdm.h>
#include <board_bcm963xx.h>
#include <bcm_tag.h>
#if defined(CONFIG_BOARD_NEUFBOX4)
#include <neufbox/leds.h>
#include <nb4/partitions.h>
#elif defined(CONFIG_BOARD_NEUFBOX6)
#include <nb6/partitions.h>
#endif

#define PFX	"board_bcm963xx: "

#define NB4_PID_OFFSET		0xff80
#define NB4_74X164_GPIO_BASE	64
#define NB4_SPI_GPIO_MOSI	7
#define NB4_SPI_GPIO_CLK	6
#define NB4_74HC64_GPIO(X)	(NB4_74X164_GPIO_BASE + (X))

#define CFE_OFFSET_64K		0x10000
#define CFE_OFFSET_128K		0x20000

static struct bcm963xx_nvram nvram;
static unsigned int mac_addr_used;
static struct board_info board;

#if !defined(CONFIG_BOARD_NEUFBOX4) && !defined(CONFIG_BOARD_NEUFBOX6)
/*
 * Required export for WL
 */
#define NVRAM_SPACE 0x8000
char nvram_buf[NVRAM_SPACE];
EXPORT_SYMBOL(nvram_buf);
#endif

static struct ring_log_info nb_ring_log_info[] = {
	{
		.name = "daemon",
		.size = 64 << 10,
	},
	{
		.name = "kern",
		.size = 64 << 10,
	},
	{
		.name = "voip_proto",
		.size = 64 << 10,
	},
	{
		.name = "voip",
		.size = 64 << 10,
	},
	{
		.name = "messages",
		.size = 64 << 10,
	},
	{
		.name = "syslog",
		.size = 64 << 10,
	},
	{
		.name = "fastcgi",
		.size = 64 << 10,
	},
	{
		.name = "voip_events",
		.size = 64 << 10,
	},
	{
		.name = "hotspot",
		.size = 64 << 10,
	},
	{
		.name = "backup",
		.size = 64 << 10,
	},
	{
		.name = "status",
		.size = 64 << 10,
	},
	{
		.name = "wlan",
		.size = 64 << 10,
	},
};

static struct ring_log_platform_data nb_ring_logs_data = {
	.num_ring_logs	= ARRAY_SIZE(nb_ring_log_info),
	.ring_logs	= nb_ring_log_info,
};

static struct platform_device nb_ring_logs = {
	.name		= "ring-logs",
	.id		= 0,
	.dev.platform_data = &nb_ring_logs_data,
};

static struct platform_device nb_neufbox_events = {
	.name		= "neufbox-events",
	.id		= 0,
};

/*
 * known 6338 boards
 */
#ifdef CONFIG_BCM63XX_CPU_6338
static struct board_info __initdata board_96338gw = {
	.name				= "96338GW",
	.expected_cpu_id		= 0x6338,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.enet0 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0			= 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= 3,
			.active_low	= 1,
		},
		{
			.name		= "ses",
			.gpio		= 5,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 1,
			.active_low	= 1,
		}
	},
};

static struct board_info __initdata board_96338w = {
	.name				= "96338W",
	.expected_cpu_id		= 0x6338,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.enet0 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.leds = {
		{
			.name		= "adsl",
			.gpio		= 3,
			.active_low	= 1,
		},
		{
			.name		= "ses",
			.gpio		= 5,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 1,
			.active_low	= 1,
		},
	},
};

static struct board_info __initdata board_96338w2_e7t = {
	.name				= "96338W2_E7T",
	.expected_cpu_id		= 0x6338,

	.has_enet0			= 1,

	.enet0 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

		.leds = {
		{
			.name		= "ppp",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 5,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",

		},
	},
};
#endif

/*
 * known 6345 boards
 */
#ifdef CONFIG_BCM63XX_CPU_6345
static struct board_info __initdata board_96345gw2 = {
	.name				= "96345GW2",
	.expected_cpu_id		= 0x6345,

	.has_uart0			= 1,
};
#endif

/*
 * known 6348 boards
 */
#ifdef CONFIG_BCM63XX_CPU_6348
static struct board_info __initdata board_96348r = {
	.name				= "96348R",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.leds = {
		{
			.name		= "adsl-fail",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "ppp",
			.gpio		= 3,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",

		},
		{
			.name		= "stop",
			.gpio		= 1,
			.active_low	= 1,
		},
	},
};

static struct board_info __initdata board_96348gw_10 = {
	.name				= "96348GW-10",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0			= 1,
	.has_pccard			= 1,
	.has_ehci0			= 1,

	.has_dsp			= 1,
	.dsp = {
		.gpio_rst		= 6,
		.gpio_int		= 34,
		.cs			= 2,
		.ext_irq		= 2,
	},

	.leds = {
		{
			.name		= "adsl-fail",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "ppp",
			.gpio		= 3,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 1,
			.active_low	= 1,
		},
	},
};

static struct board_info __initdata board_96348gw_11 = {
	.name				= "96348GW-11",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.leds = {
		{
			.name		= "adsl-fail",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "ppp",
			.gpio		= 3,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 1,
			.active_low	= 1,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 33,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};

static struct board_info __initdata board_ct536_ct5621 = {
	.name				= "CT536_CT5621",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 0,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.leds = {
		{
			.name		= "adsl-fail",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 33,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};

static struct board_info __initdata board_96348gw = {
	.name				= "96348GW",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0 = 1,

	.has_dsp			= 1,
	.dsp = {
		.gpio_rst		= 6,
		.gpio_int		= 34,
		.ext_irq		= 2,
		.cs			= 2,
	},

	.leds = {
		{
			.name		= "adsl-fail",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "ppp",
			.gpio		= 3,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 1,
			.active_low	= 1,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 36,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};

static struct board_info __initdata board_gw6200 = {
	.name				= "GW6200",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0 = 1,

	.has_dsp			= 1,
		.dsp = {
        .gpio_rst		= 8, /* FIXME: What is real GPIO here? */
		.gpio_int		= 34,
		.ext_irq		= 2,
		.cs			= 2,
	},

	.leds = {
		{
			.name		= "line1",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "line2",
			.gpio		= 5,
			.active_low	= 1,
		},
		{
			.name		= "line3",
			.gpio		= 6,
			.active_low	= 1,
		},
		{
			.name		= "tel",
			.gpio		= 7,
			.active_low	= 1,
		},
		{
		    .name		= "ethernet",
		    .gpio		= 35,
		    .active_low	= 1,
		}, 
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 36,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};

static struct board_info __initdata board_gw6000 = {
	.name				= "GW6000",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0 = 1,

	.has_dsp			= 1,
	.dsp = {
		.gpio_rst		= 6,
		.gpio_int		= 34,
		.ext_irq		= 2,
		.cs			= 2,
	},

	/* GW6000 has no GPIO-controlled leds */

	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 36,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};



static struct board_info __initdata board_FAST2404 = {
	.name				= "F@ST2404",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
        .has_enet0			= 1,
        .has_enet1			= 1,
        .has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0			= 1,
	.has_pccard			= 1,
	.has_ehci0			= 1,

	.has_udc0			= 1,
};

static struct board_info __initdata board_rta1025w_16 = {
	.name				= "RTA1025W_16",
	.expected_cpu_id		= 0x6348,

	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},
};


static struct board_info __initdata board_DV201AMR = {
	.name				= "DV201AMR",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_pci			= 1,
	.has_ohci0			= 1,

	.has_enet0			= 1,
	.has_enet1			= 1,
	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},
};

static struct board_info __initdata board_96348gw_a = {
	.name				= "96348GW-A",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0 = 1,
};

static struct board_info __initdata board_96348_D4PW = {
	.name				= "D-4P-W",
	.expected_cpu_id		= 0x6348,

	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},
	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0			= 1,
	.has_ehci0			= 1,

	.leds = {
		{
			.name		= "ppp",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 5,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",

		},
	},

};

static struct board_info __initdata board_spw500v = {
	.name				= "SPW500V",
	.expected_cpu_id		= 0x6348,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.has_dsp			= 1,
	.dsp = {
		.gpio_rst		= 6,
		.gpio_int		= 34,
		.ext_irq		= 2,
		.cs			= 2,
	},

	.leds = {
		{
			.name		= "power:red",
			.gpio		= 1,
			.active_low	= 1,
		},
		{
			.name		= "power:green",
			.gpio		= 0,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "ppp",
			.gpio		= 3,
			.active_low	= 1,
		},
		{	.name		= "pstn",
			.gpio		= 28,
			.active_low	= 1,
		},
		{
			.name		= "voip",
			.gpio		= 32,
			.active_low	= 1,
		},
	},

	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 33,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};

#endif

/*
 * known 6358 boards
 */
#ifdef CONFIG_BCM63XX_CPU_6358
#ifndef CONFIG_BOARD_NEUFBOX4

static struct board_info __initdata board_96358gw = {
	.name				= "96358GW",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.leds = {
		{
			.name		= "power:green",
			.gpio		= 5,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "power:red",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "adsl",
			.gpio		= 9,
			.active_low	= 1,
		},
		{
			.name		= "internet:green",
			.gpio		= 2,
		},
		{
			.name		= "internet:red",
			.gpio		= 10,
		},
	},

	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 34,
			.active_low	= 1,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
	},
};

static struct board_info __initdata board_96358vw = {
	.name				= "96358VW",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.leds = {
		{
			.name		= "adsl-fail",
			.gpio		= 15,
			.active_low	= 1,
		},
		{
			.name		= "ppp",
			.gpio		= 22,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 23,
			.active_low	= 1,
		},
		{
			.name		= "power",
			.gpio		= 4,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 5,
		},
	},
};

static struct board_info __initdata board_96358vw2 = {
	.name				= "96358VW2",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= 22,
			.active_low	= 1,
		},
		{
			.name		= "ppp-fail",
			.gpio		= 23,
		},
		{
			.name		= "power",
			.gpio		= 5,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "stop",
			.gpio		= 4,
			.active_low	= 1,
		},
	},
};

static struct board_info __initdata board_CPVA642 = {
	.name                           = "CPVA642",
	.expected_cpu_id                = 0x6358,

	.has_uart0			= 1,
	.has_enet1                      = 1,
	.has_pci                        = 1,

	.enet1 = {
		.force_speed_100        = 1,
		.force_duplex_full      = 1,
 	},

	.has_ohci0 = 1,
	.has_ehci0 = 1,

	.leds = {
	    /* bi-color */
		{
			.name		= "power:red",
			.gpio		= 14,
			.active_low	= 1,
		},
		{
			.name		= "power:green",
			.gpio		= 11,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "wifi:red",
			.gpio		= 6,
			.active_low	= 1,
		},
		{
			.name		= "wifi:green",
			.gpio		= 28,
			.active_low	= 0,
		},
		{
			.name		= "link:red",
			.gpio		= 9,
			.active_low	= 1,
		},
		{
			.name		= "link:green",
			.gpio		= 10,
			.active_low	= 1,
		},
		/* green only */
		{
			.name		= "ether",
			.gpio		= 1,
			.active_low	= 1,
		},
		{
			.name		= "phone1",
			.gpio		= 4,
			.active_low	= 1,
		},
		{
			.name		= "phone2",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "usb",
			.gpio		= 3,
			.active_low	= 1,
		},
    },

	.buttons = {
		{
			.desc           = "reset",
			.gpio           = 36,
			.active_low     = 1,
			.type           = EV_KEY,
			.code           = KEY_RESTART,
			.threshold      = 3,
		},
		{
			.desc		= "wps",
			.gpio		= 37,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
	},
};


static struct board_info __initdata board_AGPFS0 = {
	.name                           = "AGPF-S0",
	.expected_cpu_id                = 0x6358,

	.has_uart0			= 1,
	.has_enet0                      = 1,
	.has_enet1                      = 1,
	.has_pci                        = 1,

	.enet0 = {
		.has_phy                = 1,
		.use_internal_phy       = 1,
	},

	.enet1 = {
		.force_speed_100        = 1,
		.force_duplex_full      = 1,
	},

	.has_ohci0 = 1,
	.has_ehci0 = 1,

	.leds = {
		/*Each led on alice gate is bi-color */
		{
			.name		= "power:red",
			.gpio		= 5,
			.active_low	= 1,
		},
		{
			.name		= "power:green",
			.gpio		= 4,
			.active_low	= 1,
			.default_trigger = "default-on",
		},
		{
			.name		= "service:red",
			.gpio		= 7,
			.active_low	= 1,
		},
		{
			.name		= "service:green",
			.gpio		= 6,
			.active_low	= 1,
		},
		{
			.name		= "adsl:red",
			.gpio		= 9,
			.active_low	= 1,
		},
		{
			.name		= "adsl:green",
			.gpio		= 10,
			.active_low	= 1,
		},
		{
			.name		= "wifi:red",
			.gpio		= 23,
			.active_low	= 1,
		},
		{
			.name		= "wifi:green",
			.gpio		= 22,
			.active_low	= 1,
		},
		{
			.name		= "internet:red",
			.gpio		= 25,
			.active_low	= 1,
		},
		{
			.name		= "internet:green",
			.gpio		= 24,
			.active_low	= 1,
		},
		{
			.name		= "usr1:red",
			.gpio		= 27,
			.active_low	= 1,
		},
		{
			.name		= "usr1:green",
			.gpio		= 26,
			.active_low	= 1,
		},
		{
			.name		= "usr2:red",
			.gpio		= 30,
			.active_low	= 1,
		},
		{
			.name		= "usr2:green",
			.gpio		= 29,
			.active_low	= 1,
		},
	},

	.buttons = {
		{
			.desc           = "reset",
			.gpio           = 37,
			.active_low     = 1,
			.type           = EV_KEY,
			.code           = KEY_RESTART,
			.threshold      = 3,
		},
		{
			.desc		= "wps",
			.gpio		= 34,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
	},
};

static struct board_info __initdata board_DWVS0 = {
	.name				= "DWV-S0",
	.expected_cpu_id		= 0x6358,

	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},

	.has_ohci0			= 1,
};
#endif

#ifdef CONFIG_MTD_PARTITIONS
static struct mtd_partition nb4_mtd_partitions[] = {
	{
		.name		= "bootloader",
		.offset		= NEUFBOX_BOOTLOADER_OFFSET,
		.size		= NEUFBOX_BOOTLOADER_SIZE,
	},
	{
		.name		= "main firmware",
		.offset		= NEUFBOX_MAINFIRMWARE_OFFSET,
		.size		= NEUFBOX_MAINFIRMWARE_SIZE,
	},
	{
		.name		= "local data (jffs2)",
		.offset		= NEUFBOX_JFFS2_OFFSET,
		.size		= NEUFBOX_JFFS2_SIZE,
	},
	{
		.name		= "rescue firmware",
		.offset		= NEUFBOX_RESCUEFIRMWARE_OFFSET,
		.size		= NEUFBOX_RESCUEFIRMWARE_SIZE,
	},
	{
		.name		= "adsl PHY",
		.offset		= NEUFBOX_ADSLFIRMWARE_OFFSET,
		.size		= NEUFBOX_ADSLFIRMWARE_SIZE,
	},
	{
		.name		= "bootloader config",
		.offset		= NEUFBOX_BOOTLOADER_CFG_OFFSET,
		.size		= NEUFBOX_BOOTLOADER_CFG_SIZE,
	},
	{
		.name		= "rootfs",
		.offset		= 0,		/* runtime filled */
		.size		= 0,		/* runtime filled */
		.mask_flags	= MTD_WRITEABLE	/* force read-only */
	},
	{
		.name		= "Flash",
		.offset		= 0,
		.size		= NEUFBOX_FLASH_SIZE,
	},
};
#endif

static struct physmap_flash_data mtd_dev_data = {
	.width			= 2,
#ifdef CONFIG_MTD_PARTITIONS
	.parts			= nb4_mtd_partitions,
	.nr_parts		= ARRAY_SIZE(nb4_mtd_partitions)
#endif
};

static struct gen_74x164_platform_data nb4_gen_74x164_data = {
	.gpio_base	= NB4_74X164_GPIO_BASE,
	.ngpio		= 8,
	.gpio_pin_data	= 7,
	.gpio_pin_clk	= 6,
};

static struct platform_device nb4_gen_74x16 = {
	.name		= GEN_74X164_DRIVER_NAME,
	.id		= 0,
	.dev.platform_data = &nb4_gen_74x164_data,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
struct spi_gpio_platform_data nb4_spi_gpio_data = {
	.sck		= NB4_SPI_GPIO_CLK,
	.mosi		= NB4_SPI_GPIO_MOSI,
	.miso		= SPI_GPIO_NO_MISO,
	.num_chipselect	= 1,
};


static struct platform_device nb4_spi_gpio = {
	.name = "spi_gpio",
	.id   = 1,
	.dev = {
		.platform_data = &nb4_spi_gpio_data,
	},
};
#endif

static struct platform_device * __initdata nb4_devices[] = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	&nb4_spi_gpio,
#else
	&nb4_gen_74x16,
#endif
	&nb_ring_logs,
	&nb_neufbox_events,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
const struct gen_74x164_chip_platform_data nb4_74x164_platform_data = {
	.base = NB4_74X164_GPIO_BASE
};

static struct spi_board_info nb4_spi_devices[] = {
	{
		.modalias = "74x164",
		.max_speed_hz = 781000,
		.bus_num = 1,
		.controller_data = (void *) SPI_GPIO_NO_CHIPSELECT,
		.mode = SPI_MODE_0,
		.platform_data = &nb4_74x164_platform_data
	},
	{
		.modalias = "si3050",
		.max_speed_hz = 6250000,
		.bus_num = 0,
		.chip_select = 1,
		.mode = SPI_MODE_0,
	},
	{
		.modalias = "si3216",
		.max_speed_hz = 6250000,
		.bus_num = 0,
		.chip_select = 2,
		.mode = SPI_MODE_0,
	}
};

static struct spi_board_info nb4_no_daa_spi_devices[] = {
	{
		.modalias = "74x164",
		.max_speed_hz = 781000,
		.bus_num = 1,
		.controller_data = (void *) SPI_GPIO_NO_CHIPSELECT,
		.mode = SPI_MODE_0,
		.platform_data = &nb4_74x164_platform_data
	},
	{
		.modalias = "si3216",
		.max_speed_hz = 6250000,
		.bus_num = 0,
		.chip_select = 2,
		.mode = SPI_MODE_0,
	}
};
#endif

static struct board_info __initdata board_nb4_ser_r0 = {
	.name				= "NB4-SER-r0",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,
	.has_extspi0                    = 1,
	.has_extspi1                    = 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.has_udc0			= 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= NB4_74HC64_GPIO(4),
			.active_low	= 1,
		},
		{
			.name		= "traffic",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "tel",
			.gpio		= NB4_74HC64_GPIO(3),
			.active_low	= 1,
		},
		{
			.name		= "tv",
			.gpio		= NB4_74HC64_GPIO(2),
			.active_low	= 1,
		},
		{
			.name		= "wifi",
			.gpio		= 15,
			.active_low	= 1,
		},
		{
			.name		= "alarm",
			.gpio		= NB4_74HC64_GPIO(0),
			.active_low	= 1,
		},
		{
			.name		= "service:red",
			.gpio		= 29,
			.active_low	= 1,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:green",
			.gpio		= 30,
			.active_low	= 1,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:blue",
			.gpio		= 4,
			.active_low	= 1,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 34,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
		{
			.desc		= "wps",
			.gpio		= 37,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
		{
			.desc		= "service",
			.gpio		= 27,
			.type		= EV_KEY,
			.code		= BTN_0,
			.threshold	= 3,
		},
		{
			.desc		= "clip",
			.gpio		= 31,
			.type		= EV_KEY,
			.code		= BTN_1,
			.threshold	= 3,
		},
	},
	.devs = nb4_devices,
	.num_devs = ARRAY_SIZE(nb4_devices),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	.spis = nb4_spi_devices,
	.num_spis = ARRAY_SIZE(nb4_spi_devices),
#endif
};

static struct board_info __initdata board_nb4_ser_r1 = {
	.name				= "NB4-SER-r1",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,
	.has_extspi1                    = 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.has_udc0			= 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= NB4_74HC64_GPIO(4),
			.active_low	= 1,
		},
		{
			.name		= "traffic",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "tel",
			.gpio		= NB4_74HC64_GPIO(3),
			.active_low	= 1,
		},
		{
			.name		= "tv",
			.gpio		= NB4_74HC64_GPIO(2),
			.active_low	= 1,
		},
		{
			.name		= "wifi",
			.gpio		= 15,
			.active_low	= 1,
		},
		{
			.name		= "alarm",
			.gpio		= NB4_74HC64_GPIO(0),
			.active_low	= 1,
		},
		{
			.name		= "service:red",
			.gpio		= 29,
			.active_low	= 1,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:green",
			.gpio		= 30,
			.active_low	= 1,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:blue",
			.gpio		= 4,
			.active_low	= 1,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 34,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
		{
			.desc		= "wps",
			.gpio		= 37,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
		{
			.desc		= "service",
			.gpio		= 27,
			.type		= EV_KEY,
			.code		= BTN_0,
			.threshold	= 3,
		},
		{
			.desc		= "clip",
			.gpio		= 31,
			.type		= EV_KEY,
			.code		= BTN_1,
			.threshold	= 3,
		},
	},
	.devs = nb4_devices,
	.num_devs = ARRAY_SIZE(nb4_devices),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	.spis = nb4_no_daa_spi_devices,
	.num_spis = ARRAY_SIZE(nb4_no_daa_spi_devices),
#endif
};

static struct board_info __initdata board_nb4_ser_r2 = {
	.name				= "NB4-SER-r2",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,
	.has_extspi0                    = 1,
	.has_extspi1                    = 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= NB4_74HC64_GPIO(4),
			.active_low	= 1,
		},
		{
			.name		= "traffic",
			.gpio		= 2,
			.active_low	= 1,
		},
		{
			.name		= "tel",
			.gpio		= NB4_74HC64_GPIO(3),
			.active_low	= 1,
		},
		{
			.name		= "tv",
			.gpio		= NB4_74HC64_GPIO(2),
			.active_low	= 1,
		},
		{
			.name		= "wifi",
			.gpio		= 15,
			.active_low	= 1,
		},
		{
			.name		= "alarm",
			.gpio		= NB4_74HC64_GPIO(0),
			.active_low	= 1,
		},
		{
			.name		= "service:red",
			.gpio		= 29,
			.active_low	= 1,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:green",
			.gpio		= 30,
			.active_low	= 1,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:blue",
			.gpio		= 4,
			.active_low	= 1,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 34,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
		{
			.desc		= "wps",
			.gpio		= 37,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
		{
			.desc		= "service",
			.gpio		= 27,
			.type		= EV_KEY,
			.code		= BTN_0,
			.threshold	= 3,
		},
		{
			.desc		= "clip",
			.gpio		= 31,
			.type		= EV_KEY,
			.code		= BTN_1,
			.threshold	= 3,
		},
	},
	.devs = nb4_devices,
	.num_devs = ARRAY_SIZE(nb4_devices),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	.spis = nb4_spi_devices,
	.num_spis = ARRAY_SIZE(nb4_spi_devices),
#endif
};

static struct board_info __initdata board_nb4_fxc_r1 = {
	.name				= "NB4-FXC-r1",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,
	.has_extspi0                    = 1,
	.has_extspi1                    = 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.has_udc0			= 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= NB4_74HC64_GPIO(4),
			.active_low	= 1,
		},
		{
			.name		= "traffic",
			.gpio		= 2,
		},
		{
			.name		= "tel",
			.gpio		= NB4_74HC64_GPIO(3),
			.active_low	= 1,
		},
		{
			.name		= "tv",
			.gpio		= NB4_74HC64_GPIO(2),
			.active_low	= 1,
		},
		{
			.name		= "wifi",
			.gpio		= 15,
		},
		{
			.name		= "alarm",
			.gpio		= NB4_74HC64_GPIO(0),
			.active_low	= 1,
		},
		{
			.name		= "service:red",
			.gpio		= 29,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:green",
			.gpio		= 30,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:blue",
			.gpio		= 4,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 34,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
		{
			.desc		= "wps",
			.gpio		= 37,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
		{
			.desc		= "service",
			.gpio		= 27,
			.type		= EV_KEY,
			.code		= BTN_0,
			.threshold	= 3,
		},
		{
			.desc		= "clip",
			.gpio		= 31,
			.type		= EV_KEY,
			.code		= BTN_1,
			.threshold	= 3,
		},
	},
	.devs = nb4_devices,
	.num_devs = ARRAY_SIZE(nb4_devices),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	.spis = nb4_spi_devices,
	.num_spis = ARRAY_SIZE(nb4_spi_devices),
#endif
};

static struct board_info __initdata board_nb4_fxc_r2 = {
	.name				= "NB4-FXC-r2",
	.expected_cpu_id		= 0x6358,

	.has_uart0			= 1,
	.has_enet0			= 1,
	.has_enet1			= 1,
	.has_pci			= 1,
	.has_extspi1                    = 1,

	.enet0 = {
		.has_phy		= 1,
		.use_internal_phy	= 1,
	},

	.enet1 = {
		.force_speed_100	= 1,
		.force_duplex_full	= 1,
	},


	.has_ohci0 = 1,
	.has_pccard = 1,
	.has_ehci0 = 1,

	.leds = {
		{
			.name		= "adsl",
			.gpio		= NB4_74HC64_GPIO(4),
			.active_low	= 1,
		},
		{
			.name		= "traffic",
			.gpio		= 2,
		},
		{
			.name		= "tel",
			.gpio		= NB4_74HC64_GPIO(3),
			.active_low	= 1,
		},
		{
			.name		= "tv",
			.gpio		= NB4_74HC64_GPIO(2),
			.active_low	= 1,
		},
		{
			.name		= "wifi",
			.gpio		= 15,
		},
		{
			.name		= "alarm",
			.gpio		= NB4_74HC64_GPIO(0),
			.active_low	= 1,
		},
		{
			.name		= "service:red",
			.gpio		= 29,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:green",
			.gpio		= 30,
			.default_state	= LEDS_GPIO_DEFSTATE_ON,
		},
		{
			.name		= "service:blue",
			.gpio		= 4,
		},
	},
	.buttons = {
		{
			.desc		= "reset",
			.gpio		= 34,
			.type		= EV_KEY,
			.code		= KEY_RESTART,
			.threshold	= 3,
		},
		{
			.desc		= "wps",
			.gpio		= 37,
			.type		= EV_KEY,
			.code		= KEY_WPS_BUTTON,
			.threshold	= 3,
		},
		{
			.desc		= "service",
			.gpio		= 27,
			.type		= EV_KEY,
			.code		= BTN_0,
			.threshold	= 3,
		},
		{
			.desc		= "clip",
			.gpio		= 31,
			.type		= EV_KEY,
			.code		= BTN_1,
			.threshold	= 3,
		},
	},
	.devs = nb4_devices,
	.num_devs = ARRAY_SIZE(nb4_devices),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	.spis = nb4_no_daa_spi_devices,
	.num_spis = ARRAY_SIZE(nb4_no_daa_spi_devices),
#endif
};
#endif

#ifdef CONFIG_BCM63XX_CPU_6362
static struct led_pwm neufbox6_leds_array[] = {
	{
		.name		= "service1:red",
		.pwm_id		= 0x10,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "service2:red",
		.pwm_id		= 0x11,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "service3:red",
		.pwm_id		= 0x12,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "service1:green",
		.pwm_id		= 0x13,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "service2:green",
		.pwm_id		= 0x14,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "service3:green",
		.pwm_id		= 0x15,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "wan",
		.pwm_id		= 0x16,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "voip",
		.pwm_id		= 0x17,
		.max_brightness	= 255,
		.pwm_period_ns	= 255},
	{
		.name		= "wlan",
		.pwm_id		= 0x18,
		.max_brightness	= 255,
		.pwm_period_ns	= 255
	},
};

static struct led_pwm_platform_data neufbox6_led_data = {
	.num_leds = ARRAY_SIZE(neufbox6_leds_array),
	.leds = neufbox6_leds_array,
};

static struct platform_device nb6_pwm_leds_dev = {
	.name = "leds_pwm",
	.id = 0,
	.dev.platform_data = &neufbox6_led_data,
};

static struct i2c_gpio_platform_data nb6_i2c_gpio_data = {
	.sda_pin = 30,
	.scl_pin = 2,
};

static struct platform_device nb6_i2c_gpio_dev = {
	.name = "i2c-gpio",
	.id = 0,
	.dev.platform_data = &nb6_i2c_gpio_data,
};

static struct rtl8367r_platform_data nb6_rtl8367r_platform_data = {
	.gpio_sda = 18,
	.gpio_sck = 20,
	.irq = 51,
};

static struct platform_device nb6_rtl8367r_dev = {
	.name = RTL8367R_DRIVER_NAME,
	.id = 0,
	.dev.platform_data = &nb6_rtl8367r_platform_data,
};

#ifdef CONFIG_MTD_PARTITIONS
static struct mtd_partition nb6_mtd_partitions[] = {
	{
		.name		= "bootloader",
		.offset		= NEUFBOX_BOOTLOADER_OFFSET,
		.size		= NEUFBOX_BOOTLOADER_SIZE,
	},
	{
		.name		= "main firmware",
		.offset		= NEUFBOX_MAINFIRMWARE_OFFSET,
		.size		= NEUFBOX_MAINFIRMWARE_SIZE,
	},
	{
		.name		= "local data (jffs2)",
		.offset		= NEUFBOX_JFFS2_OFFSET,
		.size		= NEUFBOX_JFFS2_SIZE,
	},
	{
		.name		= "adsl PHY",
		.offset		= NEUFBOX_ADSLFIRMWARE_OFFSET,
		.size		= NEUFBOX_ADSLFIRMWARE_SIZE,
	},
	{
		.name		= "rescue firmware",
		.offset		= NEUFBOX_RESCUEFIRMWARE_OFFSET,
		.size		= NEUFBOX_RESCUEFIRMWARE_SIZE,
	},
	{
		.name		= "bootloader config",
		.offset		= NEUFBOX_BOOTLOADER_CFG_OFFSET,
		.size		= NEUFBOX_BOOTLOADER_CFG_SIZE,
	},
	{
		.name		= "Flash",
		.offset		= 0,
		.size		= NEUFBOX_FLASH_SIZE,
	},
};
#endif

static struct flash_platform_data nb6_flash_data = {
#ifdef CONFIG_MTD_PARTITIONS
	.parts = nb6_mtd_partitions,
	.nr_parts = ARRAY_SIZE(nb6_mtd_partitions)
#endif
};

static struct platform_device * __initdata nb6_devices[] = {
	&nb_ring_logs,
	&nb_neufbox_events,
	&nb6_pwm_leds_dev,
	&nb6_i2c_gpio_dev,
	&nb6_rtl8367r_dev,
};

static struct spi_board_info nb6_spi_devices[] = {
	{
		.modalias = "m25p80",
		.bus_num = 1,
		.chip_select = 0,
		.max_speed_hz = 50000000,
		.platform_data = &nb6_flash_data,
		.mode = SPI_MODE_0,
	},
#if 0
	{
		.modalias = "si32176",
		.bus_num = 0,
		.chip_select = 0,
		.max_speed_hz = 6250000,
		.mode = SPI_MODE_0,
	},
#endif
};

static struct board_info __initdata board_nb6 = {
	.name				= "NB6",
	.expected_cpu_id		= 0x6362,

	.has_uart0			= 1,
	.has_pci			= 1,

	.has_ohci0 = 1,
	.has_ehci0 = 1,

	.buttons = {
		{
			.desc = "reset",
			.gpio = 24,
			.type = EV_KEY,
			.code = KEY_RESTART,
			.threshold = 3,
		},
		{
			.desc = "wps",
			.gpio = 25,
			.type = EV_KEY,
			.code = KEY_WPS_BUTTON,
			.threshold = 3,
		},
		{
			.desc = "service",
			.gpio = 10,
			.type = EV_KEY,
			.code = BTN_0,
			.threshold = 3,
		},
		{
			.desc = "wlan-on",
			.gpio = 14,
			.type = EV_KEY,
			.code = BTN_1,
			.threshold = 3,
			.active_low = 1,
		},
		{
			.desc = "eco",
			.gpio = 16,
			.type = EV_KEY,
			.code = BTN_2,
			.threshold = 3,
		},
	},
	.devs = nb6_devices,
	.num_devs = ARRAY_SIZE(nb6_devices),
	.spis = nb6_spi_devices,
	.num_spis = ARRAY_SIZE(nb6_spi_devices),
};
#endif

/*
 * all boards
 */
static const struct board_info __initdata *bcm963xx_boards[] = {
#ifdef CONFIG_BCM63XX_CPU_6338
	&board_96338gw,
	&board_96338w,
	&board_96338w2_e7t,
#endif
#ifdef CONFIG_BCM63XX_CPU_6345
	&board_96345gw2,
#endif
#ifdef CONFIG_BCM63XX_CPU_6348
	&board_96348r,
	&board_96348gw,
	&board_gw6000,
	&board_gw6200,
	&board_96348gw_10,
	&board_96348gw_11,
	&board_FAST2404,
	&board_DV201AMR,
	&board_96348gw_a,
	&board_rta1025w_16,
	&board_96348_D4PW,
	&board_spw500v,
	&board_ct536_ct5621,
#endif

#ifdef CONFIG_BCM63XX_CPU_6358
#ifndef CONFIG_BOARD_NEUFBOX4
	&board_96358gw,
	&board_96358vw,
	&board_96358vw2,
	&board_AGPFS0,
	&board_CPVA642,
	&board_DWVS0,
#endif
	&board_nb4_ser_r0,
	&board_nb4_ser_r1,
	&board_nb4_ser_r2,
	&board_nb4_fxc_r1,
	&board_nb4_fxc_r2,
#endif
#ifdef CONFIG_BCM63XX_CPU_6362
	&board_nb6,
#endif
};

#ifdef CONFIG_BCM63XX_CPU_6358
static void __init nb4_nvram_fixup(u8 *boot_addr)
{
	u8 *p;

	if (!(BCMCPU_IS_6358() && (!strcmp(nvram.name, "96358VW"))))
		return;

	/* Extract nb4 PID: default value to NB4-FXC-r2 */
	p = boot_addr + NB4_PID_OFFSET;
	if (!memcmp(p, "NB4-", 4))
		memcpy(nvram.name, p, sizeof("NB4-XXX-rX"));
	else
		memcpy(nvram.name, "NB4-FXC-r2", sizeof("NB4-FXC-r2"));
}
#else
#define nb4_nvram_fixup(x)
#endif

#ifdef CONFIG_BCM63XX_CPU_6362
static void __init nb6_nvram_fixup(void)
{
	if (!BCMCPU_IS_6362())
		return;

	if ((!memcmp(nvram.name, "NB6-SER-S", sizeof("NB6-SER-S") - 1))
	    || (!memcmp(nvram.name, "NB6-FXC-S", sizeof("NB6-FXC-S") - 1))
	    || (!memcmp(nvram.name, "NB6-FXC-r0", sizeof("NB6-FXC-r0") - 1))) {
		nb6_i2c_gpio_data.sda_pin = 3;
		board_nb6.buttons[2].gpio = 15;
	}
	memcpy(nvram.name, "NB6", sizeof("NB6"));
}
#else
#define nb6_nvram_fixup()
#endif

/*
 * Register a sane SPROMv2 to make the on-board
 * bcm4318 WLAN work
 */
#ifdef CONFIG_SSB_PCIHOST
static struct ssb_sprom bcm63xx_sprom = {
	.revision		= 0x02,
	.board_rev		= 0x17,
	.country_code		= 0x0,
	.ant_available_bg 	= 0x3,
	.pa0b0			= 0x15ae,
	.pa0b1			= 0xfa85,
	.pa0b2			= 0xfe8d,
	.pa1b0			= 0xffff,
	.pa1b1			= 0xffff,
	.pa1b2			= 0xffff,
	.gpio0			= 0xff,
	.gpio1			= 0xff,
	.gpio2			= 0xff,
	.gpio3			= 0xff,
	.maxpwr_bg		= 0x004c,
	.itssi_bg		= 0x00,
	.boardflags_lo		= 0x2848,
	.boardflags_hi		= 0x0000,
};
#endif

/*
 * return board name for /proc/cpuinfo
 */
const char *board_get_name(void)
{
	return board.name;
}
EXPORT_SYMBOL(board_get_name);

/*
 * register & return a new board mac address
 */
int board_get_mac_address(u8 *mac, unsigned off)
{
	unsigned int *mac_last_digits = (unsigned int *)(mac + 2);
	unsigned int buf;

#ifdef CONFIG_BOARD_NEUFBOX4
	mac_addr_used = off;
#endif
	memcpy(mac, nvram.mac_addr_base, ETH_ALEN);

	buf = ntohl(*mac_last_digits);
	buf += mac_addr_used;
	*mac_last_digits = htonl(buf);

	mac_addr_used++;
	return 0;
}
EXPORT_SYMBOL(board_get_mac_address);

/*
 * register & return a new board mac address
 */
int board_get_wlan_mac_address(u8 * mac)
{
	unsigned int *mac_last_digits = (unsigned int *)(mac + 2);
	unsigned int buf;

	memcpy(mac, nvram.mac_addr_base, ETH_ALEN);
	buf = ntohl(*mac_last_digits);
	buf += 4;
	*mac_last_digits = htonl(buf);

	return 0;
}
EXPORT_SYMBOL(board_get_wlan_mac_address);

#if !defined(CONFIG_BOARD_NEUFBOX4) && !defined(CONFIG_BOARD_NEUFBOX6)
static void __init boardid_fixup(u8 *boot_addr)
{
	struct bcm_tag *tag = (struct bcm_tag *)(boot_addr + CFE_OFFSET_64K);

	/* check if bcm_tag is at 64k offset */
	if (strncmp(nvram.name, tag->boardid, BOARDID_LEN) != 0) {
		/* else try 128k */
		tag = (struct bcm_tag *)(boot_addr + CFE_OFFSET_128K);
		if (strncmp(nvram.name, tag->boardid, BOARDID_LEN) != 0) {
			/* No tag found */
			printk(KERN_DEBUG "No bcm_tag found!\n");
			return;
		}
	}
	/* check if we should override the boardid */
	if (tag->information1[0] != '+')
		return;

	strncpy(nvram.name, &tag->information1[1], BOARDID_LEN);

	printk(KERN_INFO "Overriding boardid with '%s'\n", nvram.name);
}
#endif

/*
 * early init callback, read nvram data from flash and checksum it
 */
void __init board_prom_init(void)
{
	unsigned int check_len, i;
	u8 *boot_addr, *cfe, *p;
	char cfe_version[32];
	u32 val;

	/* read base address of boot chip select (0)
	 * 6345 does not have MPI but boots from standard
	 * MIPS Flash address */
	if (BCMCPU_IS_6345())
		val = 0x1fc00000;
	else if (BCMCPU_IS_6362())
		val = 0x18000000;
	else {
		val = bcm_mpi_readl(MPI_CSBASE_REG(0));
		val &= MPI_CSBASE_BASE_MASK;
	}
	boot_addr = (u8 *)KSEG1ADDR(val);

	/* dump cfe version */
	cfe = boot_addr + BCM963XX_CFE_VERSION_OFFSET;
	if (!memcmp(cfe, "cfe-v", 5))
		snprintf(cfe_version, sizeof(cfe_version), "%u.%u.%u-%u.%u",
			 cfe[5], cfe[6], cfe[7], cfe[8], cfe[9]);
	else
		strcpy(cfe_version, "unknown");
	printk(KERN_INFO PFX "CFE version: %s\n", cfe_version);

	/* extract nvram data */
	memcpy(&nvram, boot_addr + BCM963XX_NVRAM_OFFSET, sizeof(nvram));
#if !defined(CONFIG_BOARD_NEUFBOX4) && !defined(CONFIG_BOARD_NEUFBOX6)
	memcpy(&nvram_buf, boot_addr + BCM963XX_NVRAM_OFFSET, NVRAM_SPACE);
#endif

	/* check checksum before using data */
	if (nvram.version <= 4)
		check_len = offsetof(struct bcm963xx_nvram, checksum_old);
	else
		check_len = sizeof(nvram);
	val = 0;
	p = (u8 *)&nvram;
	while (check_len--)
		val += *p;
	if (val) {
		printk(KERN_ERR PFX "invalid nvram checksum\n");
		return;
	}

	/* Fixup broken nb4 board name */
	strcpy(cfe_version, nvram.name);
	nb4_nvram_fixup(boot_addr);
	nb6_nvram_fixup();

#if !defined(CONFIG_BOARD_NEUFBOX4) && !defined(CONFIG_BOARD_NEUFBOX6)
	if (strcmp(cfe_version, "unknown") != 0) {
		/* cfe present */
		boardid_fixup(boot_addr);
	}
#endif

	/* find board by name */
	for (i = 0; i < ARRAY_SIZE(bcm963xx_boards); i++) {
		if (strncmp(nvram.name, bcm963xx_boards[i]->name,
			    sizeof(nvram.name)))
			continue;
		/* copy, board desc array is marked initdata */
		memcpy(&board, bcm963xx_boards[i], sizeof(board));
		if (!strcmp(board.name, "NB6"))
			strcpy(board.name, cfe_version);
		break;
	}

	/* bail out if board is not found, will complain later */
	if (!board.name[0]) {
		char name[17];
		memcpy(name, nvram.name, 16);
		name[16] = 0;
		printk(KERN_ERR PFX "unknown bcm963xx board: %s\n",
		       name);
		return;
	}

	/* setup pin multiplexing depending on board enabled device,
	 * this has to be done this early since PCI init is done
	 * inside arch_initcall */
	val = 0;

#ifdef CONFIG_PCI
	if (board.has_pci) {
		bcm63xx_pci_enabled = 1;
		if (BCMCPU_IS_6348())
			val |= GPIO_MODE_6348_G2_PCI;
	}
#endif

	if (board.has_pccard) {
		if (BCMCPU_IS_6348())
			val |= GPIO_MODE_6348_G1_MII_PCCARD;
	}

	if (board.has_enet0 && !board.enet0.use_internal_phy) {
		if (BCMCPU_IS_6348())
			val |= GPIO_MODE_6348_G3_EXT_MII |
				GPIO_MODE_6348_G0_EXT_MII;
	}

	if (board.has_enet1 && !board.enet1.use_internal_phy) {
		if (BCMCPU_IS_6348())
			val |= GPIO_MODE_6348_G3_EXT_MII |
				GPIO_MODE_6348_G0_EXT_MII;
		else if (BCMCPU_IS_6358())
			val |= GPIO_MODE_6358_ENET1_MII_CLK_INV;
	}

	if (BCMCPU_IS_6358())
		val |= GPIO_MODE_6358_EXTRA_SPI_SS;

	bcm_gpio_writel(val, GPIO_MODE_REG);

	if (board.has_extspi0) {
		if (gpio_request(32, "extspi0"))
			printk(KERN_ERR PFX "extspi0 gpio error");
		else
			gpio_direction_output(32, 1);
	}

	if (board.has_extspi1) {
		if (gpio_request(33, "extspi1"))
			printk(KERN_ERR PFX "extspi1 gpio error");
		else
			gpio_direction_output(33, 1);
	}

	/* Generate MAC address for WLAN and
	 * register our SPROM */
#ifdef CONFIG_SSB_PCIHOST
	if (!board_get_mac_address(bcm63xx_sprom.il0mac)) {
		memcpy(bcm63xx_sprom.et0mac, bcm63xx_sprom.il0mac, ETH_ALEN);
		memcpy(bcm63xx_sprom.et1mac, bcm63xx_sprom.il0mac, ETH_ALEN);
		if (ssb_arch_set_fallback_sprom(&bcm63xx_sprom) < 0)
			printk(KERN_ERR "failed to register fallback SPROM\n");
	}
#endif

	printk(PFX "%s %02x:%02x:%02x:%02x:%02x:%02x\n", nvram.name,
	       nvram.mac_addr_base[0], nvram.mac_addr_base[1],
	       nvram.mac_addr_base[2], nvram.mac_addr_base[3],
	       nvram.mac_addr_base[4], nvram.mac_addr_base[5]);
}

/*
 * second stage init callback, good time to panic if we couldn't
 * identify on which board we're running since early printk is working
 */
void __init board_setup(void)
{
	if (!board.name[0])
		panic("unable to detect bcm963xx board");
	printk(KERN_INFO PFX "board name: %s\n", board.name);

	/* make sure we're running on expected cpu */
	if (bcm63xx_get_cpu_id() != board.expected_cpu_id)
		panic("unexpected CPU for bcm963xx board");
}

#ifdef CONFIG_BOARD_NEUFBOX4
static struct resource mtd_resources[] = {
	{
		.start		= 0,	/* filled at runtime */
		.end		= 0,	/* filled at runtime */
		.flags		= IORESOURCE_MEM,
	}
};

static struct platform_device mtd_dev = {
	.name			= "physmap-flash",
	.resource		= mtd_resources,
	.num_resources		= ARRAY_SIZE(mtd_resources),
	.dev.platform_data	= &mtd_dev_data,
};
#endif

static struct resource gpiodev_resource = {
	.start			= 0xFFFFFFFF,
};

static struct gpio_led_platform_data bcm63xx_led_data;

static struct platform_device bcm63xx_gpio_leds = {
	.name			= "leds-neufbox",
	.id			= 0,
	.dev.platform_data	= &bcm63xx_led_data,
};

static struct gpio_buttons_platform_data bcm63xx_gpio_buttons_data = {
	.poll_interval  = 50,
};

static struct platform_device bcm63xx_gpio_buttons_device = {
	.name		= "gpio-buttons",
	.id		= 0,
	.dev.platform_data = &bcm63xx_gpio_buttons_data,
};

static int proc_read_mac_address_base(char *buf, char **start, off_t offset,
				      int count, int *eof, void *data)
{
	*eof = 1;
	return snprintf(buf, count, "%02X%02X%02X%02X%02X%02X\n",
			nvram.mac_addr_base[0], nvram.mac_addr_base[1],
			nvram.mac_addr_base[2], nvram.mac_addr_base[3],
			nvram.mac_addr_base[4], nvram.mac_addr_base[5]);
}

static int proc_read_productid(char *buf, char **start, off_t offset, int count,
			       int *eof, void *data)
{
	*eof = 1;
	return snprintf(buf, count, "%s\n", board_get_name());
}

/*
 * third stage init callback, register all board devices.
 */
int __init board_register_devices(void)
{
#ifdef CONFIG_BOARD_NEUFBOX4
	u32 val;
#endif
	int button_count = 0;
	int led_count = 0;

	if (board.has_uart0)
		bcm63xx_uart_register(0);

	if (board.has_uart1)
		bcm63xx_uart_register(1);

	if (board.has_pccard)
		bcm63xx_pcmcia_register();

#if !defined(CONFIG_BOARD_NEUFBOX4) && !defined(CONFIG_BOARD_NEUFBOX6)
	if (board.has_enet0 &&
	    !board_get_mac_address(board.enet0.mac_addr))
		bcm63xx_enet_register(0, &board.enet0);

	if (board.has_enet1 &&
	    !board_get_mac_address(board.enet1.mac_addr))
		bcm63xx_enet_register(1, &board.enet1);
#endif

	if (board.has_ehci0)
		bcm63xx_ehci_register();

	if (board.has_ohci0)
		bcm63xx_ohci_register();

#if !defined(CONFIG_BOARD_NEUFBOX4) && !defined(CONFIG_BOARD_NEUFBOX6)
	if (board.has_dsp)
		bcm63xx_dsp_register(&board.dsp);

	if (board.has_udc0)
		bcm63xx_udc_register();
#endif

	if (board.num_devs)
		platform_add_devices(board.devs, board.num_devs);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	if (board.num_spis)
		spi_register_board_info(board.spis, board.num_spis);
#endif

	if (!BCMCPU_IS_6345())
		bcm63xx_spi_register();

#ifdef CONFIG_BOARD_NEUFBOX6
	bcm63xx_hsspi_register();
	bcm63xx_wlan_register();
	bcm63xx_fap_register();
	bcm63xx_si32176_register();
	bcm63xx_tdm_register();
#endif

#ifdef CONFIG_BOARD_NEUFBOX4
	/* read base address of boot chip select (0) */
	if (BCMCPU_IS_6345())
		val = 0x1fc00000;
	else {
		val = bcm_mpi_readl(MPI_CSBASE_REG(0));
		val &= MPI_CSBASE_BASE_MASK;
	}
	mtd_resources[0].start = val;
	mtd_resources[0].end = val + NEUFBOX_FLASH_SIZE - 1;

	platform_device_register(&mtd_dev);
#endif

	platform_device_register_simple("GPIODEV", 0, &gpiodev_resource, 1);

	/* count number of LEDs defined by this device */
	while (led_count < ARRAY_SIZE(board.leds) && board.leds[led_count].name)
		led_count++;

	if (led_count) {
		bcm63xx_led_data.num_leds = led_count;
		bcm63xx_led_data.leds = board.leds;

		platform_device_register(&bcm63xx_gpio_leds);
	}

	/* count number of BUTTONs defined by this device */
	while (button_count < ARRAY_SIZE(board.buttons) && board.buttons[button_count].desc)
		button_count++;

	if (button_count) {
		bcm63xx_gpio_buttons_data.nbuttons = button_count;
		bcm63xx_gpio_buttons_data.buttons = board.buttons;

		platform_device_register(&bcm63xx_gpio_buttons_device);
	}

#ifdef CONFIG_BOARD_NEUFBOX4
	if (gpio_request(10, "VoIP relay") < 0)
		printk("gpio_request failed for %u\n", 10);
	gpio_direction_output(10, 0);
#endif

#ifdef CONFIG_BOARD_NEUFBOX6
	if (gpio_request(17, "plc") < 0)
		printk("gpio_request failed for %u\n", 17);
#endif

	if (create_proc_read_entry
	    ("mac_address_base", 0, NULL, proc_read_mac_address_base, NULL) < 0)
		printk(KERN_ERR "create /proc/%s entry failed\n", "mac_address_base");
	if (create_proc_read_entry
	    ("productid", 0, NULL, proc_read_productid, NULL) < 0)
		printk(KERN_ERR "create /proc/%s entry failed\n", "productid");

	return 0;
}

static int __init neufbox_profile(char *str)
{
#ifndef CONFIG_BLK_DEV_INITRD
	struct bcm_tag *tag;
	u8 *boot_addr;
	u32 val;
	u32 kerneladdr;
	u32 kernellen;
	u32 rootfsaddr;
	u32 rootfslen;

	val = bcm_mpi_readl(MPI_CSBASE_REG(0));
	val &= MPI_CSBASE_BASE_MASK;
	boot_addr = (u8 *)KSEG1ADDR(val);

	if (!strcmp(str, "rescue")) {
#ifdef CONFIG_BOARD_NEUFBOX4
		board.leds[led_id_red].default_state =
		    LEDS_GPIO_DEFSTATE_OFF;
		board.leds[led_id_green].default_state =
		    LEDS_GPIO_DEFSTATE_OFF;
		board.leds[led_id_blue].default_state =
		    LEDS_GPIO_DEFSTATE_ON;
#endif
		tag = (void *)(boot_addr + NEUFBOX_RESCUEFIRMWARE_OFFSET);
	} else {		/* if (!strcmp(str, "main")) */
		str = "main";
		tag = (void *)(boot_addr + NEUFBOX_MAINFIRMWARE_OFFSET);
	}

	/* Get the values and calculate */
	sscanf(tag->kernelAddress, "%u", &kerneladdr);
	sscanf(tag->kernelLength, "%u", &kernellen);
	sscanf(tag->rootLength, "%u", &rootfslen);

	kerneladdr -= 0xbfc00000;
	rootfsaddr = kerneladdr + kernellen;
	rootfsaddr = ALIGN(rootfsaddr, 4);

	nb4_mtd_partitions[6].offset = rootfsaddr;
	nb4_mtd_partitions[6].size = rootfslen;
#endif

	printk(PFX "%s profile\n", str);
	return 0;
}
early_param("neufbox", neufbox_profile);
