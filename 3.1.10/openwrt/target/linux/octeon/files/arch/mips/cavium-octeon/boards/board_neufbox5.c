/*!
 * \file board.c
 *
 * \brief Implement neufbox board
 *
 * \author Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/ring_logs.h>
#include <linux/mtd/physmap.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/gpio_buttons.h>
#include <linux/irq.h>
#include <linux/timer.h>
#include <linux/gpio.h>
#include <linux/leds.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/74x164.h>

#include <cvmx-app-init.h>

#include <neufbox/events.h>
#include <neufbox/leds.h>
#include <nb5/board.h>
#include <nb5/partitions.h>

struct board {
	/* serialization data */
	char pid[32];
	u8 mac_address[6];
};

static struct board nb5;

u8 sfp_bitrate = 0u;
EXPORT_SYMBOL(sfp_bitrate);

#define GPIO_74X164_OFFSET 64
#define GPIO_74X164(X) (GPIO_74X164_OFFSET + (X))
#define GPIO_CPU_OFFSET 0
#define GPIO_CPU(X) (GPIO_CPU_OFFSET + (X))

static struct gen_74x164_platform_data nb5_gen_74x164_data = {
	.gpio_base = GPIO_74X164_OFFSET,
	.ngpio = 8,
	.gpio_pin_data = GPIO_CPU(3),
	.gpio_pin_clk =  GPIO_CPU(4),
};

static struct platform_device nb5_gen_74x16 = {
	.name = GEN_74X164_DRIVER_NAME,
	.id = -1,
	.dev = {
		.platform_data = &nb5_gen_74x164_data,
		}
};

static struct gpio_led nb5_leds_data_array[] = {
	{
	 .name = "wan",
	 .gpio = GPIO_74X164(0),
	 .active_low = 1,
	 },
	{
	 .name = "traffic",
	 .gpio = GPIO_74X164(1),
	 .active_low = 1,
	 },
	{
	 .name = "tel",
	 .gpio = GPIO_74X164(2),
	 .active_low = 1,
	 },
	{
	 .name = "tv",
	 .gpio = GPIO_74X164(3),
	 .active_low = 1,
	 },
	{
	 .name = "wifi",
	 .gpio = GPIO_74X164(4),
	 .active_low = 1,
	 },
	{
	 .name = "alarm",
	 .gpio = GPIO_74X164(5),
	 .active_low = 1,
	 },
	{
	 .name = "service:red",
	 .gpio = GPIO_CPU(0),
	 .active_low = 1,
	 },
	{
	 .name = "service:green",
	 .gpio = GPIO_CPU(1),
	 .active_low = 1,
	 },
	{
	 .name = "service:blue",
	 .gpio = GPIO_CPU(2),
	 .active_low = 1,
	 },
};

static struct gpio_led_platform_data nb5_leds_data = {
	.num_leds = ARRAY_SIZE(nb5_leds_data_array),
	.leds = nb5_leds_data_array,
};

static struct platform_device nb5_leds = {
	.name = "leds-neufbox",
	.id = -1,
	.dev = {
		.platform_data = &nb5_leds_data,
		}
};

static struct resource nb5_gpio_resources[] = {
	{
	 .start = ~0,
	 }
};

static struct gpio_button nb5_gpio_buttons_array[] = {
	{
	 .desc = "reset",
	 .type = EV_KEY,
	 .code = KEY_RESTART,
	 .threshold = 3,
	 .active_low = 1,
	 .gpio = 12,
	 },
	{
	 .desc = "wps",
	 .type = EV_KEY,
	 .code = KEY_WPS_BUTTON,
	 .threshold = 3,
	 .active_low = 1,
	 .active_low = 1,
	 .gpio = 11,
	 },
	{
	 .desc = "service",
	 .type = EV_KEY,
	 .code = BTN_0,
	 .threshold = 3,
	 .active_low = 1,
	 .gpio = 13,
	 },
};

static struct gpio_buttons_platform_data nb5_gpio_buttons_data = {
	.buttons = nb5_gpio_buttons_array,
	.nbuttons = ARRAY_SIZE(nb5_gpio_buttons_array),
	.poll_interval = 50,	/* 50 ms */
};

static struct platform_device nb5_gpio_buttons = {
	.name = "gpio-buttons",
	.id = -1,
	.dev = {
		.platform_data = &nb5_gpio_buttons_data,
		},
};

static struct platform_device nb5_gpio = {
	.name = "GPIODEV",
	.resource = nb5_gpio_resources,
	.num_resources = ARRAY_SIZE(nb5_gpio_resources),
};

#ifdef CONFIG_MTD_PARTITIONS
static struct mtd_partition nb5_mtd_partitions[] = {
	{
	 .name = "bootloader",
	 .offset = NEUFBOX_BOOTLOADER_OFFSET,
	 .size = NEUFBOX_BOOTLOADER_SIZE,
	 },
	{
	 .name = "uboot nvram",
	 .offset = NEUFBOX_UBOOTNVRAM_OFFSET,
	 .size = NEUFBOX_UBOOTNVRAM_SIZE,
	 },
	{
	 .name = "main firmware",
	 .offset = NEUFBOX_MAINFIRMWARE_OFFSET,
	 .size = NEUFBOX_MAINFIRMWARE_SIZE,
	 },
	{
	 .name = "rescue firmware",
	 .offset = NEUFBOX_RESCUEFIRMWARE_OFFSET,
	 .size = NEUFBOX_RESCUEFIRMWARE_SIZE,
	 },
	{
	 .name = "local data (jffs2)",
	 .offset = NEUFBOX_JFFS2_OFFSET,
	 .size = NEUFBOX_JFFS2_SIZE,
	 },
	{
	 .name = "Flash",
	 .offset = 0,
	 .size = NEUFBOX_FLASH_SIZE,
	 },
};
#endif

static struct physmap_flash_data nb5_flash_data = {
	.width = 2,
#ifdef CONFIG_MTD_PARTITIONS
	.parts = nb5_mtd_partitions,
	.nr_parts = ARRAY_SIZE(nb5_mtd_partitions)
#endif
};

static struct resource nb5_flash_resource = {
	.start = NEUFBOX_FLASH_BASE,
	.end = NEUFBOX_FLASH_BASE + NEUFBOX_FLASH_SIZE - 1,
	.flags = IORESOURCE_MEM,
};

static struct platform_device nb5_flash = {
	.name = "physmap-flash",
	.id = 0,
	.dev = {.platform_data = &nb5_flash_data,},
	.resource = &nb5_flash_resource,
	.num_resources = 1,
};

static struct ring_log_info nb5_ring_log_info[] = {
	{
	 .name = "daemon",
	 .size = 128 << 10,
	 },
	{
	 .name = "kern",
	 .size = 128 << 10,
	 },
	{
	 .name = "voip_proto",
	 .size = 128 << 10,
	 },
	{
	 .name = "voip",
	 .size = 128 << 10,
	 },
	{
	 .name = "messages",
	 .size = 128 << 10,
	 },
	{
	 .name = "syslog",
	 .size = 128 << 10,
	 },
	{
	 .name = "fastcgi",
	 .size = 128 << 10,
	 },
	{
	 .name = "voip_events",
	 .size = 128 << 10,
	 },
	{
	 .name = "hotspot",
	 .size = 128 << 10,
	 },
	{
	 .name = "lighttpd",
	 .size = 128 << 10,
	 },
};

static struct ring_log_platform_data nb5_ring_logs_data = {
	.num_ring_logs = ARRAY_SIZE(nb5_ring_log_info),
	.ring_logs = nb5_ring_log_info,
};

static struct platform_device nb5_ring_logs = {
	.name = "ring-logs",
	.id = -1,
	.dev = {.platform_data = &nb5_ring_logs_data,},
};

static struct platform_device nb5_neufbox_events = {
	.name = "neufbox-events",
	.id = -1,
	.dev = {},
};

void neufbox_pid(char *pid, size_t len)
{
	strncpy(pid, nb5.pid, len);
}

EXPORT_SYMBOL(neufbox_pid);

static int proc_read_mac_address_base(char *buf, char **start, off_t offset,
				      int count, int *eof, void *data)
{
	*eof = 1;
	return snprintf(buf, count, "%02X%02X%02X%02X%02X%02X\n",
			nb5.mac_address[0],
			nb5.mac_address[1],
			nb5.mac_address[2],
			nb5.mac_address[3],
			nb5.mac_address[4], nb5.mac_address[5]);
}

static int proc_read_productid(char *buf, char **start, off_t offset, int count,
			       int *eof, void *data)
{
	*eof = 1;
	return snprintf(buf, count, "%s\n", nb5.pid);
}

static int __init neufbox_profile(char *str)
{
	printk(KERN_INFO "load %s profile\n", str);
	if (!strcmp(str, "main")) {
		nb5_leds_data.leds[led_id_red].default_state = LEDS_GPIO_DEFSTATE_ON;
		nb5_leds_data.leds[led_id_green].default_state = LEDS_GPIO_DEFSTATE_ON;
		nb5_leds_data.leds[led_id_blue].default_state = LEDS_GPIO_DEFSTATE_OFF;
	} else if (!strcmp(str, "rescue")) {
		nb5_leds_data.leds[led_id_red].default_state = LEDS_GPIO_DEFSTATE_OFF;
		nb5_leds_data.leds[led_id_green].default_state = LEDS_GPIO_DEFSTATE_OFF;
		nb5_leds_data.leds[led_id_blue].default_state = LEDS_GPIO_DEFSTATE_ON;
	}
	return 0;
}

early_param("neufbox", neufbox_profile);

static int __init board_init(void)
{
	/* Load board profile from PID */
	extern cvmx_bootinfo_t *octeon_bootinfo;
	struct serialization *base =
	    CKSEG1ADDR(NEUFBOX_FLASH_BASE) + NEUFBOX_BOOTLOADER_SIZE -
	    sizeof(*base);

	snprintf(nb5.pid, sizeof(nb5.pid), "%s", base->pid);
	memcpy(nb5.mac_address, base->mac_address, sizeof(nb5.mac_address));

	/* Fill octeon info; sould be done in uboot */
	snprintf(octeon_bootinfo->board_serial_number,
		 sizeof(octeon_bootinfo->board_serial_number), "%s", nb5.pid);
	memcpy(octeon_bootinfo->mac_addr_base, nb5.mac_address,
	       sizeof(octeon_bootinfo->mac_addr_base));
	octeon_bootinfo->mac_addr_count = 4;

	platform_device_register(&nb5_gen_74x16);
	platform_device_register(&nb5_leds);
	platform_device_register(&nb5_gpio);
	platform_device_register(&nb5_gpio_buttons);
	platform_device_register(&nb5_flash);
	platform_device_register(&nb5_ring_logs);
	platform_device_register(&nb5_neufbox_events);

	if (create_proc_read_entry
	    ("mac_address_base", 0, NULL, proc_read_mac_address_base, NULL) < 0)
		printk("create /proc/%s endry failed\n", "mac_address_base");
	if (create_proc_read_entry
	    ("productid", 0, NULL, proc_read_productid, NULL) < 0)
		printk("create /proc/%s endry failed\n", "productid");

	return 0;
}

module_init(board_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Miguel GAIO <miguel.gaio@efixo.com>");
