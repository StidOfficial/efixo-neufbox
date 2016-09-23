/*
 * Platform data definition for the Realtek RTL8367R ethernet switch driver
 *
 * Copyright (C) 2009-2010 Gabor Juhos <juhosg@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#ifndef _RTL8367R_H
#define _RTL8367R_H

#define RTL8367R_DRIVER_NAME	"rtl8367r"

struct rtl8367r_platform_data {
	unsigned	gpio_sda;
	unsigned	gpio_sck;
	unsigned	irq;
};

#endif
