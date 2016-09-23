/*
 * Realtek RTL8367 SMI interface driver defines
 *
 * Copyright (C) 2009-2010 Gabor Juhos <juhosg@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#ifndef _RTL8367_SMI_H
#define _RTL8367_SMI_H

struct rtl8367_smi {
	struct device		*parent;
	unsigned int		gpio_sda;
	unsigned int		gpio_sck;
	spinlock_t		lock;
#if 0
	unsigned int		low_speed_clock:1;
#endif
};

int rtl8367_smi_init(struct rtl8367_smi *smi);
void rtl8367_smi_cleanup(struct rtl8367_smi *smi);
int rtl8367_smi_write_reg(struct rtl8367_smi *smi, u32 addr, u32 data);
int rtl8367_smi_read_reg(struct rtl8367_smi *smi, u32 addr, u32 *data);

#endif /*  _RTL8367_SMI_H */
