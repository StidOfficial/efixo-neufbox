/*
 * bcmrobo.h: Broadcom Robo switch interface
 *
 * Copyright (C) 2010 Miguel Gaio <miguel.gaio@efixo.com>
 * Copyright (C) 2005 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2008 Michael Buesch <mb@bu3sch.de>
 * Based on 'robocfg' by Oleg I. Vdovikin
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#ifndef __ROBO_SWITCH_H_
#define __ROBO_SWITCH_H_

#include <linux/kernel.h>
#include <linux/switch.h>


struct phy_device;
struct mii_bus;

struct robo {
	struct device		*parent;

	struct switch_dev	sw_dev;

#ifdef CONFIG_SPI
	struct mii_bus		*mii_bus;
#endif

	char			buf[4096];
};

static inline struct robo *sw_to_robo(struct switch_dev *dev)
{
	return container_of(dev, struct robo, sw_dev);
}

u16 robo_phy_r16(struct phy_device *, u16, u16);

u16 robo_r16(struct robo *, u16, u16);
u32 robo_r32(struct robo *, u16, u16);
void robo_w16(struct robo *, u16, u16, u16);
void robo_w32(struct robo *, u16, u16, u32);

int robo_mii_bus_match(struct mii_bus *);
int robo_init(struct robo *);
void robo_cleanup(struct robo *);


#endif
