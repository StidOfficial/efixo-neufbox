/*
 * robo-switch.c: Broadcom Robo switch interface
 *
 * Copyright (C) 2010 Miguel Gaio <miguel.gaio@efixo.com>
 * Copyright (C) 2005 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2008 Michael Buesch <mb@bu3sch.de>
 * Based on 'robocfg' by Oleg I. Vdovikin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/phy.h>
#include <linux/spi/spi.h>

#include "robo-switch.h"
#include "etc53xx.h"


#define BCMROBO_DRIVER_DESC	"Broadcom Robo switch interface"

/* MII registers */
#define REG_MII_PAGE    0x10    /* MII Page register */
#define REG_MII_ADDR    0x11    /* MII Address register */
#define REG_MII_DATA0   0x18    /* MII Data register 0 */

#define REG_MII_PAGE_ENABLE     1
#define REG_MII_ADDR_WRITE      1
#define REG_MII_ADDR_READ       2


/* MII bus */

static void robo_phy_commit(struct phy_device *phydev, u16 page, u16 reg, u16 op)
{
	int i;
	u16 v;

	/* set page number */
	v = (page << 8) | REG_MII_PAGE_ENABLE;
	phy_write(phydev, REG_MII_PAGE, v);

	/* set register address */
	v = (reg << 8) | op;
	phy_write(phydev, REG_MII_ADDR, v);

	/* check if operation completed */
	for (i = 0; i < 5; ++i) {
		v = phy_read(phydev, REG_MII_ADDR);
		if (!(v & (REG_MII_ADDR_WRITE | REG_MII_ADDR_READ)))
			break;
		udelay(10);
	}

	if (i == 5) {
		dev_err(&phydev->dev, "I/O page:%u reg:%u timeout\n", page,
				reg);
		return;
	}
}

u16 robo_phy_r16(struct phy_device *phydev, u16 page, u16 reg)
{
	u16 v;

	robo_phy_commit(phydev, page, reg, REG_MII_ADDR_READ);
	v = phy_read(phydev, REG_MII_DATA0);
	return v;
}
EXPORT_SYMBOL_GPL(robo_phy_r16);

static u32 robo_phy_r32(struct phy_device *phydev, u16 page, u16 reg)
{
	u32 v;

	robo_phy_commit(phydev, page, reg, REG_MII_ADDR_READ);
	v = (phy_read(phydev, REG_MII_DATA0) & 0xffff)
		| (phy_read(phydev, REG_MII_DATA0 + 1) << 16);
	return v;
}

static void robo_phy_w16(struct phy_device *phydev, u16 page, u16 reg, u16 v)
{
	phy_write(phydev, REG_MII_DATA0, v);
	robo_phy_commit(phydev, page, reg, REG_MII_ADDR_WRITE);
}

static void robo_phy_w32(struct phy_device *phydev, u16 page, u16 reg, u32 v)
{
	phy_write(phydev, REG_MII_DATA0, v & 0xffff);
	phy_write(phydev, REG_MII_DATA0 + 1, v >> 16);
	robo_phy_commit(phydev, page, reg, REG_MII_ADDR_WRITE);
}

/* Robo registers access */

u16 robo_r16(struct robo *robo, u16 page, u16 reg)
{
	struct device *dev = robo->parent;

	if (dev->bus == &mdio_bus_type) {
		return robo_phy_r16(to_phy_device(dev), page, reg);
	} else {
		BUG();
	}
}
EXPORT_SYMBOL_GPL(robo_r16);

u32 robo_r32(struct robo *robo, u16 page, u16 reg)
{
	struct device *dev = robo->parent;

	if (dev->bus == &mdio_bus_type) {
		return robo_phy_r32(to_phy_device(dev), page, reg);
	} else {
		BUG();
	}
}
EXPORT_SYMBOL_GPL(robo_r32);


void robo_w16(struct robo *robo, u16 page, u16 reg, u16 v)
{
	struct device *dev = robo->parent;

	if (dev->bus == &mdio_bus_type) {
		robo_phy_w16(to_phy_device(dev), page, reg, v);
	} else {
		BUG();
	}
}
EXPORT_SYMBOL_GPL(robo_w16);

void robo_w32(struct robo *robo, u16 page, u16 reg, u32 v)
{
	struct device *dev = robo->parent;

	if (dev->bus == &mdio_bus_type) {
		robo_phy_w32(to_phy_device(dev), page, reg, v);
	} else {
		BUG();
	}
}
EXPORT_SYMBOL_GPL(robo_w32);

/* SPI device: Robo MII bus */

#ifdef CONFIG_SPI
static int robo_read_phy_reg(struct robo *robo, int addr, u32 reg)
{
	struct switch_dev *sw_dev = &robo->sw_dev;
	int ret;

	if (addr > sw_dev->ports) {
		return 0xffff;
	}

	ret = robo_r16(robo, ROBO_PORT0_MII_PAGE + addr, reg << 1);
	return ret;
}

static int robo_write_phy_reg(struct robo *robo, int addr, int reg, u16 val)
{
	struct switch_dev *sw_dev = &robo->sw_dev;

	if (addr > sw_dev->ports) {
		return -EINVAL;
	}

	robo_w16(robo, ROBO_PORT0_MII_PAGE + addr, reg << 1, val);
	return 0;
}

static int robo_mii_read(struct mii_bus *bus, int addr, int reg)
{
	return robo_read_phy_reg(bus->priv, addr, reg);
}

static int robo_mii_write(struct mii_bus *bus, int addr, int reg, u16 val)
{
	return robo_write_phy_reg(bus->priv, addr, reg, val);
}

int robo_mii_bus_match(struct mii_bus *bus)
{
	return (bus->read == robo_mii_read &&
			bus->write == robo_mii_write);
}
EXPORT_SYMBOL_GPL(robo_mii_bus_match);

static int robo_mii_init(struct robo *robo)
{
	struct mii_bus *bus;
	struct switch_dev *sw_dev = &robo->sw_dev;
	int err;

	bus = mdiobus_alloc();
	if (bus == NULL) {
		err = -ENOMEM;
		goto err_out;
	}

	robo->mii_bus = bus;
	bus->priv = robo;
	bus->name = sw_dev->devname;
	bus->read = robo_mii_read;
	bus->write = robo_mii_write;
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s", sw_dev->devname);
	bus->phy_mask = ~((1 << sw_dev->ports) - 1);

	err = mdiobus_register(bus);
	if (err)
		goto err_free;

	return 0;

err_free:
	mdiobus_free(robo->mii_bus);
err_out:
	return err;
}

static void robo_mii_cleanup(struct mii_bus *bus)
{
	mdiobus_unregister(bus);
	mdiobus_free(bus);
}
#endif

/* Robo */

int robo_init(struct robo *robo)
{
	int err = 0;
#ifdef CONFIG_SPI
	struct device *dev = robo->parent;

	if (dev->bus == &spi_bus_type)
		err = robo_mii_init(robo);
#endif
	return err;
}
EXPORT_SYMBOL_GPL(robo_init);

void robo_cleanup(struct robo *robo)
{
#ifdef CONFIG_SPI
	struct device *dev = robo->parent;

	if (dev->bus == &spi_bus_type)
		robo_mii_cleanup(robo->mii_bus);
#endif
}
EXPORT_SYMBOL_GPL(robo_cleanup);

MODULE_DESCRIPTION(BCMROBO_DRIVER_DESC);
MODULE_LICENSE("GPL v2");
