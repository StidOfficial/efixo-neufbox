/*!
 *      \file bcm53xx.c
 *
 *      \author Copyright 2009 Miguel GAIO <miguel.gaio@efixo.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mii.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/delay.h>

#include <linux/bcmphy.h>
#include <linux/bcm53xx.h>

#include <neufbox/events.h>

static void bcm53xx_reg_commit(struct bcmphy *phy, unsigned page, unsigned reg,
			       int write)
{
	int i;
	u16 v;

	/* set page number */
	v = (page << ROBO_MII_PAGE_SHIFT) | ROBO_MII_PAGE_ENABLE;
	bcmphy_write(phy, ROBO_MII_PAGE, v);

	/* set register address */
	if (write)
		v = (reg << ROBO_MII_ADDR_SHIFT) | ROBO_MII_ADDR_WRITE;
	else
		v = (reg << ROBO_MII_ADDR_SHIFT) | ROBO_MII_ADDR_READ;
	bcmphy_write(phy, ROBO_MII_ADDR, v);

	/* check if operation completed */
	for (i = 0; i < 5; ++i) {
		v = bcmphy_read(phy, ROBO_MII_ADDR);
		if (!(v & (ROBO_MII_ADDR_WRITE | ROBO_MII_ADDR_READ)))
			break;
		udelay(10);
	}

	if (i == 5) {
		pr_err("%s(%02x, %02x) %s\n", __func__, page, reg, "timeout");
		return;
	}
}

static void bcm53xx_reg_read(struct bcmphy *phy, unsigned page, unsigned reg,
			     unsigned len, union bcm53xx_reg_union *u)
{
	spin_lock_bh(&phy->lock);

	bcm53xx_reg_commit(phy, page, reg, 0);

	switch (len) {
	case 1:
		pr_debug("%s(%x, %x, %d, %04x)\n", __func__, page, reg, len,
			 u->raw[0]);
		u->raw[0] = bcmphy_read(phy, ROBO_MII_DATA0 + 0);	/* 15:00 */
		break;
	case 2:
		pr_debug("%s(%x, %x, %d, %04x)\n", __func__, page, reg, len,
			 u->raw[0]);
		u->raw[0] = bcmphy_read(phy, ROBO_MII_DATA0 + 0);	/* 15:00 */
		break;
	case 4:
		pr_debug("%s(%x, %x, %d, %04x%04x)\n", __func__, page, reg, len,
			 u->raw[1], u->raw[0]);
		u->raw[1] = bcmphy_read(phy, ROBO_MII_DATA0 + 0);	/* 15:00 */
		u->raw[0] = bcmphy_read(phy, ROBO_MII_DATA0 + 1);	/* 31:16 */
		break;
	case 6:
		pr_debug("%s(%x, %x, %d, %04x%04x%04x)\n", __func__, page, reg,
			 len, u->raw[2], u->raw[1], u->raw[0]);
		u->raw[2] = bcmphy_read(phy, ROBO_MII_DATA0 + 0);	/* 15:00 */
		u->raw[1] = bcmphy_read(phy, ROBO_MII_DATA0 + 1);	/* 31:16 */
		u->raw[0] = bcmphy_read(phy, ROBO_MII_DATA0 + 2);	/* 47:32 */
		break;
	case 8:
		pr_debug("%s(%x, %x, %d, %04x%04x%04x%04x)\n", __func__, page,
			 reg, len, u->raw[3], u->raw[2], u->raw[1], u->raw[0]);
		u->raw[3] = bcmphy_read(phy, ROBO_MII_DATA0 + 0);	/* 15:00 */
		u->raw[2] = bcmphy_read(phy, ROBO_MII_DATA0 + 1);	/* 31:16 */
		u->raw[1] = bcmphy_read(phy, ROBO_MII_DATA0 + 2);	/* 47:32 */
		u->raw[0] = bcmphy_read(phy, ROBO_MII_DATA0 + 3);	/* 63:48 */
		break;
	default:
		pr_err("%s: [%02x:%02x:%d] %s\n", __func__, page, reg, len,
		       "invalid length");
		break;
	}

	spin_unlock_bh(&phy->lock);
}

static void bcm53xx_reg_write(struct bcmphy *phy, unsigned page, unsigned reg,
			      unsigned len, union bcm53xx_reg_union *u)
{
	spin_lock_bh(&phy->lock);

	switch (len) {
	case 1:
		pr_debug("%s(%x, %x, %d, %04x)\n", __func__, page, reg, len,
			 u->raw[0]);
		bcmphy_write(phy, ROBO_MII_DATA0 + 0, u->raw[0]);	/* 15:00 */
		break;
	case 2:
		pr_debug("%s(%x, %x, %d, %04x)\n", __func__, page, reg, len,
			 u->raw[0]);
		bcmphy_write(phy, ROBO_MII_DATA0 + 0, u->raw[0]);	/* 15:00 */
		break;
	case 4:
		pr_debug("%s(%x, %x, %d, %04x%04x)\n", __func__, page, reg, len,
			 u->raw[1], u->raw[0]);
		bcmphy_write(phy, ROBO_MII_DATA0 + 0, u->raw[1]);	/* 15:00 */
		bcmphy_write(phy, ROBO_MII_DATA0 + 1, u->raw[0]);	/* 31:16 */
		break;
	case 6:
		pr_debug("%s(%x, %x, %d, %04x%04x%04x)\n", __func__, page, reg,
			 len, u->raw[2], u->raw[1], u->raw[0]);
		bcmphy_write(phy, ROBO_MII_DATA0 + 0, u->raw[2]);	/* 15:00 */
		bcmphy_write(phy, ROBO_MII_DATA0 + 1, u->raw[1]);	/* 31:16 */
		bcmphy_write(phy, ROBO_MII_DATA0 + 2, u->raw[0]);	/* 47:32 */
		break;
	case 8:
		pr_debug("%s(%x, %x, %d, %04x%04x%04x%04X)\n", __func__, page,
			 reg, len, u->raw[3], u->raw[2], u->raw[1], u->raw[0]);
		bcmphy_write(phy, ROBO_MII_DATA0 + 0, u->raw[3]);	/* 15:00 */
		bcmphy_write(phy, ROBO_MII_DATA0 + 1, u->raw[2]);	/* 31:16 */
		bcmphy_write(phy, ROBO_MII_DATA0 + 2, u->raw[1]);	/* 47:32 */
		bcmphy_write(phy, ROBO_MII_DATA0 + 3, u->raw[0]);	/* 62:48 */
		break;
	default:
		pr_err("%s: [%02x:%02x:%d] %s\n", __func__, page, reg, len,
		       "invalid length");
		break;
	}

	bcm53xx_reg_commit(phy, page, reg, 1);

	spin_unlock_bh(&phy->lock);
}

static u16 bcm53xx_r16(struct bcmphy *phy, unsigned page, unsigned reg)
{
	union bcm53xx_reg_union u;

	bcm53xx_reg_read(phy, page, reg, sizeof(u16), &u);

	return u.u16;
}

static u32 bcm53xx_r32(struct bcmphy *phy, unsigned page, unsigned reg)
{
	union bcm53xx_reg_union u;

	bcm53xx_reg_read(phy, page, reg, sizeof(u32), &u);

	return u.u32;
}

#if 0
static void bcm53xx_w16(struct bcmphy *phy, unsigned page, unsigned reg, u16 v)
{
	union bcm53xx_reg_union u = {.u16 = v };

	bcm53xx_reg_write(phy, page, reg, sizeof(u16), &u);
}

static void bcm53xx_w32(struct bcmphy *phy, unsigned page, unsigned reg, u32 v)
{
	union bcm53xx_reg_union u = {.u32 = v };

	bcm53xx_reg_write(phy, page, reg, sizeof(u32), &u);
}
#endif

int bcm53xx_ioctl(struct bcmphy *phy, struct ifreq *rq, int cmd)
{
	struct bcm53xx_ioctl_data bcm;

	if (cmd == SIOCGROBOREGS) {
		if (copy_from_user(&bcm, rq->ifr_data, sizeof(bcm)) < 0)
			return -EFAULT;
		bcm53xx_reg_read(phy, bcm.page, bcm.reg, bcm.len, &bcm.u);
		__copy_to_user(rq->ifr_data, &bcm, sizeof(bcm));
	} else if (cmd == SIOCSROBOREGS) {
		if (copy_from_user(&bcm, rq->ifr_data, sizeof(bcm)) < 0)
			return -EFAULT;
		bcm53xx_reg_write(phy, bcm.page, bcm.reg, bcm.len, &bcm.u);
		__copy_to_user(rq->ifr_data, &bcm, sizeof(bcm));
	} else
		return -EOPNOTSUPP;
	return 0;
}

EXPORT_SYMBOL(bcm53xx_ioctl);

static unsigned bcm53xx_media_speed(unsigned v)
{
	if (v == 0x2)
		return SPEED_1000;
	else if (v == 0x1)
		return SPEED_100;
	else
		return SPEED_10;
}

void bcm53xx_media_check(struct bcmphy *phy)
{
	/* Not reliable at ALL */
#if 0
	u16 changed;
#else
	static u16 changed = 0u;
#endif
	u16 link;
	u32 speed = 0u;
	u16 duplex = 0u;
	unsigned i;

	/* Not reliable at ALL */
#if 0
	changed = bcm53xx_r16(phy, PAGE_STATUS, ROBO_LINK_STATUS_CHANGE);
	if (!changed)
		return;
#else
	link = bcm53xx_r16(phy, PAGE_STATUS, ROBO_LINK_STATUS);
	if (link == changed)
		return;

	changed ^= link;
#endif

	if (phy->dev_id == 0x25) {
		speed = bcm53xx_r16(phy, PAGE_STATUS, ROBO_PORT_SPEED_SUMMARY);
		duplex = bcm53xx_r16(phy, PAGE_STATUS,
				     ROBO_5325_DUPLEX_STATUS_SUMMARY);
	} else if (phy->dev_id == 0x95) {
		speed = bcm53xx_r32(phy, PAGE_STATUS, ROBO_PORT_SPEED_SUMMARY);
		duplex = bcm53xx_r16(phy, PAGE_STATUS,
				     ROBO_5395_DUPLEX_STATUS_SUMMARY);
	}

	for (i = 0; i < phy->ports_count; ++i) {
		char ifname[sizeof("bcm53xx/i")];
		unsigned mask = (1 << i);
		u16 _changed = ! !(changed & mask);
		u16 _duplex = ! !(duplex & mask);
		u16 _link = ! !(link & mask);
		u32 _speed = 0u;

		if (!_changed)
			continue;

		if (_link) {
			if (phy->dev_id == 0x25) {
				_speed = (speed >> i);
				_speed = bcm53xx_media_speed(_speed & 0x1);
			} else if (phy->dev_id == 0x95) {
				_speed = (speed >> (i << 1));
				_speed = bcm53xx_media_speed(_speed & 0x3);
			}
#define EVENT_UP(P,S,D) ((event_id_port0_up + (2*(P)))|((S|(D))<<8))
			event_enqueue(EVENT_UP(i, _speed, _duplex));
		} else {
#define EVENT_DOWN(P)	(event_id_port0_down + (2*(P)))
			event_enqueue(EVENT_DOWN(i));
		}
		snprintf(ifname, sizeof(ifname), "bcm53xx/%d", i);
		bcmphy_print_status(ifname, _link, _speed, _duplex);
	}
	changed = link;
}

EXPORT_SYMBOL(bcm53xx_media_check);

int bcm53xx_probe(struct bcmphy *phy)
{
	unsigned id;

	if ((!phy->read) || (!phy->write)) {
		printk("%s failed\n", __func__);
		return -EINVAL;
	}

	spin_lock_init(&phy->lock);
	id = bcm53xx_r16(phy, PAGE_MANAGEMENT, ROBO_DEV_ID);
	printk("bcm53%02x detected(%02x)\n", phy->dev_id, id);

	return 0;
}

EXPORT_SYMBOL(bcm53xx_probe);

MODULE_AUTHOR("Miguel Gaio <miguel.gaio@efixo.com>");
MODULE_LICENSE("GPL v2");
