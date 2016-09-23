/*!
 *      \file bcm54xx.c
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
#include <linux/device.h>
#include <linux/mii.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/gpio.h>

#include <linux/bcmphy.h>
#include <linux/bcm54xx.h>
#include "sfp.h"

#if defined (CONFIG_BOARD_NEUFBOX4) || defined(CONFIG_BOARD_NEUFBOX5)
#include <neufbox/events.h>
#endif

/*
 * Indirect register access functions for the 1000BASE-T/100BASE-TX/10BASE-T
 * 0x1c shadow registers.
 */
static int bcm54xx_shadow_read(struct bcmphy *phy, u16 shadow)
{
	int ret;

	spin_lock_bh(&phy->lock);
	bcmphy_write(phy, MII_BCM54XX_SHD, MII_BCM54XX_SHD_VAL(shadow));
	ret = MII_BCM54XX_SHD_DATA(bcmphy_read(phy, MII_BCM54XX_SHD));
	spin_unlock_bh(&phy->lock);

	return ret;
}

static int bcm54xx_shadow_write(struct bcmphy *phy, u16 shadow, u16 val)
{
	int ret;

	spin_lock_bh(&phy->lock);
	ret = bcmphy_write(phy, MII_BCM54XX_SHD,
			    MII_BCM54XX_SHD_WRITE |
			    MII_BCM54XX_SHD_VAL(shadow) |
			    MII_BCM54XX_SHD_DATA(val));
	spin_unlock_bh(&phy->lock);

	return ret;
}

#ifdef CONFIG_BOARD_NEUFBOX5
/* Indirect register access functions for the Expansion Registers */
#if 0
static int bcm54xx_exp_read(struct bcmphy *phy, u8 regnum)
{
	int val;

	val = bcmphy_write(phy, MII_BCM54XX_EXP_SEL, regnum);
	if (val < 0)
		return val;

	val = bcmphy_read(phy, MII_BCM54XX_EXP_DATA);

	/* Restore default value.  It's O.K. if this write fails. */
	bcmphy_write(phy, MII_BCM54XX_EXP_SEL, 0);

	return val;
}
#endif

static int bcm54xx_exp_write(struct bcmphy *phy, u16 regnum, u16 val)
{
	int ret;

	ret = bcmphy_write(phy, MII_BCM54XX_EXP_SEL, regnum);
	if (ret < 0)
		return ret;

	ret = bcmphy_write(phy, MII_BCM54XX_EXP_DATA, val);

	/* Restore default value.  It's O.K. if this write fails. */
	bcmphy_write(phy, MII_BCM54XX_EXP_SEL, 0);

	return ret;
}

static void bcm54xx_configure_fiber_100baseFX(struct bcmphy *phy)
{
	u16 val;

	/*! \note Fiber autodetect active low, select prior fiber */
	val = AUTODETECT_FIBER_AL | AUTODETECT_PRIORITY_FIBER;
	bcm54xx_shadow_write(phy, SHADOW_COPPER_FIBER_AUTODETECT, val);

	/*! \note Select copper 00h-0Fh registers */
	val = bcm54xx_shadow_read(phy, BCM5482_SHD_MODE);
	val &=
	    (~RESERVED_WRITE_CLEAR & ~MODE_SELECT_MASK &
	     ~BCM5482_SHD_MODE_1000BX);
	val |= (RESERVED_WRITE_SET | MODE_SELECT_FIBER);
	bcm54xx_shadow_write(phy, BCM5482_SHD_MODE, val);

	/*! \note Chip power down */
	val = bcmphy_read(phy, MII_BMCR);
	val |= BMCR_PDOWN;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \note Select fiber mode, 1000Base-X */
	val = bcm54xx_shadow_read(phy, BCM5482_SHD_MODE);
	val &= (~RESERVED_WRITE_CLEAR & ~MODE_SELECT_MASK);
	val |= (RESERVED_WRITE_SET | BCM5482_SHD_MODE_1000BX);
	bcm54xx_shadow_write(phy, BCM5482_SHD_MODE, val);

	/*! \note disable autoneg force 100FD */
	val = bcmphy_read(phy, MII_BMCR);
	val &= ~BMCR_ANENABLE;
	val |= BMCR_FULLDPLX | BMCR_SPEED100;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \note Chip power up */
	val = bcmphy_read(phy, MII_BMCR);
	val &= ~BMCR_PDOWN;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \note Select fiber mode */
	val = bcm54xx_shadow_read(phy, BCM5482_SHD_MODE);
	val &= (~RESERVED_WRITE_CLEAR & ~MODE_SELECT_MASK);
	val |= (RESERVED_WRITE_SET | MODE_SELECT_FIBER);
	bcm54xx_shadow_write(phy, BCM5482_SHD_MODE, val);

	/*! \note Set TXD loopback */
	val = bcmphy_read(phy, MII_BMCR);
	val |= BMCR_LOOPBACK;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \note SerDes enable */
	val = bcm54xx_shadow_read(phy, SHADOW_SERDES_CONTROL);
	val |= (SERDES_ENABLE);
	bcm54xx_shadow_write(phy, SHADOW_SERDES_CONTROL, val);

	/*! \note Expansion 50h == 0C3Bh
	 *  \todo add docs
	 */
	bcm54xx_exp_write(phy, 0x50 | MII_BCM54XX_EXP_SEL_ER, 0x0c3b);

	/*! \note Expansion 50h == 0x0C3Ah
	 *  \todo add docs
	 */
	bcm54xx_exp_write(phy, 0x50 | MII_BCM54XX_EXP_SEL_ER, 0x0c3a);

	/*! \note Reset TXD loopback */
	val = bcmphy_read(phy, MII_BMCR);
	val &= ~BMCR_LOOPBACK;
	bcmphy_write(phy, MII_BMCR, val);

	udelay(1000);

	/*! \note SerDes status */
	bcm54xx_shadow_read(phy, SHADOW_SERDES_STATUS);
}

static void bcm54xx_configure_fiber_1000baseX(struct bcmphy *phy)
{
	u16 val;

	/*! \note Fiber autodetect active low, select prior fiber */
	val = AUTODETECT_FIBER_AL | AUTODETECT_PRIORITY_FIBER;
	bcm54xx_shadow_write(phy, SHADOW_COPPER_FIBER_AUTODETECT, val);

	/*! \note Mode select fiber */
	val = bcm54xx_shadow_read(phy, BCM5482_SHD_MODE);
	val &= (~RESERVED_WRITE_CLEAR & ~MODE_SELECT_MASK);
	val |= (RESERVED_WRITE_SET | MODE_SELECT_FIBER);
	bcm54xx_shadow_write(phy, BCM5482_SHD_MODE, val);

	/*! \note Chip power down */
	val = bcmphy_read(phy, MII_BMCR);
	val |= BMCR_PDOWN;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \note Mode select fiber */
	val = bcm54xx_shadow_read(phy, BCM5482_SHD_MODE);
	val &= (~RESERVED_WRITE_CLEAR & ~MODE_SELECT_MASK);
	val |= (RESERVED_WRITE_SET | MODE_SELECT_FIBER);
	bcm54xx_shadow_write(phy, BCM5482_SHD_MODE, val);

	/*! \note Select 1000BASE-X registers for addresses 00h–0Fh */
	val = bcm54xx_shadow_read(phy, BCM5482_SHD_MODE);
	val &= (~RESERVED_WRITE_CLEAR);
	val |= (RESERVED_WRITE_SET | BCM5482_SHD_MODE_1000BX);
	bcm54xx_shadow_write(phy, BCM5482_SHD_MODE, val);

	/*! \note Link disbale autoneg force 1000FD */
	val = bcmphy_read(phy, MII_BMCR);
	val &= ~BMCR_ANENABLE;
	val |= BMCR_FULLDPLX | BMCR_SPEED1000;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \note Chip power up */
	val = bcmphy_read(phy, MII_BMCR);
	val &= ~BMCR_PDOWN;
	bcmphy_write(phy, MII_BMCR, val);

	/*! \todo add docs RGMII timing delay */
	bcmphy_write(phy, MII_RESV4, 0xf0e7);
	bcmphy_write(phy, MII_NCONFIG, 0x8c00);
}

void bcm54xx_media_check(struct bcmphy *phy)
{
	u8 new_sfp_bitrate = sfp_eeprom_bitrate();

	extern u8 sfp_bitrate;

	if (!sfp_Rx_ok())
		new_sfp_bitrate = 0u;

	if (new_sfp_bitrate != sfp_bitrate) {
		sfp_bitrate = new_sfp_bitrate;

#define EVENT_DOWN	(event_id_eth0_down)
#define EVENT_UP(S,D) ((event_id_eth0_up)|((S|(D))<<8))
		if (sfp_bitrate == 0u) {
			sfp_Tx_disable();
			bcmphy_print_status("bcm54xx/0", 0, 0, 0);
			event_enqueue(EVENT_DOWN);
		} else if (sfp_bitrate < 5u) {
			sfp_Tx_enable();
			bcm54xx_configure_fiber_100baseFX(phy);
			bcmphy_print_status("bcm54xx/0", 1, 100, 1);
			event_enqueue(EVENT_UP(100, 1));
		} else if (sfp_bitrate < 15u) {
			sfp_Tx_enable();
			bcm54xx_configure_fiber_1000baseX(phy);
			bcmphy_print_status("bcm54xx/0", 1, 1000, 1);
			event_enqueue(EVENT_UP(1000, 1));
		}
#undef EVENT_DOWN
#undef EVENT_UP

	}
}

EXPORT_SYMBOL(bcm54xx_media_check);
#endif

int bcm54xx_ioctl(struct bcmphy *phy, struct ifreq *rq, int cmd)
{
	struct mii_ioctl_data *mii_data = if_mii(rq);

	if (cmd == SIOCGGPHYSHADOWREGS)
		mii_data->val_out = bcm54xx_shadow_read(phy, mii_data->reg_num);
	else if (cmd == SIOCSGPHYSHADOWREGS)
		bcm54xx_shadow_write(phy, mii_data->reg_num, mii_data->val_in);
	else
		return -EOPNOTSUPP;

	return 0;
}

EXPORT_SYMBOL(bcm54xx_ioctl);

int bcm54xx_probe(struct bcmphy *phy)
{
	uint32_t phyid;
#ifdef CONFIG_BOARD_NEUFBOX5
	uint64_t val;
	int i;

	for (i = 4; i <= 7; i++)
		cvmx_write_csr(CVMX_MIO_BOOT_REG_CFGX(i),
			       cvmx_read_csr(CVMX_MIO_BOOT_REG_CFGX(i))
			       & (~1 << 31));

	val = cvmx_read_csr(CVMX_GPIO_BOOT_ENA);
	val &= 0xfffffffffffff0ff;
	cvmx_write_csr(CVMX_GPIO_BOOT_ENA, val);

	if (gpio_request(GPHY_CHIP_RESET_GPIO, "GPHY") < 0) {
		printk("%s: gpio_request failed for %u\n", "Broadcom 5482 PHY", GPHY_CHIP_RESET_GPIO);
		return -EINVAL;
	}
	gpio_direction_output(GPHY_CHIP_RESET_GPIO, 0);
	gpio_set_value(GPHY_CHIP_RESET_GPIO, 0);
	udelay(1000);
	gpio_set_value(GPHY_CHIP_RESET_GPIO, 1);
#endif

	spin_lock_init(&phy->lock);

	phyid =
	    (bcmphy_read(phy, MII_PHYSID1) << 16) |
	    (bcmphy_read(phy, MII_PHYSID2) << 0);

	if ((phyid & 0xfffffff0) != PHY_ID_BCM5482)
		return -EIO;

	printk("Registered Broadcom 5482 PHY\n");

	return 0;
}

EXPORT_SYMBOL(bcm54xx_probe);

MODULE_AUTHOR("Miguel Gaio <miguel.gaio@efixo.com>");
MODULE_LICENSE("GPL v2");
