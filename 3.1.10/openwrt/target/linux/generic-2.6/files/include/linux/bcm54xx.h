/*!
 * \file broadcom-5482s-gphy.h
 *
 * \brief Define broadcom 5482S gphy register
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
 * 
 */

#ifndef _BROADCOM_54XX_GPHY_H_
#define _BROADCOM_54XX_GPHY_H_

#define GPHY_CHIP_RESET_GPIO	9

#include <linux/types.h>

#ifdef __KERNEL__

#include <linux/bcmphy.h>
#include <linux/if.h>

struct bcphy;

int bcm54xx_probe(struct bcmphy *);
int bcm54xx_ioctl(struct bcmphy *, struct ifreq *, int);
void bcm54xx_media_check(struct bcmphy *);

#else
#include <linux/sockios.h>
#endif				/* __KERNEL__ */

enum {
	SIOCGGPHYSHADOWREGS = SIOCDEVPRIVATE + 1,
	SIOCSGPHYSHADOWREGS
};

#define PHY_ID_BCM5482		0x0143bcb0

#define MII_BCM54XX_ECR		0x10	/* BCM54xx extended control register */
#define MII_BCM54XX_ECR_IM	0x1000	/* Interrupt mask */
#define MII_BCM54XX_ECR_IF	0x0800	/* Interrupt force */

#define MII_BCM54XX_ESR		0x11	/* BCM54xx extended status register */
#define MII_BCM54XX_ESR_IS	0x1000	/* Interrupt status */

#define MII_BCM54XX_EXP_DATA	0x15	/* Expansion register data */
#define MII_BCM54XX_EXP_SEL	0x17	/* Expansion register select */
#define MII_BCM54XX_EXP_SEL_SSD	0x0e00	/* Secondary SerDes select */
#define MII_BCM54XX_EXP_SEL_ER	0x0f00	/* Expansion register select */

#define MII_BCM54XX_AUX_CTL	0x18	/* Auxiliary control register */
#define MII_BCM54XX_ISR		0x1a	/* BCM54xx interrupt status register */
#define MII_BCM54XX_IMR		0x1b	/* BCM54xx interrupt mask register */
#define MII_BCM54XX_INT_CRCERR	0x0001	/* CRC error */
#define MII_BCM54XX_INT_LINK	0x0002	/* Link status changed */
#define MII_BCM54XX_INT_SPEED	0x0004	/* Link speed change */
#define MII_BCM54XX_INT_DUPLEX	0x0008	/* Duplex mode changed */
#define MII_BCM54XX_INT_LRS	0x0010	/* Local receiver status changed */
#define MII_BCM54XX_INT_RRS	0x0020	/* Remote receiver status changed */
#define MII_BCM54XX_INT_SSERR	0x0040	/* Scrambler synchronization error */
#define MII_BCM54XX_INT_UHCD	0x0080	/* Unsupported HCD negotiated */
#define MII_BCM54XX_INT_NHCD	0x0100	/* No HCD */
#define MII_BCM54XX_INT_NHCDL	0x0200	/* No HCD link */
#define MII_BCM54XX_INT_ANPR	0x0400	/* Auto-negotiation page received */
#define MII_BCM54XX_INT_LC	0x0800	/* All counters below 128 */
#define MII_BCM54XX_INT_HC	0x1000	/* Counter above 32768 */
#define MII_BCM54XX_INT_MDIX	0x2000	/* MDIX status change */
#define MII_BCM54XX_INT_PSERR	0x4000	/* Pair swap error */

#define MII_BCM54XX_SHD		0x1c	/* 0x1c shadow registers */
#define MII_BCM54XX_SHD_WRITE	0x8000
#define MII_BCM54XX_SHD_VAL(x)	((x & 0x1f) << 10)
#define MII_BCM54XX_SHD_DATA(x)	((x & 0x3ff) << 0)

/*
 * AUXILIARY CONTROL SHADOW ACCESS REGISTERS.  (PHY REG 0x18)
 */
#define MII_BCM54XX_AUXCTL_SHDWSEL_AUXCTL	0x0000
#define MII_BCM54XX_AUXCTL_ACTL_TX_6DB		0x0400
#define MII_BCM54XX_AUXCTL_ACTL_SMDSP_ENA	0x0800

#define MII_BCM54XX_AUXCTL_MISC_WREN	0x8000
#define MII_BCM54XX_AUXCTL_MISC_FORCE_AMDIX	0x0200
#define MII_BCM54XX_AUXCTL_MISC_RDSEL_MISC	0x7000
#define MII_BCM54XX_AUXCTL_SHDWSEL_MISC	0x0007

/*
 * Broadcom LED source encodings.  These are used in BCM5461, BCM5481,
 * BCM5482, and possibly some others.
 */
#define BCM_LED_SRC_LINKSPD1	0x0
#define BCM_LED_SRC_LINKSPD2	0x1
#define BCM_LED_SRC_XMITLED	0x2
#define BCM_LED_SRC_ACTIVITYLED	0x3
#define BCM_LED_SRC_FDXLED	0x4
#define BCM_LED_SRC_SLAVE	0x5
#define BCM_LED_SRC_INTR	0x6
#define BCM_LED_SRC_QUALITY	0x7
#define BCM_LED_SRC_RCVLED	0x8
#define BCM_LED_SRC_MULTICOLOR1	0xa
#define BCM_LED_SRC_OPENSHORT	0xb
#define BCM_LED_SRC_OFF		0xe	/* Tied high */
#define BCM_LED_SRC_ON		0xf	/* Tied low */

/*
 * BCM5482: Shadow registers
 * Shadow values go into bits [14:10] of register 0x1c to select a shadow
 * register to access.
 */
#define BCM5482_SHD_LEDS1	0x0d	/* 01101: LED Selector 1 */
					/* LED3 / ~LINKSPD[2] selector */
#define BCM5482_SHD_LEDS1_LED3(src)	((src & 0xf) << 4)
					/* LED1 / ~LINKSPD[1] selector */
#define BCM5482_SHD_LEDS1_LED1(src)	((src & 0xf) << 0)
#define BCM5482_SHD_SSD		0x14	/* 10100: Secondary SerDes control */
#define BCM5482_SHD_SSD_LEDM	0x0008	/* SSD LED Mode enable */
#define BCM5482_SHD_SSD_EN	0x0001	/* SSD enable */
#define BCM5482_SHD_MODE	0x1f	/* 11111: Mode Control Register */
#define BCM5482_SHD_MODE_1000BX	0x0001	/* Enable 1000BASE-X registers */

/*
 * EXPANSION SHADOW ACCESS REGISTERS.  (PHY REG 0x15, 0x16, and 0x17)
 */
#define MII_BCM54XX_EXP_AADJ1CH0		0x001f
#define  MII_BCM54XX_EXP_AADJ1CH0_SWP_ABCD_OEN	0x0200
#define  MII_BCM54XX_EXP_AADJ1CH0_SWSEL_THPF	0x0100
#define MII_BCM54XX_EXP_AADJ1CH3		0x601f
#define  MII_BCM54XX_EXP_AADJ1CH3_ADCCKADJ	0x0002
#define MII_BCM54XX_EXP_EXP08			0x0F08
#define  MII_BCM54XX_EXP_EXP08_RJCT_2MHZ	0x0001
#define  MII_BCM54XX_EXP_EXP08_EARLY_DAC_WAKE	0x0200
#define MII_BCM54XX_EXP_EXP75			0x0f75
#define  MII_BCM54XX_EXP_EXP75_VDACCTRL		0x003c
#define MII_BCM54XX_EXP_EXP96			0x0f96
#define  MII_BCM54XX_EXP_EXP96_MYST		0x0010

#define MII_RESV3				0x15
#define	NOT_SELECT_EXPANSION_REGISTER	(0x0<<8)
#define	SELECT_SECONDARY_SERDES		(0xE<<8)
#define	SELECT_EXPANSION_REGISTER	(0xF<<8)

#define MII_RESV4				0x18
#define EDGE_RATE_CONTROL_4NS		(0<<12)
#define EDGE_RATE_CONTROL_5NS		(1<<12)
#define EDGE_RATE_CONTROL_3NS		(2<<12)
#define EDGE_RATE_CONTROL_0NS		(0<<12)
#define	SHADOW_REGISTER_AUXILIARY_CTL	(0<<0)
#define	SHADOW_REGISTER_10BASE_T	(1<<0)
#define	SHADOW_REGISTER_POWER_MII_CTL	(2<<0)
#define	SHADOW_REGISTER_RESERVED0	(3<<0)
#define	SHADOW_REGISTER_MISC_TEST	(4<<0)
#define	SHADOW_REGISTER_RESERVED1	(5<<0)
#define	SHADOW_REGISTER_RESERVED2	(6<<0)
#define	SHADOW_REGISTER_MISC_CTL	(7<<0)

#define SHADOW_SPARE_CONTROL1			0x02	/* 00010 */
#define SHADOW_CLOCK_ALIGNMENT			0x03	/* 00011 */
#define GTXCLK_DELAY_ENABLE		(1<<9)
#define SHADOW_SPARE_CONTROL2			0x04	/* 00100 */
#define SHADOW_SPARE_CONTROL3			0x05	/* 00101 */
#define SHADOW_LED_STATUS			0x08	/* 01000 */
#define SHADOW_LED_CONTROL			0x09	/* 01001 */
#define SHADOW_AUTO_POWERDOWN			0x0A	/* 01010 */
#define SHADOW_LED_SELECTOR1			0x0D	/* 01101 */
#define SHADOW_LED_SELECTOR2			0x0E	/* 01110 */
#define SHADOW_LED_GPIO				0x0F	/* 01111 */
#define SHADOW_SERDES_STATUS			0x11	/* 10001 */
#define SHADOW_SERDES_CONTROL			0x13	/* 10011 */
#define SERDES_ENABLE			(1<<0)
#define SERDES_HALFDUPLEX		(0<<1)
#define SERDES_FULLDUPLEX		(1<<1)
#define FAR_AND_FAULT_ENABLE		(3<<1)
#define SHADOW_SGMII_SLAVE			0x15	/* 10101 */
#define SHADOW_COPPER_FIBER_AUTODETECT		0x1E	/* 11110 */
#define AUTODETECT_ENABLE		(1<<0)
#define AUTODETECT_PRIORITY_COPPER	(0<<1)
#define AUTODETECT_PRIORITY_FIBER	(1<<1)
#define AUTODETECT_DEFAULT_COPPER	(0<<2)
#define AUTODETECT_DEFAULT_FIBER	(1<<2)
#define AUTODETECT_FIBER_AH		(0<<8)
#define AUTODETECT_FIBER_AL		(1<<8)
#define SHADOW_MODE_CONTROL			0x1F	/* 11111 */
#define SELECT_COPPER_REGISTERS		(0<<0)
#define SELECT_1000BASEX_REGISTERS	(1<<0)
#define MODE_SELECT_COPPER		(0<<1)
#define MODE_SELECT_MASK		(3<<1)
#define MODE_SELECT_FIBER		(1<<1)
#define MODE_SELECT_SGMII		(2<<1)
#define MODE_SELECT_MEDIA_CONVERTER	(3<<1)
#define RESERVED_WRITE_SET		(1<<3)
#define FIBER_SIGNAL_DETECTED		(1<<4)
#define COPPER_ENERGY_DETECTED		(1<<5)
#define SERDES_LINK			(1<<6)
#define COPPER_LINK			(1<<7)
#define MODE_SELECT_CHANGE		(1<<8)
#define RESERVED_WRITE_CLEAR		(1<<9)

#endif				/* _BROADCOM_54XX_GPHY_H_ */
