/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 Maxime Bizon <mbizon@freebox.fr>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/gpio.h>

#include <bcm63xx_regs.h>
#include <bcm63xx_io.h>
#include <bcm63xx_cs.h>
#include <bcm63xx_cpu.h>
#include <bcm63xx_board.h>
#include <pcmcia/ss.h>

#define PFX	"bcm63xx_pcmcia: "

enum {
	CARD_CARDBUS = (1 << 0),
	CARD_PCCARD = (1 << 1),
	CARD_5V = (1 << 2),
	CARD_3V = (1 << 3),
	CARD_XV = (1 << 4),
	CARD_YV = (1 << 5),
};

struct bcm63xx_pcmcia_socket {
        /* all regs access are protected by this spinlock */
        spinlock_t lock;

        /* base remapped address of registers */
        void __iomem *base;

        /* whether a card is detected at the moment */
        int card_detected;

        /* type of detected card (mask of above enum) */
        u8 card_type;

};

#ifdef CONFIG_CARDBUS
/* if cardbus is used, platform device needs reference to actual pci
 * device */
#endif

/*
 * read/write helper for pcmcia regs
 */
static inline u32 pcmcia_readl(struct bcm63xx_pcmcia_socket *skt, u32 off)
{
	return bcm_readl(skt->base + off);
}

static inline void pcmcia_writel(struct bcm63xx_pcmcia_socket *skt,
				 u32 val, u32 off)
{
	bcm_writel(val, skt->base + off);
}

/*
 * Implements the set_socket() operation for the in-kernel PCMCIA
 * service (formerly SS_SetSocket in Card Services). We more or
 * less punt all of this work and let the kernel handle the details
 * of power configuration, reset, &c. We also record the value of
 * `state' in order to regurgitate it to the PCMCIA core later.
 */
static int bcm63xx_pcmcia_set_socket(struct bcm63xx_pcmcia_socket *sock,
				     int state)
{
	struct bcm63xx_pcmcia_socket *skt;
	unsigned long flags;
	u32 val;

	skt = sock;

	spin_lock_irqsave(&skt->lock, flags);

	/* note: hardware cannot control socket power, so we will
	 * always report SS_POWERON */

	/* apply socket reset */
	val = pcmcia_readl(skt, PCMCIA_C1_REG);
	if (state & SS_RESET)
		val |= PCMCIA_C1_RESET_MASK;
	else
		val &= ~PCMCIA_C1_RESET_MASK;

	/* reverse reset logic for cardbus card */
	if (skt->card_detected && (skt->card_type & CARD_CARDBUS))
		val ^= PCMCIA_C1_RESET_MASK;

	pcmcia_writel(skt, val, PCMCIA_C1_REG);

	spin_unlock_irqrestore(&skt->lock, flags);

	return 0;
}

/*
 * identity cardtype from VS[12] input, CD[12] input while only VS2 is
 * floating, and CD[12] input while only VS1 is floating
 */
enum {
	IN_VS1 = (1 << 0),
	IN_VS2 = (1 << 1),
	IN_CD1_VS2H = (1 << 2),
	IN_CD2_VS2H = (1 << 3),
	IN_CD1_VS1H = (1 << 4),
	IN_CD2_VS1H = (1 << 5),
};

static const u8 vscd_to_cardtype[] = {

	/* VS1 float, VS2 float */
	[IN_VS1 | IN_VS2] = (CARD_PCCARD | CARD_5V),

	/* VS1 grounded, VS2 float */
	[IN_VS2] = (CARD_PCCARD | CARD_5V | CARD_3V),

	/* VS1 grounded, VS2 grounded */
	[0] = (CARD_PCCARD | CARD_5V | CARD_3V | CARD_XV),

	/* VS1 tied to CD1, VS2 float */
	[IN_VS1 | IN_VS2 | IN_CD1_VS1H] = (CARD_CARDBUS | CARD_3V),

	/* VS1 grounded, VS2 tied to CD2 */
	[IN_VS2 | IN_CD2_VS2H] = (CARD_CARDBUS | CARD_3V | CARD_XV),

	/* VS1 tied to CD2, VS2 grounded */
	[IN_VS1 | IN_CD2_VS1H] = (CARD_CARDBUS | CARD_3V | CARD_XV | CARD_YV),

	/* VS1 float, VS2 grounded */
	[IN_VS1] = (CARD_PCCARD | CARD_XV),

	/* VS1 float, VS2 tied to CD2 */
	[IN_VS1 | IN_VS2 | IN_CD2_VS2H] = (CARD_CARDBUS | CARD_3V),

	/* VS1 float, VS2 tied to CD1 */
	[IN_VS1 | IN_VS2 | IN_CD1_VS2H] = (CARD_CARDBUS | CARD_XV | CARD_YV),

	/* VS1 tied to CD2, VS2 float */
	[IN_VS1 | IN_VS2 | IN_CD2_VS1H] = (CARD_CARDBUS | CARD_YV),

	/* VS2 grounded, VS1 is tied to CD1, CD2 is grounded */
	[IN_VS1 | IN_CD1_VS1H] = 0, /* ignore cardbay */
};

/*
 * poll hardware to check card insertion status
 */
static unsigned int __get_socket_status(struct bcm63xx_pcmcia_socket *skt)
{
	unsigned int stat;
	u32 val;

	stat = 0;

	/* check CD for card presence */
	val = pcmcia_readl(skt, PCMCIA_C1_REG);

	if (!(val & PCMCIA_C1_CD1_MASK) && !(val & PCMCIA_C1_CD2_MASK))
		stat |= SS_DETECT;

	/* if new insertion, detect cardtype */
	if ((stat & SS_DETECT) && !skt->card_detected) {
		unsigned int stat = 0;

		/* float VS1, float VS2 */
		val |= PCMCIA_C1_VS1OE_MASK;
		val |= PCMCIA_C1_VS2OE_MASK;
		pcmcia_writel(skt, val, PCMCIA_C1_REG);

		/* wait for output to stabilize and read VS[12] */
		udelay(10);
		val = pcmcia_readl(skt, PCMCIA_C1_REG);
		stat |= (val & PCMCIA_C1_VS1_MASK) ? IN_VS1 : 0;
		stat |= (val & PCMCIA_C1_VS2_MASK) ? IN_VS2 : 0;

		/* drive VS1 low, float VS2 */
		val &= ~PCMCIA_C1_VS1OE_MASK;
		val |= PCMCIA_C1_VS2OE_MASK;
		pcmcia_writel(skt, val, PCMCIA_C1_REG);

		/* wait for output to stabilize and read CD[12] */
		udelay(10);
		val = pcmcia_readl(skt, PCMCIA_C1_REG);
		stat |= (val & PCMCIA_C1_CD1_MASK) ? IN_CD1_VS2H : 0;
		stat |= (val & PCMCIA_C1_CD2_MASK) ? IN_CD2_VS2H : 0;

		/* float VS1, drive VS2 low */
		val |= PCMCIA_C1_VS1OE_MASK;
		val &= ~PCMCIA_C1_VS2OE_MASK;
		pcmcia_writel(skt, val, PCMCIA_C1_REG);

		/* wait for output to stabilize and read CD[12] */
		udelay(10);
		val = pcmcia_readl(skt, PCMCIA_C1_REG);
		stat |= (val & PCMCIA_C1_CD1_MASK) ? IN_CD1_VS1H : 0;
		stat |= (val & PCMCIA_C1_CD2_MASK) ? IN_CD2_VS1H : 0;

		/* guess cardtype from all this */
		skt->card_type = vscd_to_cardtype[stat];
		if (!skt->card_type)
			printk("MPI: unsupported card type\n");
		else
			printk("MPI: detect %s %s\n",
				skt->card_type & CARD_3V ? "3V" : "5V",
				skt->card_type & CARD_CARDBUS ? "cardbus" : "pccard");

		/* drive both VS pin to 0 again */
		val &= ~(PCMCIA_C1_VS1OE_MASK | PCMCIA_C1_VS2OE_MASK);

		/* enable correct logic */
		val &= ~(PCMCIA_C1_EN_PCMCIA_MASK | PCMCIA_C1_EN_CARDBUS_MASK);
		if (skt->card_type & CARD_PCCARD)
			val |= PCMCIA_C1_EN_PCMCIA_MASK;
		else
			val |= PCMCIA_C1_EN_CARDBUS_MASK;

		pcmcia_writel(skt, val, PCMCIA_C1_REG);
	}
	skt->card_detected = (stat & SS_DETECT) ? 1 : 0;

	/* report card type/voltage */
	if (skt->card_type & CARD_CARDBUS)
		stat |= SS_CARDBUS;
	if (skt->card_type & CARD_3V)
		stat |= SS_3VCARD;
	if (skt->card_type & CARD_XV)
		stat |= SS_XVCARD;
	stat |= SS_POWERON;

	return stat;
}

/*
 * core request to get current socket status
 */
static int bcm63xx_pcmcia_get_status(struct bcm63xx_pcmcia_socket *sock,
				     unsigned int *status)
{
	struct bcm63xx_pcmcia_socket *skt;

	skt = sock;

	spin_lock_bh(&skt->lock);
	*status = __get_socket_status(skt);
	spin_unlock_bh(&skt->lock);

	return 0;
}

int mpi_DetectPcCard(void)
{
	struct bcm63xx_pcmcia_socket skt;
	unsigned int status;

	spin_lock_init(&skt.lock);
	skt.base = (void __iomem*)bcm63xx_regset_address(RSET_PCMCIA);
	skt.card_type = 0;
	skt.card_detected = 0;

	bcm63xx_pcmcia_get_status(&skt, &status);
	if (!skt.card_type)
		return 0;

	bcm63xx_pcmcia_set_socket(&skt, SS_RESET);
	mdelay(10);
	bcm63xx_pcmcia_set_socket(&skt, 0);
	mdelay(100);

	return 0;
}
EXPORT_SYMBOL(mpi_DetectPcCard);
