#ifndef BCM63XX_DEV_SPI_H
#define BCM63XX_DEV_SPI_H

#include <linux/types.h>
#include <bcm63xx_io.h>
#include <bcm63xx_regs.h>

int __init bcm63xx_spi_register(void);
int __init bcm63xx_hsspi_register(void);

struct bcm63xx_spi_pdata {
	unsigned int	fifo_size;
	int		bus_num;
	int		num_chipselect;
	u32		speed_hz;
};

enum bcm63xx_regs_spi {
        SPI_CMD,
        SPI_INT_STATUS,
        SPI_INT_MASK_ST,
        SPI_INT_MASK,
        SPI_ST,
        SPI_CLK_CFG,
        SPI_FILL_BYTE,
        SPI_MSG_TAIL,
        SPI_RX_TAIL,
        SPI_MSG_CTL,
        SPI_MSG_DATA,
        SPI_RX_DATA,
};

static inline unsigned long bcm63xx_spireg(enum bcm63xx_regs_spi reg)
{
#ifdef BCMCPU_RUNTIME_DETECT
	extern const unsigned long *bcm63xx_regs_spi;
        return bcm63xx_regs_spi[reg];
#else
#ifdef CONFIG_BCM63XX_CPU_6338
switch (reg) {
	case SPI_CMD:
		return SPI_BCM_6338_SPI_CMD;
	case SPI_INT_STATUS:
		return SPI_BCM_6338_SPI_INT_STATUS;
	case SPI_INT_MASK_ST:
		return SPI_BCM_6338_SPI_MASK_INT_ST;
	case SPI_INT_MASK:
		return SPI_BCM_6338_SPI_INT_MASK;
	case SPI_ST:
		return SPI_BCM_6338_SPI_ST;
	case SPI_CLK_CFG:
		return SPI_BCM_6338_SPI_CLK_CFG;
	case SPI_FILL_BYTE:
		return SPI_BCM_6338_SPI_FILL_BYTE;
	case SPI_MSG_TAIL:
		return SPI_BCM_6338_SPI_MSG_TAIL;
	case SPI_RX_TAIL:
		return SPI_BCM_6338_SPI_RX_TAIL;
	case SPI_MSG_CTL:
		return SPI_BCM_6338_SPI_MSG_CTL;
	case SPI_MSG_DATA:
		return SPI_BCM_6338_SPI_MSG_DATA;
	case SPI_RX_DATA:
		return SPI_BCM_6338_SPI_RX_DATA;
}
#endif
#ifdef CONFIG_BCM63XX_CPU_6348
switch (reg) {
	case SPI_CMD:
		return SPI_BCM_6348_SPI_CMD;
	case SPI_INT_MASK_ST:
		return SPI_BCM_6348_SPI_MASK_INT_ST;
	case SPI_INT_MASK:
		return SPI_BCM_6348_SPI_INT_MASK;
	case SPI_INT_STATUS:
		return SPI_BCM_6348_SPI_INT_STATUS;
	case SPI_ST:
		return SPI_BCM_6348_SPI_ST;
	case SPI_CLK_CFG:
		return SPI_BCM_6348_SPI_CLK_CFG;
	case SPI_FILL_BYTE:
		return SPI_BCM_6348_SPI_FILL_BYTE;
	case SPI_MSG_TAIL:
		return SPI_BCM_6348_SPI_MSG_TAIL;
	case SPI_RX_TAIL:
		return SPI_BCM_6348_SPI_RX_TAIL;
	case SPI_MSG_CTL:
		return SPI_BCM_6348_SPI_MSG_CTL;
	case SPI_MSG_DATA:
		return SPI_BCM_6348_SPI_MSG_DATA;
	case SPI_RX_DATA:
		return SPI_BCM_6348_SPI_RX_DATA;
}
#endif
#if defined(CONFIG_BCM63XX_CPU_6358) || defined(CONFIG_BCM63XX_CPU_6362)
switch (reg) {
	case SPI_CMD:
		return SPI_BCM_6358_SPI_CMD;
	case SPI_INT_STATUS:
		return SPI_BCM_6358_SPI_INT_STATUS;
	case SPI_INT_MASK_ST:
		return SPI_BCM_6358_SPI_MASK_INT_ST;
	case SPI_INT_MASK:
		return SPI_BCM_6358_SPI_INT_MASK;
	case SPI_ST:
		return SPI_BCM_6358_SPI_STATUS;
	case SPI_CLK_CFG:
		return SPI_BCM_6358_SPI_CLK_CFG;
	case SPI_FILL_BYTE:
		return SPI_BCM_6358_SPI_FILL_BYTE;
	case SPI_MSG_TAIL:
		return SPI_BCM_6358_SPI_MSG_TAIL;
	case SPI_RX_TAIL:
		return SPI_BCM_6358_SPI_RX_TAIL;
	case SPI_MSG_CTL:
		return SPI_BCM_6358_MSG_CTL;
	case SPI_MSG_DATA:
		return SPI_BCM_6358_SPI_MSG_DATA;
	case SPI_RX_DATA:
		return SPI_BCM_6358_SPI_RX_DATA;
}
#endif
#endif
	return 0;
}

#endif /* BCM63XX_DEV_SPI_H */
