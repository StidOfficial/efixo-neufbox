#ifndef BCM63XX_DEV_TDM_H
#define BCM63XX_DEV_TDM_H
#include <linux/kernel.h>
#include <bcm63xx_regs.h>

enum bcm63xx_regs_tdm {
	TDM_CTL,
	TDM_CHAN_CTL,
	TDM_INT_STATUS,
	TDM_INT_MASK,
	TDM_PLL_CTL1,
	TDM_PLL_CTL2,
	TDM_PLL_CTL3,
	TDM_PLL_CTL4,
	TDM_PLL_STATUS,
	TDM_NTR_COUNTER,
	TDM_TS_TABLE,
};

enum bcm63xx_regs_tdm_dma {
	TDM_DMA_NUM_CHP,
	TDM_DMA_CTL,
	TDM_DMA_CH1_FC_LOW_THR,
	TDM_DMA_CH1_FC_HIGH_THR,
	TDM_DMA_CH1_BUF_ALLOC,
	TDM_DMA_CH3_FC_LOW_THR,
	TDM_DMA_CH3_FC_HIGH_THR,
	TDM_DMA_CH3_BUF_ALLOC,
	TDM_DMA_CH5_FC_LOW_THR,
	TDM_DMA_CH5_FC_HIGH_THR,
	TDM_DMA_CH5_BUF_ALLOC,
	TDM_DMA_CH7_FC_LOW_THR,
	TDM_DMA_CH7_FC_HIGH_THR,
	TDM_DMA_CH7_BUF_ALLOC,
	TDM_DMA_CHANNEL_RESET,
	TDM_DMA_CHANNEL_DEBUG,
	TDM_DMA_INT_STATUS,
	TDM_DMA_INT_MASK,
};

enum bcm63xx_regs_tdm_dma_ch1 {
	TDM_DMA_CH1_CTL,
	TDM_DMA_CH1_INT_STATUS,
	TDM_DMA_CH1_INT_MASK,
	TDM_DMA_CH1_MAX_BURST,
};

enum bcm63xx_regs_tdm_dma_ch2 {
	TDM_DMA_CH2_CTL,
	TDM_DMA_CH2_INT_STATUS,
	TDM_DMA_CH2_INT_MASK,
	TDM_DMA_CH2_MAX_BURST,
};

enum bcm63xx_regs_tdm_dma_state_ram {
	TDM_DMA_STATE_RAM_ADDR,
	TDM_DMA_STATE_RAM_STATUS,
	TDM_DMA_STATE_RAM_BUF_DESC1,
	TDM_DMA_STATE_RAM_BUF_DESC2,
};


extern const uint32_t *bcm63xx_tdm_reg_base;
extern const uint32_t *bcm63xx_tdm_dma_reg_base;
extern const uint32_t *bcm63xx_tdm_dma_ch1_reg_base;
extern const uint32_t *bcm63xx_tdm_dma_ch2_reg_base;
extern const uint32_t *bcm63xx_tdm_dma_state_ram;

static inline uint32_t bcm63xx_tdm_reg(enum bcm63xx_regs_tdm reg)
{
#ifdef BCMCPU_RUNTIME_DETECT
	return bcm63xx_regs_tdm[reg];
#else
	if (BCMCPU_IS_6358()) {
		switch (reg) {
		case TDM_CTL:
			return BCM6358_TDM_CTL;
		case TDM_CHAN_CTL:
			return BCM6358_TDM_CHAN_CTL;
		case TDM_INT_STATUS:
			return BCM6358_TDM_INT_STATUS;
		case TDM_INT_MASK:
			return BCM6358_TDM_INT_MASK;
		case TDM_PLL_CTL1:
			return BCM6358_TDM_PLL_CTL1;
		case TDM_PLL_CTL2:
			return BCM6358_TDM_PLL_CTL2;
		case TDM_PLL_CTL3:
			return BCM6358_TDM_PLL_CTL3;
		case TDM_PLL_STATUS:
			return BCM6358_TDM_PLL_STATUS;
		case TDM_TS_TABLE:
			return BCM6358_TDM_TS_TABLE;
		default:
			return 0xdeadbeef;
		};
	}

	if (BCMCPU_IS_6362()) {
		switch (reg) {
		case TDM_CTL:
			return BCM6362_TDM_CTL;
		case TDM_CHAN_CTL:
			return BCM6362_TDM_CHAN_CTL;
		case TDM_INT_STATUS:
			return BCM6362_TDM_INT_STATUS;
		case TDM_INT_MASK:
			return BCM6362_TDM_INT_MASK;
		case TDM_PLL_CTL1:
			return BCM6362_TDM_PLL_CTL1;
		case TDM_PLL_CTL2:
			return BCM6362_TDM_PLL_CTL2;
		case TDM_PLL_CTL3:
			return BCM6362_TDM_PLL_CTL3;
		case TDM_PLL_CTL4:
			return BCM6362_TDM_PLL_CTL4;
		case TDM_PLL_STATUS:
			return BCM6362_TDM_PLL_STATUS;
		case TDM_NTR_COUNTER:
			return BCM6362_TDM_NTR_COUNTER;
		case TDM_TS_TABLE:
			return BCM6362_TDM_TS_TABLE;
		default:
			return 0xdeadbeef;
		};
	}

	return 0xdeadbeef;
#endif /* BCMCPU_RUNTIME_DETECT */
}

static inline uint32_t bcm63xx_tdm_dma_reg(enum bcm63xx_regs_tdm_dma reg)
{
#ifdef BCMCPU_RUNTIME_DETECT
	return bcm63xx_regs_tdm_dma[reg];
#else
	if (BCMCPU_IS_6358()) {
		switch (reg) {
		case TDM_DMA_NUM_CHP:
			return BCM6358_TDM_DMA_NUM_CHP;
		case TDM_DMA_CTL:
			return BCM6358_TDM_DMA_CTL;
		case TDM_DMA_CH1_FC_LOW_THR:
			return BCM6358_TDM_DMA_CH1_FC_LOW_THR;
		case TDM_DMA_CH1_FC_HIGH_THR:
			return BCM6358_TDM_DMA_CH1_FC_HIGH_THR;
		case TDM_DMA_CH1_BUF_ALLOC:
			return BCM6358_TDM_DMA_CH1_BUF_ALLOC;
		case TDM_DMA_CH3_FC_LOW_THR:
			return BCM6358_TDM_DMA_CH3_FC_LOW_THR;
		case TDM_DMA_CH3_FC_HIGH_THR:
			return BCM6358_TDM_DMA_CH3_FC_HIGH_THR;
		case TDM_DMA_CH3_BUF_ALLOC:
			return BCM6358_TDM_DMA_CH3_BUF_ALLOC;
		default:
			return 0xdeadbeef;
		};
	}

	if (BCMCPU_IS_6362()) {
		switch (reg) {
		case TDM_DMA_CTL:
			return BCM6362_TDM_DMA_CTL;
		case TDM_DMA_CH1_FC_LOW_THR:
			return BCM6362_TDM_DMA_CH1_FC_LOW_THR;
		case TDM_DMA_CH1_FC_HIGH_THR:
			return BCM6362_TDM_DMA_CH1_FC_HIGH_THR;
		case TDM_DMA_CH1_BUF_ALLOC:
			return BCM6362_TDM_DMA_CH1_BUF_ALLOC;
		case TDM_DMA_CH3_FC_LOW_THR:
			return BCM6362_TDM_DMA_CH3_FC_LOW_THR;
		case TDM_DMA_CH3_FC_HIGH_THR:
			return BCM6362_TDM_DMA_CH3_FC_HIGH_THR;
		case TDM_DMA_CH3_BUF_ALLOC:
			return BCM6362_TDM_DMA_CH3_BUF_ALLOC;
		case TDM_DMA_CH5_FC_LOW_THR:
			return BCM6362_TDM_DMA_CH5_FC_LOW_THR;
		case TDM_DMA_CH5_FC_HIGH_THR:
			return BCM6362_TDM_DMA_CH5_FC_HIGH_THR;
		case TDM_DMA_CH5_BUF_ALLOC:
			return BCM6362_TDM_DMA_CH5_BUF_ALLOC;
		case TDM_DMA_CH7_FC_LOW_THR:
			return BCM6362_TDM_DMA_CH7_FC_LOW_THR;
		case TDM_DMA_CH7_FC_HIGH_THR:
			return BCM6362_TDM_DMA_CH7_FC_HIGH_THR;
		case TDM_DMA_CH7_BUF_ALLOC:
			return BCM6362_TDM_DMA_CH7_BUF_ALLOC;
		case TDM_DMA_CHANNEL_RESET:
			return BCM6362_TDM_DMA_CHANNEL_RESET;
		case TDM_DMA_CHANNEL_DEBUG:
			return BCM6362_TDM_DMA_CHANNEL_DEBUG;
		case TDM_DMA_INT_STATUS:
			return BCM6362_TDM_DMA_INT_STATUS;
		case TDM_DMA_INT_MASK:
			return BCM6362_TDM_DMA_INT_MASK;
		default:
			return 0xdeadbeef;
		}
	}
	return 0xdeadbeef;
#endif /* BCMCPU_RUNTIME_DETECT */
}

static inline uint32_t bcm6362_tdm_dma_ch1_reg(enum bcm63xx_regs_tdm_dma_ch1 reg)
{
#ifdef BCMCPU_RUNTIME_DETECT
	return bcm63xx_regs_tdm_dma_ch1[reg];
#else
	if (BCMCPU_IS_6358()) {
		switch(reg) {
		case TDM_DMA_CH1_CTL:
			return BCM6358_TDM_DMA_CH1_CTL;
		case TDM_DMA_CH1_INT_STATUS:
			return BCM6358_TDM_DMA_CH1_INT_STATUS;
		case TDM_DMA_CH1_INT_MASK:
			return BCM6358_TDM_DMA_CH1_INT_MASK;
		case TDM_DMA_CH1_MAX_BURST:
			return BCM6358_TDM_DMA_CH1_MAX_BURST;
		default:
			return 0xdeadbeef;
		}
	}

	if (BCMCPU_IS_6362()) {
		switch(reg) {
		case TDM_DMA_CH1_CTL:
			return BCM6362_TDM_DMA_CH1_CTL;
		case TDM_DMA_CH1_INT_STATUS:
			return BCM6362_TDM_DMA_CH1_INT_STATUS;
		case TDM_DMA_CH1_INT_MASK:
			return BCM6362_TDM_DMA_CH1_INT_MASK;
		case TDM_DMA_CH1_MAX_BURST:
			return BCM6362_TDM_DMA_CH1_MAX_BURST;
		default:
			return 0xdeadbeef;
		}
	}

	return 0xdeadbeef;
#endif /* BCMCPU_RUNTIME_DETECT */
}

static inline uint32_t bcm6362_tdm_dma_ch2_reg(enum bcm63xx_regs_tdm_dma_ch2 reg)
{
#ifdef BCMCPU_RUNTIME_DETECT
	return bcm63xx_regs_tdm_dma_ch2[reg];
#else
	if (BCMCPU_IS_6358()) {
		switch(reg) {
		case TDM_DMA_CH2_CTL:
			return BCM6358_TDM_DMA_CH2_CTL;
		case TDM_DMA_CH2_INT_STATUS:
			return BCM6358_TDM_DMA_CH2_INT_STATUS;
		case TDM_DMA_CH2_INT_MASK:
			return BCM6358_TDM_DMA_CH2_INT_MASK;
		case TDM_DMA_CH2_MAX_BURST:
			return BCM6358_TDM_DMA_CH2_MAX_BURST;
		default:
			return 0xdeadbeef;
		}
	}

	if (BCMCPU_IS_6362()) {
		switch(reg) {
		case TDM_DMA_CH2_CTL:
			return BCM6362_TDM_DMA_CH2_CTL;
		case TDM_DMA_CH2_INT_STATUS:
			return BCM6362_TDM_DMA_CH2_INT_STATUS;
		case TDM_DMA_CH2_INT_MASK:
			return BCM6362_TDM_DMA_CH2_INT_MASK;
		case TDM_DMA_CH2_MAX_BURST:
			return BCM6362_TDM_DMA_CH2_MAX_BURST;
		default:
			return 0xdeadbeef;
		}
	}

	return 0xdeadbeef;
#endif /* BCMCPU_RUNTIME_DETECT */
}

static inline uint32_t bcm63xx_tdm_dma_state_ram_reg(enum bcm63xx_regs_tdm_dma_state_ram reg)
{
#ifdef BCMCPU_RUNTIME_DETECT
	return bcm63xx_regs_tdm_dma_state_ram[reg];
#else
	if (BCMCPU_IS_6358()) {
		switch(reg) {
		case TDM_DMA_STATE_RAM_ADDR:
			return BCM6358_TDM_DMA_STATE_RAM_ADDR;
		case TDM_DMA_STATE_RAM_STATUS:
			return BCM6358_TDM_DMA_STATE_RAM_STATUS;
		case TDM_DMA_STATE_RAM_BUF_DESC1:
			return BCM6358_TDM_DMA_STATE_RAM_BUF_DESC1;
		case TDM_DMA_STATE_RAM_BUF_DESC2:
			return BCM6358_TDM_DMA_STATE_RAM_BUF_DESC2;
		default:
			return 0xdeadbeef;
		}
	}

	if (BCMCPU_IS_6362()) {
		switch(reg) {
		case TDM_DMA_STATE_RAM_ADDR:
			return BCM6362_TDM_DMA_STATE_RAM_ADDR;
		case TDM_DMA_STATE_RAM_STATUS:
			return BCM6362_TDM_DMA_STATE_RAM_STATUS;
		case TDM_DMA_STATE_RAM_BUF_DESC1:
			return BCM6362_TDM_DMA_STATE_RAM_BUF_DESC1;
		case TDM_DMA_STATE_RAM_BUF_DESC2:
			return BCM6362_TDM_DMA_STATE_RAM_BUF_DESC2;
		default:
			return 0xdeadbeef;
		}
	}

	return 0xdeadbeef;
#endif /* BCMCPU_RUNTIME_DETECT */
}

/*
 * helpers for pcm registers
 */
#define bcm_tdm_readl(o)		bcm_rset_readl(RSET_TDM, \
						       bcm63xx_tdm_reg(o))
#define bcm_tdm_writel(v, o)		bcm_rset_writel(RSET_TDM, (v), \
							bcm63xx_tdm_reg(o))
#define bcm_tdm_dma_readl(o)		bcm_rset_readl(RSET_TDM_DMA, \
						       bcm63xx_tdm_dma_reg(o))
#define bcm_tdm_dma_writel(v, o)	bcm_rset_writel(RSET_TDM_DMA, (v), \
							bcm63xx_tdm_dma_reg(o))
#define bcm_tdm_dma_ch1_readl(o)	bcm_rset_readl(RSET_TDM_DMA_CH1, \
						       bcm63xx_tdm_dma_ch1_reg(o))
#define bcm_tdm_dma_ch1_writel(v, o)	bcm_rset_writel(RSET_TDM_DMA_CH1, \
							(v), \
							bcm63xx_tdm_dma_ch1_reg(o))
#define bcm_tdm_dma_ch2_readl(o)	bcm_rset_readl(RSET_TDM_DMA_CH2, \
						       bcm63xx_tdm_dma_ch2_reg(o))
#define bcm_tdm_dma_ch2_writel(v, o)	bcm_rset_writel(RSET_TDM_DMA_CH2, \
							(v), \
							bcm63xx_tdm_dma_ch2_reg(o))

int __init bcm63xx_tdm_register(void);

#endif /* BCM63XX_DEV_TDM_H */
