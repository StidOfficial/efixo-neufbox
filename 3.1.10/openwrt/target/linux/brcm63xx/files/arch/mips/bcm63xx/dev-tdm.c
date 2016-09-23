/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2010 Tanguy Bouzéloc <tanguy.bouzeloc@efixo.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/platform_device.h>

#include <bcm63xx_dev_tdm.h>

static struct resource tdm_resources[] = {
	{
		.start		= -1, /* filled at runtime */
		.end		= -1, /* filled at runtime */
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= -1, /* filled at runtime */
		.flags		= IORESOURCE_IRQ,
	},
};

static struct platform_device bcm63xx_tdm_device = {
	.name		= "bcm63xx-tdm",
	.id		= 0,
	.num_resources	= ARRAY_SIZE(tdm_resources),
	.resource	= tdm_resources,
};

#ifdef BCMCPU_RUNTIME_DETECT
static const uint32_t bcm6358_regs_tdm[] = {
	[TDM_CTL]                 = BCM6358_TDM_CTL,
	[TDM_CHAN_CTL]    	  = BCM6358_TDM_CHAN_CTL,
	[TDM_INT_STATUS] 	  = BCM6358_TDM_INT_STATUS,
	[TDM_INT_MASK]    	  = BCM6358_TDM_INT_MASK,
	[TDM_PLL_CTL1]    	  = BCM6358_TDM_PLL_CTL1,
	[TDM_PLL_CTL2]    	  = BCM6358_TDM_PLL_CTL2,
	[TDM_PLL_CTL3]    	  = BCM6358_TDM_PLL_CTL3,
	[TDM_PLL_CTL4]    	  = 0xdeadbeef,
	[TDM_PLL_STATUS]  	  = BCM6358_TDM_PLL_STATUS,
	[TDM_NTR_COUNTER] 	  = 0xdeadbeef,
	[TDM_TS_TABLE]            = BCM6358_TDM_TS_TABLE,
};

static const uint32_t bcm6362_regs_tdm[] = {
	[TDM_CTL]                 = BCM6362_TDM_CTL,
	[TDM_CHAN_CTL]    	  = BCM6362_TDM_CHAN_CTL,
	[TDM_INT_STATUS]  	  = BCM6362_TDM_INT_STATUS,
	[TDM_INT_MASK]    	  = BCM6362_TDM_INT_MASK,
	[TDM_PLL_CTL1]    	  = BCM6362_TDM_PLL_CTL1,
	[TDM_PLL_CTL2]    	  = BCM6362_TDM_PLL_CTL2,
	[TDM_PLL_CTL3]    	  = BCM6362_TDM_PLL_CTL3,
	[TDM_PLL_CTL4]   	  = BCM6362_TDM_PLL_CTL4,
	[TDM_PLL_STATUS]	  = BCM6362_TDM_PLL_STATUS,
	[TDM_NTR_COUNTER] 	  = BCM6362_TDM_NTR_COUNTER,
	[TDM_TS_TABLE]    	  = BCM6362_TDM_TS_TABLE,
};

static const uint32_t bcm6358_regs_tdm_dma[] = {
	[TDM_DMA_NUM_CHP]         = BCM6358_TDM_DMA_NUM_CHP,
	[TDM_DMA_CTL]             = BCM6358_TDM_DMA_CTL,
	[TDM_DMA_CH1_FC_LOW_THR]  = BCM6358_TDM_DMA_CH1_FC_LOW_THR,
	[TDM_DMA_CH1_FC_HIGH_THR] = BCM6358_TDM_DMA_CH1_FC_HIGH_THR,
	[TDM_DMA_CH1_BUF_ALLOC]   = BCM6358_TDM_DMA_CH1_BUF_ALLOC,
	[TDM_DMA_CH3_FC_LOW_THR]  = BCM6358_TDM_DMA_CH3_FC_LOW_THR,
	[TDM_DMA_CH3_FC_HIGH_THR] = BCM6358_TDM_DMA_CH3_FC_HIGH_THR,
	[TDM_DMA_CH3_BUF_ALLOC]   = BCM6358_TDM_DMA_CH3_BUF_ALLOC,
	[TDM_DMA_CH5_FC_LOW_THR]  = 0xdeadbeef,
	[TDM_DMA_CH5_FC_HIGH_THR] = 0xdeadbeef,
	[TDM_DMA_CH5_BUF_ALLOC]   = 0xdeadbeef,
	[TDM_DMA_CH7_FC_LOW_THR]  = 0xdeadbeef,
	[TDM_DMA_CH7_FC_HIGH_THR] = 0xdeadbeef,
	[TDM_DMA_CH7_BUF_ALLOC]   = 0xdeadbeef,
	[TDM_DMA_CHANNEL_RESET]   = 0xdeadbeef,
	[TDM_DMA_CHANNEL_DEBUG]   = 0xdeadbeef,
	[TDM_DMA_INT_STATUS]      = 0xdeadbeef,
	[TDM_DMA_INT_MASK]        = 0xdeadbeef,
};

static const uint32_t bcm6362_regs_tdm_dma[] = {
	[TDM_DMA_NUM_CHP]         = 0xdeadbeef,
	[TDM_DMA_CTL] 		  = BCM6362_TDM_DMA_CTL,
	[TDM_DMA_CH1_FC_LOW_THR]  = BCM6362_TDM_DMA_CH1_FC_LOW_THR,
	[TDM_DMA_CH1_FC_HIGH_THR] = BCM6362_TDM_DMA_CH1_FC_HIGH_THR,
	[TDM_DMA_CH1_BUF_ALLOC]   = BCM6362_TDM_DMA_CH1_BUF_ALLOC,
	[TDM_DMA_CH3_FC_LOW_THR]  = BCM6362_TDM_DMA_CH3_FC_LOW_THR,
	[TDM_DMA_CH3_FC_HIGH_THR] = BCM6362_TDM_DMA_CH3_FC_HIGH_THR,
	[TDM_DMA_CH3_BUF_ALLOC]   = BCM6362_TDM_DMA_CH3_BUF_ALLOC,
	[TDM_DMA_CH5_FC_LOW_THR]  = BCM6362_TDM_DMA_CH5_FC_LOW_THR,
	[TDM_DMA_CH5_FC_HIGH_THR] = BCM6362_TDM_DMA_CH5_FC_HIGH_THR,
	[TDM_DMA_CH5_BUF_ALLOC]   = BCM6362_TDM_DMA_CH5_BUF_ALLOC,
	[TDM_DMA_CH7_FC_LOW_THR]  = BCM6362_TDM_DMA_CH7_FC_LOW_THR,
	[TDM_DMA_CH7_FC_HIGH_THR] = BCM6362_TDM_DMA_CH7_FC_HIGH_THR,
	[TDM_DMA_CH7_BUF_ALLOC]   = BCM6362_TDM_DMA_CH7_BUF_ALLOC,
	[TDM_DMA_CHANNEL_RESET]   = BCM6362_TDM_DMA_CHANNEL_RESET,
	[TDM_DMA_CHANNEL_DEBUG]   = BCM6362_TDM_DMA_CHANNEL_DEBUG,
	[TDM_DMA_INT_STATUS] 	  = BCM6362_TDM_DMA_INT_STATUS,
	[TDM_DMA_INT_MASK] 	  = BCM6362_TDM_DMA_INT_MASK,
};

static const uint32_t bcm6358_regs_tdm_dma_ch1[] = {
	[TDM_DMA_CH1_CTL]         = BCM6358_TDM_DMA_CH1_CTL,
	[TDM_DMA_CH1_INT_STATUS]  = BCM6358_TDM_DMA_CH1_INT_STATUS,
	[TDM_DMA_CH1_INT_MASK]    = BCM6358_TDM_DMA_CH1_INT_MASK,
	[TDM_DMA_CH1_MAX_BURST]   = BCM6358_TDM_DMA_CH1_MAX_BURST,
};

static const uint32_t bcm6362_regs_tdm_dma_ch1[] = {
	[TDM_DMA_CH1_CTL]         = BCM6362_TDM_DMA_CH1_CTL,
	[TDM_DMA_CH1_INT_STATUS]  = BCM6362_TDM_DMA_CH1_INT_STATUS,
	[TDM_DMA_CH1_INT_MASK]    = BCM6362_TDM_DMA_CH1_INT_MASK,
	[TDM_DMA_CH1_MAX_BURST]   = BCM6362_TDM_DMA_CH1_MAX_BURST,
};

static const uint32_t bcm6358_regs_tdm_dma_ch2[] = {
	[TDM_DMA_CH2_CTL]         = BCM6358_TDM_DMA_CH2_CTL,
	[TDM_DMA_CH2_INT_STATUS]  = BCM6358_TDM_DMA_CH2_INT_STATUS,
	[TDM_DMA_CH2_INT_MASK]    = BCM6358_TDM_DMA_CH2_INT_MASK,
	[TDM_DMA_CH2_MAX_BURST]   = BCM6358_TDM_DMA_CH2_MAX_BURST,
};

static const uint32_t bcm6362_regs_tdm_dma_ch2[] = {
	[TDM_DMA_CH2_CTL]         = BCM6362_TDM_DMA_CH2_CTL,
	[TDM_DMA_CH2_INT_STATUS]  = BCM6362_TDM_DMA_CH2_INT_STATUS,
	[TDM_DMA_CH2_INT_MASK]    = BCM6362_TDM_DMA_CH2_INT_MASK,
	[TDM_DMA_CH2_MAX_BURST]   = BCM6362_TDM_DMA_CH2_MAX_BURST,
};

static const uint32_t bcm6358_regs_tdm_dma_state_ram[] = {
	[TDM_DMA_STATE_RAM_ADDR]      = BCM6358_TDM_DMA_STATE_RAM_ADDR,
	[TDM_DMA_STATE_RAM_STATUS]    = BCM6358_TDM_DMA_STATE_RAM_STATUS,
	[TDM_DMA_STATE_RAM_BUF_DESC1] = BCM6358_TDM_DMA_STATE_RAM_BUF_DESC1,
	[TDM_DMA_STATE_RAM_BUF_DESC2] = BCM6358_TDM_DMA_STATE_RAM_BUF_DESC2,
};

static const uint32_t bcm6362_regs_tdm_dma_state_ram[] = {
	[TDM_DMA_STATE_RAM_ADDR]      = BCM6362_TDM_DMA_STATE_RAM_ADDR,
	[TDM_DMA_STATE_RAM_STATUS]    = BCM6362_TDM_DMA_STATE_RAM_STATUS,
	[TDM_DMA_STATE_RAM_BUF_DESC1] = BCM6362_TDM_DMA_STATE_RAM_BUF_DESC1,
	[TDM_DMA_STATE_RAM_BUF_DESC2] = BCM6362_TDM_DMA_STATE_RAM_BUF_DESC2,
};

const uint32_t *bcm63xx_regs_tdm;
EXPORT_SYMBOL(bcm63xx_regs_tdm);

const uint32_t *bcm63xx_regs_tdm_dma;
EXPORT_SYMBOL(bcm63xx_regs_tdm_dma);

const uint32_t *bcm63xx_regs_tdm_dma_ch1;
EXPORT_SYMBOL(bcm63xx_regs_tdm_dma_ch1);

const uint32_t *bcm63xx_regs_tdm_dma_ch2;
EXPORT_SYMBOL(bcm63xx_regs_tdm_dma_ch2);

const uint32_t *bcm63xx_regs_tdm_dma_state_ram;
EXPORT_SYMBOL(bcm63xx_regs_tdm_dma_state_ram);

static __init int bcm63xx_tdm_regs_init(void)
{
	if (BCMCPU_IS_6358()) {
		bcm63xx_regs_tdm = bcm6358_regs_tdm;
		bcm63xx_regs_tdm_dma = bcm6358_regs_tdm_dma;
		bcm63xx_regs_tdm_dma_ch1 = bcm6358_regs_tdm_dma_ch1;
		bcm63xx_regs_tdm_dma_ch2 = bcm6358_regs_tdm_dma_ch2;
		bcm63xx_regs_tdm_dma_state_ram = bcm6358_regs_tdm_dma_state_ram;
	} else if (BCMCPU_IS_6362()) {
		bcm63xx_regs_tdm = bcm6362_regs_tdm;
		bcm63xx_regs_tdm_dma = bcm6362_regs_tdm_dma;
		bcm63xx_regs_tdm_dma_ch1 = bcm6362_regs_tdm_dma_ch1;
		bcm63xx_regs_tdm_dma_ch2 = bcm6362_regs_tdm_dma_ch2;
		bcm63xx_regs_tdm_dma_state_ram = bcm6362_regs_tdm_dma_state_ram;
	} else {
		return -ENODEV;
	}

	return 0;
}
#else
static __init int bcm63xx_tdm_regs_init(void)
{
	if (BCMCPU_IS_6358() || BCMCPU_IS_6362())
		return 0;
	else
		return -ENODEV;
}
#endif /* BCMCPU_RUNTIME_DETECT */

int __init bcm63xx_tdm_register(void)
{
	struct clk *clk;

	if (bcm63xx_tdm_regs_init())
		return -ENODEV;

	/* enable tdm clock */
	clk = clk_get(NULL, "pcm");
	if (IS_ERR(clk))
		return -ENODEV;

	clk_enable(clk);

	tdm_resources[0].start = bcm63xx_regset_address(RSET_TDM);
	tdm_resources[0].end = tdm_resources[0].start;
	tdm_resources[0].end += RSET_TDM_SIZE - 1;
	tdm_resources[1].start = bcm63xx_get_irq_number(IRQ_TDM);

	return platform_device_register(&bcm63xx_tdm_device);
}
