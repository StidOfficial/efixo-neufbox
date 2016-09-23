/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2010 Tanguy Bouzéloc <tanguy.bouzeloc@efixo.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/platform_device.h>

#include <bcm63xx_io.h>
#include <bcm63xx_regs.h>
#include <bcm63xx_dev_tdm.h>

#define DRV_VER "0.0.2"

static int tdm_match_device(struct device *dev, struct device_driver *drv)
{
	return -ENODEV;
}

struct bus_type tdm_bus_type = {
	.name		= "tdm",
	.match		= tdm_match_device,
};
EXPORT_SYMBOL_GPL(tdm_bus_type);

struct bcm63xx_tdm {
	int                    irq;
	void __iomem           *regs;
	struct clk             *clk;
	struct platform_device *pdev;
};

static int bcm63xx_tdm_pll_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	u32 reg;
	u32 offset;
	u32 mask;

	/* soft reset the tdm clock */
	if (BCMCPU_IS_6358()) {
		offset = PERF_6358_SOFTRESET_REG;
		mask = SOFTRESET_6358_PCM_MASK;
	} else if (BCMCPU_IS_6362()) {
		offset = PERF_6362_SOFTRESET_REG;
		mask = SOFTRESET_6362_PCM_MASK;
	}

	reg = bcm_perf_readl(offset);
	reg &= ~mask;
	bcm_perf_writel(reg, offset);

	msleep(50);

	reg = bcm_perf_readl(offset);
	reg |= mask;
	bcm_perf_writel(reg, offset);

	/* power up pll */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg &= ~(TDM_PLL_CTL_RESET | TDM_PLL_CTL_RESET_CH1
		 | TDM_PLL_CTL_RESET_CH1);
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	bcm_tdm_writel(0x1C40127D, TDM_PLL_CTL1);
	bcm_tdm_writel(0xD0000000, TDM_PLL_CTL2);
	bcm_tdm_writel(0x38000700, TDM_PLL_CTL3);
	bcm_tdm_writel(0x00100015, TDM_PLL_CTL4);

	/* remove analog reset */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg &= ~TDM_PLL_CTL_ARESET;
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	/* remove digital reset */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg &= ~TDM_PLL_CTL_DRESET;
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	/* remove clk16 reset */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg &= ~TDM_PLL_CTL_CLK16_RESET;
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	msleep(10);

	reg = bcm_tdm_readl(TDM_PLL_STATUS);
	if ((reg & TDM_PLL_LOCK) != TDM_PLL_LOCK) {
		dev_err(dev, "pll didn't lock the programmed output frequency\n");
		return -ENXIO;
	}

	dev_dbg(dev, "pll init complete\n");
	dev_dbg(dev, "TDM_PLL_CTL1 = 0x%08x\n",
		bcm_tdm_readl(TDM_PLL_CTL1));
	dev_dbg(dev, "TDM_PLL_CTL2 = 0x%08x\n",
		bcm_tdm_readl(TDM_PLL_CTL2));
	dev_dbg(dev, "TDM_PLL_CTL3 = 0x%08x\n",
		bcm_tdm_readl(TDM_PLL_CTL3));
	dev_dbg(dev, "TDM_PLL_CTL4 = 0x%08x\n",
		bcm_tdm_readl(TDM_PLL_CTL4));

	return 0;
}

static void bcm63xx_tdm_pll_deinit(void)
{
	uint32_t reg;

	/* clock 16 reset */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg |= TDM_PLL_CTL_CLK16_RESET;
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	/* analog reset */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg |= TDM_PLL_CTL_ARESET;
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	/* digital reset */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg |= TDM_PLL_CTL_DRESET;
	bcm_tdm_writel(reg, TDM_PLL_CTL1);

	/* power down pll */
	reg = bcm_tdm_readl(TDM_PLL_CTL1);
	reg |= (TDM_PLL_CTL_RESET | TDM_PLL_CTL_RESET_CH1
		| TDM_PLL_CTL_REFCMP_RESET);
	bcm_tdm_writel(reg, TDM_PLL_CTL1);
}

static int __init bcm63xx_tdm_probe(struct platform_device *pdev)
{
	struct resource *r;
	int irq;
	struct clk *clk;
	struct bcm63xx_tdm *tdm;
	struct device *dev = &pdev->dev;
	int ret = 0;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(dev, "no iomem for device\n");
		ret = -ENXIO;
		goto out;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(dev, "no irq for device\n");
		ret = -ENXIO;
		goto out;
	}

	clk = clk_get(dev, "pcm");
	if (IS_ERR(clk)) {
		dev_err(dev, "No clock for device\n");
		ret = -ENODEV;
		goto out;
	}

	clk_enable(clk);

	tdm = kmalloc(sizeof(struct bcm63xx_tdm), GFP_KERNEL);
	if (!tdm) {
		dev_err(dev, "out of memory\n");
		ret = -ENOMEM;
		goto out_clk;
	}
	
	platform_set_drvdata(pdev, tdm);
	tdm->clk = clk;
	tdm->irq = irq;
	
	if (!request_mem_region(r->start, r->end - r->start, KBUILD_MODNAME)) {
		dev_err(dev, "request_mem_region failed\n");
		ret = -ENXIO;
		goto out_free;
	}

	tdm->regs = ioremap_nocache(r->start, r->end - r->start);
	if (!tdm->regs) {
		dev_err(dev, "unable to ioremap regs\n");
		ret = -ENOMEM;
		goto out_mem_region;
	}

	ret = bcm63xx_tdm_pll_init(pdev);
	if(ret)
		goto out_pll;

	dev_info(dev, "at 0x%08x (irq %d) v%s\n", r->start, irq, DRV_VER);
	return ret;

out_pll:
	bcm63xx_tdm_pll_deinit();
out_mem_region:
	release_mem_region(r->start, r->end - r->start);
out_free:
	kfree(tdm);
out_clk:
	clk_disable(clk);
	clk_put(clk);
out:
	return ret;
}

static int __exit bcm63xx_tdm_remove(struct platform_device *pdev)
{
	struct bcm63xx_tdm *tdm = platform_get_drvdata(pdev);
	struct resource *r = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	bcm63xx_tdm_pll_deinit();
	clk_disable(tdm->clk);
	clk_put(tdm->clk);
	iounmap(tdm->regs);
	release_mem_region(r->start, r->end - r->start);
	kfree(tdm);
	platform_set_drvdata(pdev, 0);

	return 0;
}

#ifdef CONFIG_PM
static int bcm63xx_tdm_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	struct bcm63xx_tdm *tdm = platform_get_drvdata(pdev);

        clk_disable(tdm->clk);

	return 0;
}

static int bcm63xx_tdm_resume(struct platform_device *pdev)
{
	struct bcm63xx_tdm *tdm = platform_get_drvdata(pdev);

	clk_enable(tdm->clk);

	return 0;
}
#else
#define bcm63xx_tdm_suspend	NULL
#define bcm63xx_tdm_resume	NULL
#endif

static struct platform_driver bcm63xx_tdm_driver = {
	.driver = {
		.name  = "bcm63xx-tdm",
		.owner = THIS_MODULE,
	},
	.probe         = bcm63xx_tdm_probe,
	.remove        = bcm63xx_tdm_remove,
	.suspend       = bcm63xx_tdm_suspend,
	.resume        = bcm63xx_tdm_resume,
};

static int __init bcm63xx_tdm_init(void)
{
	return platform_driver_register(&bcm63xx_tdm_driver);
}

static void __exit bcm63xx_tdm_exit(void)
{
	platform_driver_unregister(&bcm63xx_tdm_driver);
}

module_init(bcm63xx_tdm_init);
module_exit(bcm63xx_tdm_exit);

MODULE_ALIAS("platform:bcm63xx_tdm");
MODULE_AUTHOR("Tanguy Bouzéloc <tanguy.bouzeloc@efixo.com");
MODULE_DESCRIPTION("Broadcom BCM63xx TDM Controller driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VER);
