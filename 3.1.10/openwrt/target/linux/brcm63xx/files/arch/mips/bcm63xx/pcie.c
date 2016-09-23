
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/clk.h>

#include <bcm63xx_cpu.h>
#include <bcm63xx_io.h>
#include <bcm63xx_regs.h>

int __init bcm63xx_pcie_init(void)
{
	struct clk *clk;
	u32 reg;

	/* enable USB host clock */
	clk = clk_get(NULL, "pcie");
	if (IS_ERR(clk))
		return -ENODEV;

	clk_enable(clk);

	/* pcie serdes enable */
	reg = bcm_rset_readl(RSET_MISC, MISC_6362_SERDES_CTL);
	reg |= (SERDES_6362_PCIE_ENABLE | SERDES_6362_PCIE_EXD_ENABLE);
	bcm_rset_writel(RSET_MISC, reg, MISC_6362_SERDES_CTL);

	/* reset pcie and ext device */
	reg = bcm_perf_readl(PERF_6362_SOFTRESET_REG);
	reg &= ~(SOFTRESET_6362_PCIE_MASK | SOFTRESET_6362_PCIE_EXT_MASK | SOFTRESET_6362_PCIE_CORE_MASK);
	bcm_perf_writel(reg, PERF_6362_SOFTRESET_REG);
	mdelay(10);
	reg = bcm_perf_readl(PERF_6362_SOFTRESET_REG);
	reg |= (SOFTRESET_6362_PCIE_MASK | SOFTRESET_6362_PCIE_CORE_MASK);
	bcm_perf_writel(reg, PERF_6362_SOFTRESET_REG);
	mdelay(10);
	reg = bcm_perf_readl(PERF_6362_SOFTRESET_REG);
	reg |= (SOFTRESET_6362_PCIE_EXT_MASK);
	bcm_perf_writel(reg, PERF_6362_SOFTRESET_REG);
	/* this is a critical delay */
	mdelay(200);

	/* enable PCIE */
	return 0;
}
arch_initcall(bcm63xx_pcie_init);
