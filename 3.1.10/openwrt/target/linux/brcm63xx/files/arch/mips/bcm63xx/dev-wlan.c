
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/clk.h>

#include <bcm63xx_cpu.h>
#include <bcm63xx_io.h>
#include <bcm63xx_regs.h>

#include <bcm_map_part.h>

int __init bcm63xx_wlan_register(void)
{
	struct clk *clk;
	u32 reg;

	/* enable USB host clock */
	clk = clk_get(NULL, "wlan");
	if (IS_ERR(clk))
		return -ENODEV;

	clk_enable(clk);

	mdelay(10);
	reg = bcm_perf_readl(PERF_6362_SOFTRESET_REG);
	reg &= ~(SOFTRESET_6362_WLAN_SHIM_UBUS_MASK | SOFTRESET_6362_WLAN_SHIM_MASK);
	bcm_perf_writel(reg, PERF_6362_SOFTRESET_REG);
	mdelay(1);
	reg = bcm_perf_readl(PERF_6362_SOFTRESET_REG);
	reg |= (SOFTRESET_6362_WLAN_SHIM_UBUS_MASK | SOFTRESET_6362_WLAN_SHIM_MASK);
	bcm_perf_writel(reg, PERF_6362_SOFTRESET_REG);
	mdelay(1);

	/* a0b0compatible */
	if ((bcm63xx_get_cpu_rev() & 0xff) == 0xa0) {
		WLAN_SHIM->a0.ShimMisc =
		    (WLAN_SHIM_FORCE_CLOCKS_ON | WLAN_SHIM_MACRO_SOFT_RESET);
		mdelay(1);
		WLAN_SHIM->a0.MacControl = (SICF_FGC | SICF_CLOCK_EN);
		WLAN_SHIM->a0.ShimMisc = WLAN_SHIM_FORCE_CLOCKS_ON;
		WLAN_SHIM->a0.ShimMisc = 0;
		WLAN_SHIM->a0.MacControl = SICF_CLOCK_EN;
	} else {
		WLAN_SHIM->b0.ShimMisc =
		    (WLAN_SHIM_FORCE_CLOCKS_ON | WLAN_SHIM_MACRO_SOFT_RESET);
		mdelay(1);
		WLAN_SHIM->b0.MacControl = (SICF_FGC | SICF_CLOCK_EN);
		WLAN_SHIM->b0.ShimMisc = WLAN_SHIM_FORCE_CLOCKS_ON;
		WLAN_SHIM->b0.ShimMisc = 0;
		WLAN_SHIM->b0.MacControl = SICF_CLOCK_EN;
	}

	return 0;
}
