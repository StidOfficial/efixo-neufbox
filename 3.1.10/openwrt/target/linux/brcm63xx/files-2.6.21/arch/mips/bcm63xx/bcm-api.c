
#include <linux/init.h>
#include <linux/module.h>

#include <bcm_map_part.h>
#include <boardparms.h>

static int __init bcm6358_spi_init(void)
{
	/* Enable SPI interface */
	PERF->blkEnables |= SPI_CLK_EN;
	/* Enable Overlay for SPI SS Pins */
	GPIO->GPIOMode |= GPIO_MODE_SPI_SS_OVERLAY;
	/* Enable SPI Slave Select as Output Pins */
	/* GPIO 32 is SS2, GPIO 33 is SS3 */
	GPIO->GPIODir |= ((uint64) 0x3 << 32);
	return 0;
}
arch_initcall(bcm6358_spi_init);
