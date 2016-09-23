#ifndef BCM63XX_CPU_H_
#define BCM63XX_CPU_H_

#include <linux/types.h>
#include <linux/init.h>

/*
 * Macro to fetch bcm63xx cpu id and revision, should be optimized at
 * compile time if only one CPU support is enabled (idea stolen from
 * arm mach-types)
 */
#define BCM6338_CPU_ID		0x6338
#define BCM6345_CPU_ID		0x6345
#define BCM6348_CPU_ID		0x6348
#define BCM6358_CPU_ID		0x6358
#define BCM6362_CPU_ID		0x6362

void __init bcm63xx_cpu_init(void);
u16 __bcm63xx_get_cpu_id(void);
u16 bcm63xx_get_cpu_rev(void);
unsigned int bcm63xx_get_cpu_freq(void);

#ifdef CONFIG_BCM63XX_CPU_6338
# ifdef bcm63xx_get_cpu_id
#  undef bcm63xx_get_cpu_id
#  define bcm63xx_get_cpu_id()	__bcm63xx_get_cpu_id()
#  define BCMCPU_RUNTIME_DETECT
# else
#  define bcm63xx_get_cpu_id()	BCM6338_CPU_ID
# endif
# define BCMCPU_IS_6338()	(bcm63xx_get_cpu_id() == BCM6338_CPU_ID)
#else
# define BCMCPU_IS_6338()	(0)
#endif

#ifdef CONFIG_BCM63XX_CPU_6345
# ifdef bcm63xx_get_cpu_id
#  undef bcm63xx_get_cpu_id
#  define bcm63xx_get_cpu_id()	__bcm63xx_get_cpu_id()
#  define BCMCPU_RUNTIME_DETECT
# else
#  define bcm63xx_get_cpu_id()	BCM6345_CPU_ID
# endif
# define BCMCPU_IS_6345()	(bcm63xx_get_cpu_id() == BCM6345_CPU_ID)
#else
# define BCMCPU_IS_6345()	(0)
#endif

#ifdef CONFIG_BCM63XX_CPU_6348
# ifdef bcm63xx_get_cpu_id
#  undef bcm63xx_get_cpu_id
#  define bcm63xx_get_cpu_id()	__bcm63xx_get_cpu_id()
#  define BCMCPU_RUNTIME_DETECT
# else
#  define bcm63xx_get_cpu_id()	BCM6348_CPU_ID
# endif
# define BCMCPU_IS_6348()	(bcm63xx_get_cpu_id() == BCM6348_CPU_ID)
#else
# define BCMCPU_IS_6348()	(0)
#endif

#ifdef CONFIG_BCM63XX_CPU_6358
# ifdef bcm63xx_get_cpu_id
#  undef bcm63xx_get_cpu_id
#  define bcm63xx_get_cpu_id()	__bcm63xx_get_cpu_id()
#  define BCMCPU_RUNTIME_DETECT
# else
#  define bcm63xx_get_cpu_id()	BCM6358_CPU_ID
# endif
# define BCMCPU_IS_6358()	(bcm63xx_get_cpu_id() == BCM6358_CPU_ID)
#else
# define BCMCPU_IS_6358()	(0)
#endif

#ifdef CONFIG_BCM63XX_CPU_6362
# ifdef bcm63xx_get_cpu_id
#  undef bcm63xx_get_cpu_id
#  define bcm63xx_get_cpu_id()	__bcm63xx_get_cpu_id()
#  define BCMCPU_RUNTIME_DETECT
# else
#  define bcm63xx_get_cpu_id()	BCM6362_CPU_ID
# endif
# define BCMCPU_IS_6362()	(bcm63xx_get_cpu_id() == BCM6362_CPU_ID)
#else
# define BCMCPU_IS_6362()	(0)
#endif

#ifndef bcm63xx_get_cpu_id
#error "No CPU support configured"
#endif

/*
 * While registers sets are (mostly) the same across 63xx CPU, base
 * address of these sets do change.
 */
enum bcm63xx_regs_set {
	RSET_DSL_LMEM = 0,
	RSET_PERF,
	RSET_TIMER,
	RSET_WDT,
	RSET_UART0,
	RSET_UART1,
	RSET_GPIO,
	RSET_SPI,
	RSET_HSSPI,
	RSET_UDC0,
	RSET_OHCI0,
	RSET_OHCI_PRIV,
	RSET_USBH_PRIV,
	RSET_MPI,
	RSET_PCMCIA,
	RSET_DSL,
	RSET_ENET0,
	RSET_ENET1,
	RSET_ENETDMA,
	RSET_EHCI0,
	RSET_SDRAM,
	RSET_MEMC,
	RSET_DDR,
	RSET_MISC,
	RSET_TDM,
	RSET_TDM_DMA,
	RSET_TDM_DMA_CH1,
	RSET_TDM_DMA_CH2,
	RSET_ATM,
	RSET_USB_CTL,
};

#define RSET_DSL_LMEM_SIZE		(64 * 1024 * 4)
#define RSET_DSL_SIZE			4096
#define RSET_WDT_SIZE			12
#define RSET_ENET_SIZE			2048
#define RSET_ENETDMA_SIZE		2048
#define RSET_SPI_SIZE			256
#define RSET_UART_SIZE			24
#define RSET_HSSPI_SIZE			2048
#define RSET_UDC_SIZE			256
#define RSET_OHCI_SIZE			256
#define RSET_EHCI_SIZE			256
#define RSET_PCMCIA_SIZE		12
#define RSET_TDM_SIZE                   2048

/*
 * 6338 register sets base address
 */
#define BCM_6338_DSL_LMEM_BASE		(0xfff00000)
#define BCM_6338_PERF_BASE		(0xfffe0000)
#define BCM_6338_BB_BASE		(0xfffe0100)
#define BCM_6338_TIMER_BASE		(0xfffe0200)
#define BCM_6338_WDT_BASE		(0xfffe021c)
#define BCM_6338_UART0_BASE		(0xfffe0300)
#define BCM_6338_UART1_BASE		(0xdeadbeef)
#define BCM_6338_GPIO_BASE		(0xfffe0400)
#define BCM_6338_SPI_BASE		(0xfffe0c00)
#define BCM_6338_UDC0_BASE		(0xfffe3000)
#define BCM_6338_USBDMA_BASE		(0xfffe2400)
#define BCM_6338_OHCI0_BASE		(0xdeadbeef)
#define BCM_6338_OHCI_PRIV_BASE		(0xfffe3000)
#define BCM_6338_USBH_PRIV_BASE		(0xdeadbeef)
#define BCM_6338_MPI_BASE		(0xfffe3160)
#define BCM_6338_PCMCIA_BASE		(0xdeadbeef)
#define BCM_6338_SDRAM_REGS_BASE	(0xfffe3100)
#define BCM_6338_DSL_BASE		(0xfffe1000)
#define BCM_6338_SAR_BASE		(0xfffe2000)
#define BCM_6338_UBUS_BASE		(0xdeadbeef)
#define BCM_6338_ENET0_BASE		(0xfffe2800)
#define BCM_6338_ENET1_BASE		(0xdeadbeef)
#define BCM_6338_ENETDMA_BASE		(0xfffe2400)
#define BCM_6338_EHCI0_BASE		(0xdeadbeef)
#define BCM_6338_SDRAM_BASE		(0xfffe3100)
#define BCM_6338_MEMC_BASE		(0xdeadbeef)
#define BCM_6338_DDR_BASE		(0xdeadbeef)

/*
 * 6345 register sets base address
 */
#define BCM_6345_DSL_LMEM_BASE		(0xfff00000)
#define BCM_6345_PERF_BASE		(0xfffe0000)
#define BCM_6345_BB_BASE		(0xfffe0100)
#define BCM_6345_TIMER_BASE		(0xfffe0200)
#define BCM_6345_WDT_BASE		(0xfffe021c)
#define BCM_6345_UART0_BASE		(0xfffe0300)
#define BCM_6345_UART1_BASE		(0xdeadbeef)
#define BCM_6345_GPIO_BASE		(0xfffe0400)
#define BCM_6345_SPI_BASE		(0xdeadbeef)
#define BCM_6345_UDC0_BASE		(0xfffe2100)
#define BCM_6345_USBDMA_BASE		(0xfffe2800)
#define BCM_6345_ENET0_BASE		(0xfffe1800)
#define BCM_6345_ENETDMA_BASE		(0xfffe2800)
#define BCM_6345_PCMCIA_BASE		(0xfffe2028)
#define BCM_6345_MPI_BASE		(0xdeadbeef)
#define BCM_6345_OHCI0_BASE		(0xfffe2100)
#define BCM_6345_OHCI_PRIV_BASE		(0xfffe2200)
#define BCM_6345_USBH_PRIV_BASE		(0xdeadbeef)
#define BCM_6345_SDRAM_REGS_BASE	(0xfffe2300)
#define BCM_6345_DSL_BASE		(0xdeadbeef)
#define BCM_6345_SAR_BASE		(0xdeadbeef)
#define BCM_6345_UBUS_BASE		(0xdeadbeef)
#define BCM_6345_ENET1_BASE		(0xdeadbeef)
#define BCM_6345_EHCI0_BASE		(0xdeadbeef)
#define BCM_6345_SDRAM_BASE		(0xfffe2300)
#define BCM_6345_MEMC_BASE		(0xdeadbeef)
#define BCM_6345_DDR_BASE		(0xdeadbeef)

/*
 * 6348 register sets base address
 */
#define BCM_6348_DSL_LMEM_BASE		(0xfff00000)
#define BCM_6348_PERF_BASE		(0xfffe0000)
#define BCM_6348_TIMER_BASE		(0xfffe0200)
#define BCM_6348_WDT_BASE		(0xfffe021c)
#define BCM_6348_UART0_BASE		(0xfffe0300)
#define BCM_6348_UART1_BASE		(0xdeadbeef)
#define BCM_6348_GPIO_BASE		(0xfffe0400)
#define BCM_6348_SPI_BASE		(0xfffe0c00)
#define BCM_6348_UDC0_BASE		(0xfffe1000)
#define BCM_6348_OHCI0_BASE		(0xfffe1b00)
#define BCM_6348_OHCI_PRIV_BASE		(0xfffe1c00)
#define BCM_6348_USBH_PRIV_BASE		(0xdeadbeef)
#define BCM_6348_MPI_BASE		(0xfffe2000)
#define BCM_6348_PCMCIA_BASE		(0xfffe2054)
#define BCM_6348_SDRAM_REGS_BASE	(0xfffe2300)
#define BCM_6348_DSL_BASE		(0xfffe3000)
#define BCM_6348_ENET0_BASE		(0xfffe6000)
#define BCM_6348_ENET1_BASE		(0xfffe6800)
#define BCM_6348_ENETDMA_BASE		(0xfffe7000)
#define BCM_6348_EHCI0_BASE		(0xdeadbeef)
#define BCM_6348_SDRAM_BASE		(0xfffe2300)
#define BCM_6348_MEMC_BASE		(0xdeadbeef)
#define BCM_6348_DDR_BASE		(0xdeadbeef)

/*
 * 6358 register sets base address
 */
#define BCM_6358_DSL_LMEM_BASE		(0xfff00000)
#define BCM_6358_PERF_BASE		(0xfffe0000)
#define BCM_6358_TIMER_BASE		(0xfffe0040)
#define BCM_6358_WDT_BASE		(0xfffe005c)
#define BCM_6358_UART0_BASE		(0xfffe0100)
#define BCM_6358_UART1_BASE		(0xfffe0120)
#define BCM_6358_GPIO_BASE		(0xfffe0080)
#define BCM_6358_SPI_BASE		(0xfffe0800)
#define BCM_6358_UDC0_BASE		(0xfffe0400)
#define BCM_6358_OHCI0_BASE		(0xfffe1400)
#define BCM_6358_OHCI_PRIV_BASE		(0xdeadbeef)
#define BCM_6358_USBH_PRIV_BASE		(0xfffe1500)
#define BCM_6358_MPI_BASE		(0xfffe1000)
#define BCM_6358_PCMCIA_BASE		(0xfffe1054)
#define BCM_6358_SDRAM_REGS_BASE	(0xfffe2300)
#define BCM_6358_DSL_BASE		(0xfffe3000)
#define BCM_6358_ENET0_BASE		(0xfffe4000)
#define BCM_6358_ENET1_BASE		(0xfffe4800)
#define BCM_6358_ENETDMA_BASE		(0xfffe5000)
#define BCM_6358_EHCI0_BASE		(0xfffe1300)
#define BCM_6358_SDRAM_BASE		(0xdeadbeef)
#define BCM_6358_MEMC_BASE		(0xfffe1200)
#define BCM_6358_DDR_BASE		(0xfffe12a0)
#define BCM_6358_TDM_BASE               (0xfffe1600)
#define BCM_6358_TDM_DMA_BASE           (0xfffe1800)
#define BCM_6358_ATM_BASE               (0xfffe2000)
#define BCM_6358_USB_CTL_BASE           (0xfffe5400)

/*
 * 6362 register sets base address
 */
#define BCM_6362_EHCI0_BASE		(0x10002500)
#define BCM_6362_OHCI0_BASE		(0x10002600)
#define BCM_6362_OHCI_PRIV_BASE		(0xdeadbeef)
#define BCM_6362_USBH_PRIV_BASE		(0x10002700)
#define BCM_6362_PERF_BASE		(0x10000000)
#define BCM_6362_TIMER_BASE		(0x10000040)
#define BCM_6362_WDT_BASE		(0x1000005c)
#define BCM_6362_GPIO_BASE		(0x10000080)
#define BCM_6362_UART0_BASE		(0x10000100)
#define BCM_6362_SPI_BASE		(0x10000800)
#define BCM_6362_HSSPI_BASE		(0x10001000)
#define BCM_6362_MISC_BASE		(0x10001800)
#define BCM_6362_TDM_BASE		(0x1000a000)
#define BCM_6362_TDM_DMA_BASE		(0x1000a800)
#define BCM_6362_TDM_DMA_CH1_BASE	(0x1000aa00)
#define BCM_6362_TDM_DMA_CH2_BASE	(0x1000aa10)
#define BCM_6362_DDR_BASE		(0x10003000)


extern const unsigned long *bcm63xx_regs_base;

static inline unsigned long bcm63xx_regset_address(enum bcm63xx_regs_set set)
{
#ifdef BCMCPU_RUNTIME_DETECT
	return bcm63xx_regs_base[set];
#else
#ifdef CONFIG_BCM63XX_CPU_6338
	switch (set) {
	case RSET_DSL_LMEM:
		return BCM_6338_DSL_LMEM_BASE;
	case RSET_PERF:
		return BCM_6338_PERF_BASE;
	case RSET_TIMER:
		return BCM_6338_TIMER_BASE;
	case RSET_WDT:
		return BCM_6338_WDT_BASE;
	case RSET_UART0:
		return BCM_6338_UART0_BASE;
	case RSET_UART1:
		return BCM_6338_UART1_BASE;
	case RSET_GPIO:
		return BCM_6338_GPIO_BASE;
	case RSET_SPI:
		return BCM_6338_SPI_BASE;
	case RSET_UDC0:
		return BCM_6338_UDC0_BASE;
	case RSET_OHCI0:
		return BCM_6338_OHCI0_BASE;
	case RSET_OHCI_PRIV:
		return BCM_6338_OHCI_PRIV_BASE;
	case RSET_USBH_PRIV:
		return BCM_6338_USBH_PRIV_BASE;
	case RSET_MPI:
		return BCM_6338_MPI_BASE;
	case RSET_PCMCIA:
		return BCM_6338_PCMCIA_BASE;
	case RSET_DSL:
		return BCM_6338_DSL_BASE;
	case RSET_ENET0:
		return BCM_6338_ENET0_BASE;
	case RSET_ENET1:
		return BCM_6338_ENET1_BASE;
	case RSET_ENETDMA:
		return BCM_6338_ENETDMA_BASE;
	case RSET_EHCI0:
		return BCM_6338_EHCI0_BASE;
	case RSET_SDRAM:
		return BCM_6338_SDRAM_BASE;
	case RSET_MEMC:
		return BCM_6338_MEMC_BASE;
	case RSET_DDR:
		return BCM_6338_DDR_BASE;
	}
#endif
#ifdef CONFIG_BCM63XX_CPU_6345
	switch (set) {
	case RSET_DSL_LMEM:
		return BCM_6345_DSL_LMEM_BASE;
	case RSET_PERF:
		return BCM_6345_PERF_BASE;
	case RSET_TIMER:
		return BCM_6345_TIMER_BASE;
	case RSET_WDT:
		return BCM_6345_WDT_BASE;
	case RSET_UART0:
		return BCM_6345_UART0_BASE;
	case RSET_UART1:
		return BCM_6345_UART1_BASE;
	case RSET_GPIO:
		return BCM_6345_GPIO_BASE;
	case RSET_SPI:
		return BCM_6345_SPI_BASE;
	case RSET_UDC0:
		return BCM_6345_UDC0_BASE;
	case RSET_OHCI0:
		return BCM_6345_OHCI0_BASE;
	case RSET_OHCI_PRIV:
		return BCM_6345_OHCI_PRIV_BASE;
	case RSET_USBH_PRIV:
		return BCM_6345_USBH_PRIV_BASE;
	case RSET_MPI:
		return BCM_6345_MPI_BASE;
	case RSET_PCMCIA:
		return BCM_6345_PCMCIA_BASE;
	case RSET_DSL:
		return BCM_6345_DSL_BASE;
	case RSET_ENET0:
		return BCM_6345_ENET0_BASE;
	case RSET_ENET1:
		return BCM_6345_ENET1_BASE;
	case RSET_ENETDMA:
		return BCM_6345_ENETDMA_BASE;
	case RSET_EHCI0:
		return BCM_6345_EHCI0_BASE;
	case RSET_SDRAM:
		return BCM_6345_SDRAM_BASE;
	case RSET_MEMC:
		return BCM_6345_MEMC_BASE;
	case RSET_DDR:
		return BCM_6345_DDR_BASE;
	}
#endif
#ifdef CONFIG_BCM63XX_CPU_6348
	switch (set) {
	case RSET_DSL_LMEM:
		return BCM_6348_DSL_LMEM_BASE;
	case RSET_PERF:
		return BCM_6348_PERF_BASE;
	case RSET_TIMER:
		return BCM_6348_TIMER_BASE;
	case RSET_WDT:
		return BCM_6348_WDT_BASE;
	case RSET_UART0:
		return BCM_6348_UART0_BASE;
	case RSET_UART1:
		return BCM_6348_UART1_BASE;
	case RSET_GPIO:
		return BCM_6348_GPIO_BASE;
	case RSET_SPI:
		return BCM_6348_SPI_BASE;
	case RSET_UDC0:
		return BCM_6348_UDC0_BASE;
	case RSET_OHCI0:
		return BCM_6348_OHCI0_BASE;
	case RSET_OHCI_PRIV:
		return BCM_6348_OHCI_PRIV_BASE;
	case RSET_USBH_PRIV:
		return BCM_6348_USBH_PRIV_BASE;
	case RSET_MPI:
		return BCM_6348_MPI_BASE;
	case RSET_PCMCIA:
		return BCM_6348_PCMCIA_BASE;
	case RSET_DSL:
		return BCM_6348_DSL_BASE;
	case RSET_ENET0:
		return BCM_6348_ENET0_BASE;
	case RSET_ENET1:
		return BCM_6348_ENET1_BASE;
	case RSET_ENETDMA:
		return BCM_6348_ENETDMA_BASE;
	case RSET_EHCI0:
		return BCM_6348_EHCI0_BASE;
	case RSET_SDRAM:
		return BCM_6348_SDRAM_BASE;
	case RSET_MEMC:
		return BCM_6348_MEMC_BASE;
	case RSET_DDR:
		return BCM_6348_DDR_BASE;
	}
#endif
#ifdef CONFIG_BCM63XX_CPU_6358
	switch (set) {
	case RSET_DSL_LMEM:
		return BCM_6358_DSL_LMEM_BASE;
	case RSET_PERF:
		return BCM_6358_PERF_BASE;
	case RSET_TIMER:
		return BCM_6358_TIMER_BASE;
	case RSET_WDT:
		return BCM_6358_WDT_BASE;
	case RSET_UART0:
		return BCM_6358_UART0_BASE;
	case RSET_UART1:
		return BCM_6358_UART1_BASE;
	case RSET_GPIO:
		return BCM_6358_GPIO_BASE;
	case RSET_SPI:
		return BCM_6358_SPI_BASE;
	case RSET_UDC0:
		return BCM_6358_UDC0_BASE;
	case RSET_OHCI0:
		return BCM_6358_OHCI0_BASE;
	case RSET_OHCI_PRIV:
		return BCM_6358_OHCI_PRIV_BASE;
	case RSET_USBH_PRIV:
		return BCM_6358_USBH_PRIV_BASE;
	case RSET_MPI:
		return BCM_6358_MPI_BASE;
	case RSET_PCMCIA:
		return BCM_6358_PCMCIA_BASE;
	case RSET_ENET0:
		return BCM_6358_ENET0_BASE;
	case RSET_ENET1:
		return BCM_6358_ENET1_BASE;
	case RSET_ENETDMA:
		return BCM_6358_ENETDMA_BASE;
	case RSET_DSL:
		return BCM_6358_DSL_BASE;
	case RSET_EHCI0:
		return BCM_6358_EHCI0_BASE;
	case RSET_SDRAM:
		return BCM_6358_SDRAM_BASE;
	case RSET_MEMC:
		return BCM_6358_MEMC_BASE;
	case RSET_DDR:
		return BCM_6358_DDR_BASE;
	case RSET_TDM:
		return BCM_6358_TDM_BASE;
	case RSET_TDM_DMA:
		return BCM_6358_TDM_DMA_BASE;
	case RSET_ATM:
		return BCM_6358_ATM_BASE;
	case RSET_USB_CTL:
		return BCM_6358_USB_CTL_BASE;
	default:
		return 0;
	}
#endif
#ifdef CONFIG_BCM63XX_CPU_6362
	switch (set) {
	case RSET_PERF:
		return BCM_6362_PERF_BASE;
	case RSET_TIMER:
		return BCM_6362_TIMER_BASE;
	case RSET_WDT:
		return BCM_6362_WDT_BASE;
	case RSET_UART0:
		return BCM_6362_UART0_BASE;
	case RSET_GPIO:
		return BCM_6362_GPIO_BASE;
	case RSET_SPI:
		return BCM_6362_SPI_BASE;
	case RSET_HSSPI:
		return BCM_6362_HSSPI_BASE;
	case RSET_OHCI0:
		return BCM_6362_OHCI0_BASE;
	case RSET_OHCI_PRIV:
		return BCM_6362_OHCI_PRIV_BASE;
	case RSET_USBH_PRIV:
		return BCM_6362_USBH_PRIV_BASE;
	case RSET_EHCI0:
		return BCM_6362_EHCI0_BASE;
	case RSET_DDR:
		return BCM_6362_DDR_BASE;
	case RSET_MISC:
		return BCM_6362_MISC_BASE;
	case RSET_TDM:
		return BCM_6362_TDM_BASE;
	case RSET_TDM_DMA:
		return BCM_6362_TDM_DMA_BASE;
	case RSET_TDM_DMA_CH1:
		return BCM_6362_TDM_DMA_CH1_BASE;
	case RSET_TDM_DMA_CH2:
		return BCM_6362_TDM_DMA_CH2_BASE;
	default:
		return 0;
	}
#endif
#endif
	/* unreached */
	return 0;
}

/*
 * IRQ number changes across CPU too
 */
enum bcm63xx_irq {
	IRQ_TIMER = 0,
	IRQ_SPI,
	IRQ_UART0,
	IRQ_UART1,
	IRQ_HSSPI,
	IRQ_DSL,
	IRQ_UDC0,
	IRQ_ENET0,
	IRQ_ENET1,
	IRQ_ENET_PHY,
	IRQ_OHCI0,
	IRQ_EHCI0,
	IRQ_PCMCIA0,
	IRQ_ENET0_RXDMA,
	IRQ_ENET0_TXDMA,
	IRQ_ENET1_RXDMA,
	IRQ_ENET1_TXDMA,
	IRQ_PCI,
	IRQ_PCMCIA,
	IRQ_TDM,
	IRQ_RING_OSC,
	IRQ_WLAN_GPIO,
	IRQ_WLAN,
	IRQ_IPSEC,
	IRQ_USBS,
	IRQ_NAND_FLASH,
	IRQ_EPHY,
	IRQ_EPHY_ENERGY_0,
	IRQ_EPHY_ENERGY_1,
	IRQ_EPHY_ENERGY_2,
	IRQ_EPHY_ENERGY_3,
	IRQ_USB_CNTL_RX_DMA,
	IRQ_USB_CNTL_TX_DMA,
	IRQ_USB_BULK_RX_DMA,
	IRQ_USB_BULK_TX_DMA,
	IRQ_USB_ISO_RX_DMA,
	IRQ_USB_ISO_TX_DMA,
	IRQ_IPSEC_DMA_0,
	IRQ_IPSEC_DMA_1,
	IRQ_XDSL,
	IRQ_FAP,
	IRQ_PCIE_RC,
	IRQ_PCIE_EP,
};

/*
 * 6338 irqs
 */
#define BCM_6338_TIMER_IRQ		(IRQ_INTERNAL_BASE + 0)
#define BCM_6338_SPI_IRQ		(IRQ_INTERNAL_BASE + 1)
#define BCM_6338_UART0_IRQ		(IRQ_INTERNAL_BASE + 2)
#define BCM_6338_DG_IRQ			(IRQ_INTERNAL_BASE + 4)
#define BCM_6338_DSL_IRQ		(IRQ_INTERNAL_BASE + 5)
#define BCM_6338_ATM_IRQ		(IRQ_INTERNAL_BASE + 6)
#define BCM_6338_UDC0_IRQ		(IRQ_INTERNAL_BASE + 7)
#define BCM_6338_ENET0_IRQ		(IRQ_INTERNAL_BASE + 8)
#define BCM_6338_ENET_PHY_IRQ		(IRQ_INTERNAL_BASE + 9)
#define BCM_6338_SDRAM_IRQ		(IRQ_INTERNAL_BASE + 10)
#define BCM_6338_USB_CNTL_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 11)
#define BCM_6338_USB_CNTL_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 12)
#define BCM_6338_USB_BULK_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13)
#define BCM_6338_USB_BULK_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 14)
#define BCM_6338_ENET0_RXDMA_IRQ	(IRQ_INTERNAL_BASE + 15)
#define BCM_6338_ENET0_TXDMA_IRQ	(IRQ_INTERNAL_BASE + 16)
#define BCM_6338_SDIO_IRQ		(IRQ_INTERNAL_BASE + 17)

/*
 * 6345 irqs
 */
#define BCM_6345_TIMER_IRQ		(IRQ_INTERNAL_BASE + 0)
#define BCM_6345_UART0_IRQ		(IRQ_INTERNAL_BASE + 2)
#define BCM_6345_DSL_IRQ		(IRQ_INTERNAL_BASE + 3)
#define BCM_6345_ATM_IRQ		(IRQ_INTERNAL_BASE + 4)
#define BCM_6345_UDC0_IRQ		(IRQ_INTERNAL_BASE + 5)
#define BCM_6345_ENET0_IRQ		(IRQ_INTERNAL_BASE + 8)
#define BCM_6345_ENET_PHY_IRQ		(IRQ_INTERNAL_BASE + 12)
#define BCM_6345_ENET0_RXDMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 1)
#define BCM_6345_ENET0_TXDMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 2)
#define BCM_6345_EBI_RX_IRQ		(IRQ_INTERNAL_BASE + 13 + 5)
#define BCM_6345_EBI_TX_IRQ		(IRQ_INTERNAL_BASE + 13 + 6)
#define BCM_6345_RESERVED_RX_IRQ	(IRQ_INTERNAL_BASE + 13 + 9)
#define BCM_6345_RESERVED_TX_IRQ	(IRQ_INTERNAL_BASE + 13 + 10)
#define BCM_6345_USB_BULK_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 13)
#define BCM_6345_USB_BULK_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 14)
#define BCM_6345_USB_CNTL_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 15)
#define BCM_6345_USB_CNTL_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 16)
#define BCM_6345_USB_ISO_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 17)
#define BCM_6345_USB_ISO_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 13 + 18)

/*
 * 6348 irqs
 */
#define BCM_6348_TIMER_IRQ		(IRQ_INTERNAL_BASE + 0)
#define BCM_6348_SPI_IRQ		(IRQ_INTERNAL_BASE + 1)
#define BCM_6348_UART0_IRQ		(IRQ_INTERNAL_BASE + 2)
#define BCM_6348_DSL_IRQ		(IRQ_INTERNAL_BASE + 4)
#define BCM_6348_UDC0_IRQ		(IRQ_INTERNAL_BASE + 6)
#define BCM_6348_ENET1_IRQ		(IRQ_INTERNAL_BASE + 7)
#define BCM_6348_ENET0_IRQ		(IRQ_INTERNAL_BASE + 8)
#define BCM_6348_ENET_PHY_IRQ		(IRQ_INTERNAL_BASE + 9)
#define BCM_6348_OHCI0_IRQ		(IRQ_INTERNAL_BASE + 12)
#define BCM_6348_USB_CNTL_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 14)
#define BCM_6348_USB_CNTL_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 15)
#define BCM_6348_USB_BULK_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 16)
#define BCM_6348_USB_BULK_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 17)
#define BCM_6348_USB_ISO_RX_DMA_IRQ	(IRQ_INTERNAL_BASE + 18)
#define BCM_6348_USB_ISO_TX_DMA_IRQ	(IRQ_INTERNAL_BASE + 19)
#define BCM_6348_ENET0_RXDMA_IRQ	(IRQ_INTERNAL_BASE + 20)
#define BCM_6348_ENET0_TXDMA_IRQ	(IRQ_INTERNAL_BASE + 21)
#define BCM_6348_ENET1_RXDMA_IRQ	(IRQ_INTERNAL_BASE + 22)
#define BCM_6348_ENET1_TXDMA_IRQ	(IRQ_INTERNAL_BASE + 23)
#define BCM_6348_PCMCIA_IRQ		(IRQ_INTERNAL_BASE + 24)
#define BCM_6348_PCI_IRQ		(IRQ_INTERNAL_BASE + 24)

/*
 * 6358 irqs
 */
#define BCM_6358_TIMER_IRQ		(IRQ_INTERNAL_BASE + 0)
#define BCM_6358_SPI_IRQ		(IRQ_INTERNAL_BASE + 1)
#define BCM_6358_UART0_IRQ		(IRQ_INTERNAL_BASE + 2)
#define BCM_6358_UART1_IRQ		(IRQ_INTERNAL_BASE + 3)
#define BCM_6358_OHCI0_IRQ		(IRQ_INTERNAL_BASE + 5)
#define BCM_6358_ENET1_IRQ		(IRQ_INTERNAL_BASE + 6)
#define BCM_6358_ENET0_IRQ		(IRQ_INTERNAL_BASE + 8)
#define BCM_6358_ENET_PHY_IRQ		(IRQ_INTERNAL_BASE + 9)
#define BCM_6358_EHCI0_IRQ		(IRQ_INTERNAL_BASE + 10)
#define BCM_6358_ENET0_RXDMA_IRQ	(IRQ_INTERNAL_BASE + 15)
#define BCM_6358_ENET0_TXDMA_IRQ	(IRQ_INTERNAL_BASE + 16)
#define BCM_6358_ENET1_RXDMA_IRQ	(IRQ_INTERNAL_BASE + 17)
#define BCM_6358_ENET1_TXDMA_IRQ	(IRQ_INTERNAL_BASE + 18)
#define BCM_6358_DSL_IRQ		(IRQ_INTERNAL_BASE + 29)
#define BCM_6358_PCI_IRQ		(IRQ_INTERNAL_BASE + 31)
#define BCM_6358_PCMCIA_IRQ		(IRQ_INTERNAL_BASE + 24)

/*
 * 6362 irqs
 */
#define BCM_6362_TIMER_IRQ		(IRQ_INTERNAL_BASE + 0)
#define BCM_6362_RING_OSC_IRQ           (IRQ_INTERNAL_BASE + 1)
#define BCM_6362_SPI_IRQ		(IRQ_INTERNAL_BASE + 2)
#define BCM_6362_UART0_IRQ		(IRQ_INTERNAL_BASE + 3)
#define BCM_6362_UART1_IRQ		(IRQ_INTERNAL_BASE + 4)
#define BCM_6362_HSSPI_IRQ		(IRQ_INTERNAL_BASE + 5)
#define BCM_6362_WLAN_GPIO_IRQ          (IRQ_INTERNAL_BASE + 6)
#define BCM_6362_WLAN_IRQ               (IRQ_INTERNAL_BASE + 7)
#define BCM_6362_IPSEC_IRQ              (IRQ_INTERNAL_BASE + 8)
#define BCM_6362_OHCI0_IRQ		(IRQ_INTERNAL_BASE + 9)
#define BCM_6362_EHCI0_IRQ		(IRQ_INTERNAL_BASE + 10)
#define BCM_6362_USBS_IRQ               (IRQ_INTERNAL_BASE + 11)
#define BCM_6362_NAND_FLASH_IRQ         (IRQ_INTERNAL_BASE + 12)
#define BCM_6362_TDM_IRQ                (IRQ_INTERNAL_BASE + 13)
#define BCM_6362_EPHY_IRQ               (IRQ_INTERNAL_BASE + 14)
#define BCM_6362_DG_IRQ                 (IRQ_INTERNAL_BASE + 15)
#define BCM_6362_EPHY_ENERGY_0_IRQ      (IRQ_INTERNAL_BASE + 16)
#define BCM_6362_EPHY_ENERGY_1_IRQ      (IRQ_INTERNAL_BASE + 17)
#define BCM_6362_EPHY_ENERGY_2_IRQ      (IRQ_INTERNAL_BASE + 18)
#define BCM_6362_EPHY_ENERGY_3_IRQ      (IRQ_INTERNAL_BASE + 19)
#define BCM_6362_USB_CNTL_RX_DMA_IRQ    (IRQ_INTERNAL_BASE + 20)
#define BCM_6362_USB_CNTL_TX_DMA_IRQ    (IRQ_INTERNAL_BASE + 21)
#define BCM_6362_USB_BULK_RX_DMA_IRQ    (IRQ_INTERNAL_BASE + 22)
#define BCM_6362_USB_BULK_TX_DMA_IRQ    (IRQ_INTERNAL_BASE + 23)
#define BCM_6362_USB_ISO_RX_DMA_IRQ     (IRQ_INTERNAL_BASE + 24)
#define BCM_6362_USB_ISO_TX_DMA_IRQ     (IRQ_INTERNAL_BASE + 25)
#define BCM_6362_IPSEC_DMA_0_IRQ        (IRQ_INTERNAL_BASE + 26)
#define BCM_6362_IPSEC_DMA_1_IRQ        (IRQ_INTERNAL_BASE + 27)
#define BCM_6362_XDSL_IRQ               (IRQ_INTERNAL_BASE + 28)
#define BCM_6362_FAP_IRQ                (IRQ_INTERNAL_BASE + 29)
#define BCM_6362_PCIE_RC_IRQ            (IRQ_INTERNAL_BASE + 30)
#define BCM_6362_PCIE_EP_IRQ            (IRQ_INTERNAL_BASE + 31)

extern const int *bcm63xx_irqs;

static inline int bcm63xx_get_irq_number(enum bcm63xx_irq irq)
{
	return bcm63xx_irqs[irq];
}

/*
 * Coprocessor 0 CMT Local Register
*/
#define CP0_CMT_TPID                (0x1 << 31)

/*
 * return installed memory size
 */
unsigned int bcm63xx_get_memory_size(void);

#endif /* !BCM63XX_CPU_H_ */
