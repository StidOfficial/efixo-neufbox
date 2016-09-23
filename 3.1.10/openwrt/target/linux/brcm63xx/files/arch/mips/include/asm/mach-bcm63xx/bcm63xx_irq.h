#ifndef BCM63XX_IRQ_H_
#define BCM63XX_IRQ_H_

#include <bcm63xx_cpu.h>

#define IRQ_MIPS_BASE			0
#define IRQ_INTERNAL_BASE		8

static inline unsigned long bcm63xx_irq_ext_base(void)
{
	switch (bcm63xx_get_cpu_id()) {
		case BCM6362_CPU_ID:
			return IRQ_MIPS_BASE + 48;
		case BCM6358_CPU_ID:
			return IRQ_MIPS_BASE + 33;
		default:
			return IRQ_MIPS_BASE + 3;
	}
}

#define IRQ_EXT_0			(bcm63xx_irq_ext_base() + 0)
#define IRQ_EXT_1			(bcm63xx_irq_ext_base() + 1)
#define IRQ_EXT_2			(bcm63xx_irq_ext_base() + 2)
#define IRQ_EXT_3			(bcm63xx_irq_ext_base() + 3)

#define INTERRUPT_ID_SOFTWARE_0		0
#define INTERRUPT_ID_SOFTWARE_1		1

#endif /* ! BCM63XX_IRQ_H_ */
