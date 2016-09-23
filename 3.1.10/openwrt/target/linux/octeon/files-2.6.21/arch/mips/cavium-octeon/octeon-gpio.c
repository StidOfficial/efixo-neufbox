/*!
 * \file octeon-gpio.c
 *
 * \brief Implement octeon gpio
 *
 * \author Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * 
 */

#include <linux/types.h>
#include <linux/init.h>
#include <asm/errno.h>
#include <asm/gpio.h>

#include <cvmx.h>
#include <cvmx-csr-addresses.h>
#include <cvmx-interrupt.h>
#include <cvmx-gpio.h>

#define IRQ_TRIGGER_HIGH   0
#define IRQ_TRIGGER_RISING 1

int gpio_to_irq(unsigned gpio)
{
	return gpio + CVMX_IRQ_GPIO0;
}

int irq_to_gpio(unsigned irq)
{
	return irq - CVMX_IRQ_GPIO0;
}

static int octeon_gpio_get_value(struct gpio_chip *chip, unsigned gpio)
{
	uint32_t mask = cvmx_gpio_read();

	return (mask >> gpio) & 0x01;
}

static void octeon_gpio_set_value(struct gpio_chip *chip, unsigned gpio,
				  int value)
{
	if (value) {
		cvmx_gpio_set(1ul << gpio);
	} else {
		cvmx_gpio_clear(1ul << gpio);
	}
}

static int octeon_gpio_direction_input(struct gpio_chip *chip, unsigned gpio)
{
	cvmx_gpio_bit_cfgx_t gpio_cfgx;

	gpio_cfgx.u64 = 0ul;
	gpio_cfgx.s.int_en = 1;
	gpio_cfgx.s.rx_xor = 1;
	gpio_cfgx.s.int_type = IRQ_TRIGGER_RISING;

	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(gpio), gpio_cfgx.u64);

	return 0;
}

static int octeon_gpio_direction_output(struct gpio_chip *chip, unsigned gpio,
					int value)
{
	cvmx_gpio_bit_cfgx_t gpio_cfgx;

	gpio_cfgx.u64 = 0ul;
	gpio_cfgx.s.tx_oe = 1;

	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(gpio), gpio_cfgx.u64);

	/* octeon_gpio_set_value(chip, gpio, value); */

	return 0;
}

static struct gpio_chip octeon_gpio_chip = {
	.label = "octeon-cn5020",
	.direction_input = octeon_gpio_direction_input,
	.direction_output = octeon_gpio_direction_output,
	.get = octeon_gpio_get_value,
	.set = octeon_gpio_set_value,
	.base = 0,
	.ngpio = 24,
};

int __init octeon_gpio_init(void)
{
	/* Register our GPIO chip */
	gpiochip_add(&octeon_gpio_chip);

	return 0;
}

arch_initcall(octeon_gpio_init);
