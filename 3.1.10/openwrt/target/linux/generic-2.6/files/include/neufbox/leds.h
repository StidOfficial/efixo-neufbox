/*
 *      neufbox/leds.h
 *
 *      Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _NEUFBOX_LEDS_H_
#define _NEUFBOX_LEDS_H_

#include <linux/types.h>

#if defined(CONFIG_BOARD_NEUFBOX6) || defined(NB6)

enum led_mode {
	led_mode_disable,
	led_mode_boot,
	led_mode_boot_main,
	led_mode_boot_tftp,
	led_mode_boot_rescue,
	led_mode_login,
	led_mode_burning,
	led_mode_downloading,
	led_mode_wdt_temperature,
	led_mode_wdt_voltage,
	led_mode_panic,
	led_mode_control,
};

enum led_id {
	led_id_red1 = 0x10,
	led_id_red2,
	led_id_red3,
	led_id_green1,
	led_id_green2,
	led_id_green3,
	led_id_wan,
	led_id_voip,
	led_id_wlan,
};
#define led_id_tv led_id_green2

enum led_state {
	led_state_off = 0,
	led_state_half = 15,
	led_state_full = 31,
	led_state_on = led_state_full,
	led_state_slowblinks = 0x80 | led_state_full,
	led_state_blinks = led_state_slowblinks,
};

#else /* NB4: NB5 */

enum led_mode {
	led_mode_disable,
	led_mode_control,
	led_mode_downloading,
	led_mode_burning,
	led_mode_panic,
	led_mode_demo,

	led_mode_last
};

enum led_id {
	led_id_wan,
	led_id_traffic,
	led_id_voip,
	led_id_tv,
	led_id_wlan,
	led_id_alarm,

	led_id_red,
	led_id_green,
	led_id_blue,

	led_id_last
};

enum led_state {
	led_state_unchanged,
	led_state_off,
	led_state_on,
	led_state_full = led_state_on,
	led_state_toggle,
	led_state_blinkonce,
	led_state_slowblinks,
	led_state_blinks,
};

/** led dev ioctl */

#define LED_IOCTL_MAGIC	'M'

struct leds_dev_ioctl_struct {
	enum led_mode mode;
	enum led_id id;
	enum led_state state;
};

#define LED_IOCTL_SET_MODE _IOW(LED_IOCTL_MAGIC, 0, struct leds_dev_ioctl_struct)
#define LED_IOCTL_GET_MODE _IOR(LED_IOCTL_MAGIC, 1, struct leds_dev_ioctl_struct)
#define LED_IOCTL_SET_LED  _IOW(LED_IOCTL_MAGIC, 2, struct leds_dev_ioctl_struct)
#define LED_IOCTL_GET_LED  _IOWR(LED_IOCTL_MAGIC, 3, struct leds_dev_ioctl_struct)

#endif

#ifdef __KERNEL__

void leds_mode(u8 mode);

void leds_config(u8 id, u8 level);

#endif				/* __KERNEL__ */

#endif				/* _NEUFBOX_LEDS_H_ */
