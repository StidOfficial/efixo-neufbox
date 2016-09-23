/*!
 * \file leds.c
 *
 * \brief  Implement leds interface
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
 * $Id: leds.c 17865 2010-09-30 14:45:34Z mgo $
 */

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include "leds.h"

#ifndef NB6
static int leds_ioctl(unsigned int cmd, struct leds_dev_ioctl_struct *led_ioctl)
{
	int fd;

	fd = open("/dev/leds", O_RDWR);
	if (fd < 0) {
		syslog(LOG_PERROR, "open(%s, O_RDWR): %s ", "/dev/leds",
		       strerror(errno));
		return 1;
	}

	if (ioctl(fd, cmd, led_ioctl) < 0) {
		syslog(LOG_PERROR, "ioctl(%d, %d, %p): %s ", fd, cmd,
		       led_ioctl, strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);

	return 0;
}

enum led_mode nbd_leds_set_mode(enum led_mode mode)
{
	struct leds_dev_ioctl_struct leds_dev_ioctl;

	leds_dev_ioctl.mode = mode;

	leds_ioctl(LED_IOCTL_SET_MODE, &leds_dev_ioctl);

	return leds_dev_ioctl.mode;
}

enum led_mode nbd_leds_get_mode(void)
{
	struct leds_dev_ioctl_struct leds_dev_ioctl;

	if (leds_ioctl(LED_IOCTL_GET_MODE, &leds_dev_ioctl) < 0)
		return -1;

	return leds_dev_ioctl.mode;
}

enum led_state nbd_leds_state(enum led_id id)
{
	struct leds_dev_ioctl_struct leds_dev_ioctl;

	leds_dev_ioctl.id = id;
	leds_ioctl(LED_IOCTL_GET_LED, &leds_dev_ioctl);

	return leds_dev_ioctl.state;
}

#else

enum led_state nbd_leds_state(enum led_id id)
{
	if (id == led_id_wan)
		return led_state_on;
	else
		return led_state_off;
}

enum led_mode nbd_leds_set_mode(enum led_mode mode)
{
	enum led_mode old = nbd_leds_get_mode();
	char const *p;
	int fd;

	switch (mode) {
	case led_mode_disable:
		p = "disable";
		break;
	case led_mode_control:
		p = "control";
		break;
	case led_mode_downloading:
		p = "downloading";
		break;
	case led_mode_burning:
		p = "burning";
		break;
	default:
		p = NULL;
		return old;
	}

	fd = open("/sys/class/hwmon/hwmon0/device/leds_mode", O_WRONLY);
	if (fd < 0) {
		syslog(LOG_PERROR, "%s() %s\n", __func__, "open()");
		return old;
	}

	write(fd, p, strlen(p));
	close(fd);

	return old;
}

enum led_mode nbd_leds_get_mode(void)
{
	enum led_mode mode = led_mode_control;
	char buf[128];
	int fd;

	fd = open("/sys/class/hwmon/hwmon0/device/leds_mode", O_RDONLY);
	if (fd < 0) {
		syslog(LOG_PERROR, "%s() %s\n", __func__, "open()");
		return mode;
	}

	read(fd, buf, sizeof(buf));
	close(fd);

	return mode;
}

#endif

int nbd_leds_brightness(enum led_state status)
{
	return nbd_leds_set_mode((status == led_state_on) ?
				 led_mode_control : led_mode_disable);
}
