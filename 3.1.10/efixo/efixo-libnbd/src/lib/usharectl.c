/*
 * usharectl.c
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
 * $Id: usharectl.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include "usharectl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "nvram.h"

int nbd_usharectl_start(void)
{
	return nbd_set("usharectl", "start");
}

int nbd_usharectl_stop(void)
{
	return nbd_set("usharectl", "stop");
}

int nbd_usharectl_restart(void)
{
	return nbd_set("usharectl", "restart");
}

int nbd_usharectl_status(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "usharectl", "status");
}

int nbd_usharectl_set_mode(const char *mode)
{
	return nbd_set("usharectl", "set_mode", mode);
}

int nbd_usharectl_add_share(const char *uuid, const char *dir)
{
	return nbd_set("usharectl", "add_share", uuid, dir);
}

int nbd_usharectl_del_share(unsigned int idx)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%u", idx);

	return nbd_set("usharectl", "del_share", buf);
}
