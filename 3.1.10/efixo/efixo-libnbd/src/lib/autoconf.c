/*
 * \file autoconf.c
 *
 * \note Copyright 2007 Arnaud REBILLOUT <arnaud.rebillout@efixo.com>
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
 * $Id: autoconf.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <string.h>
#include <stdlib.h>

#include "core.h"
#include "autoconf.h"

int nbd_autoconf_start(void)
{
	return nbd_set("autoconf", "start");
}

int nbd_autoconf_stop(void)
{
	return nbd_set("autoconf", "stop");
}

int nbd_autoconf_get(char const *key, char *data, size_t len)
{
	return nbd_get(data, len, "autoconf", "get", key);
}

int nbd_autoconf_set(char const *key, char const *data)
{
	return nbd_set("autoconf", "set", key, data);
}

int nbd_autoconf_list(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "autoconf", "list", list);
}

int nbd_autoconf_list_long(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "autoconf", "list_long", list);
}

int nbd_autoconf_list_count(char const *list)
{
	char buf[16];

	if (nbd_get(buf, sizeof(buf), "autoconf", "list_count", list) < 0)
		return -1;

	return strtol(buf, NULL, 10);
}
