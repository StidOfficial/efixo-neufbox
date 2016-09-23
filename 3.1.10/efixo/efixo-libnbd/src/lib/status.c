/*
 * status.c
 *
 * Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: status.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <string.h>
#include <stdlib.h>

#include "core.h"
#include "status.h"

int nbd_status_get(char const *key, char *data, size_t len)
{
	return nbd_get(data, len, "status", "get", key);
}

int nbd_status_set(char const *key, char const *data)
{
	return nbd_set("status", "set", key, data);
}

int nbd_status_add(char const *key, char const *data)
{
	return nbd_set("status", "add", key, data);
}

int nbd_status_del(char const *key)
{
	return nbd_set("status", "del", key);
}

int nbd_status_list(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "status", "list", list);
}

int nbd_status_list_long(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "status", "list_long", list);
}

int nbd_status_list_contains(const char *list, const char *key)
{
	return nbd_set("status", "list_contain", list, key);
}

int nbd_status_list_flush(const char *list)
{
	return nbd_set("status", "list_flush", list);
}

int nbd_status_list_count(const char *list)
{
	char buf[16];

	if (nbd_get(buf, sizeof(buf), "status", "list_count", list) < 0)
		return -1;

	return strtol(buf, NULL, 10);
}

int nbd_status_show(char *data, size_t len)
{
	return nbd_get(data, len, "status", "show");
}

int nbd_status_xml(const char *key, char **xml, size_t * len)
{
	return nbd_get_new(xml, len, "status", "xml", key);
}
