/*
 * nvram.c
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
 * $Id: nvram.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "core.h"
#include "nvram.h"
#include "status.h"

int nbd_system_config_get(char const *key, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "get", key);
}

int nbd_user_config_get(char const *key, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "get", key);
}

int nbd_system_config_set(char const *key, char const *data)
{
	return nbd_set("nvram", "set", key, data);
}

int nbd_user_config_set(char const *key, char const *data)
{
	return nbd_set("nvram", "set", key, data);
}

int nbd_user_config_add(char const *key, char const *data)
{
	return nbd_set("nvram", "add", key, data);
}

int nbd_user_config_del(char const *key)
{
	return nbd_set("nvram", "del", key);
}

int nbd_system_config_list(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "list", list);
}

int nbd_user_config_list(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "list", list);
}

int nbd_system_config_list_long(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "list_long", list);
}

int nbd_user_config_list_long(char const *list, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "list_long", list);
}

int nbd_user_config_list_flush(char const *list)
{
	return nbd_set("nvram", "list_flush", list);
}

int nbd_user_config_list_contains(char const *list, char const *key)
{
	return nbd_set("nvram", "list_contain", list, key);
}

int nbd_system_config_list_count(char const *list)
{
	char buf[16];

	if (nbd_get(buf, sizeof(buf), "nvram", "list_count", list) < 0)
		return -1;

	return strtol(buf, NULL, 10);
}

int nbd_user_config_list_count(char const *list)
{
	char buf[16];

	if (nbd_get(buf, sizeof(buf), "nvram", "list_count", list) < 0) {
		return -1;
	}

	return strtol(buf, NULL, 10);
}

int nbd_system_config_commit(void)
{
	return nbd_set("nvram", "commit", "system");
}

int nbd_user_config_commit(void)
{
	return nbd_set("nvram", "commit", "user");
}

int nbd_system_config_erase(void)
{
	return nbd_set("nvram", "erase", "system");
}

int nbd_user_config_erase(void)
{
	return nbd_set("nvram", "erase", "user");
}

int nbd_system_config_export(char const *file)
{
	return nbd_set("nvram", "export", "system", file);
}

int nbd_user_config_export(char const *file)
{
	return nbd_set("nvram", "export", "user", file);
}

int nbd_system_config_import(char const *file)
{
	return nbd_set("nvram", "import", "system", file);
}

int nbd_user_config_import(char const *file)
{
	return nbd_set("nvram", "import", "user", file);
}

int nbd_system_config_xml(const char *key, char **xml, size_t * len)
{
	return nbd_get_new(xml, len, "nvram", "xml", key);
}

int nbd_user_config_xml(const char *key, char **xml, size_t * len)
{
	return nbd_get_new(xml, len, "nvram", "xml", key);
}

/* -- */

int nbd_nv_get(char const *key, char *data, size_t len)
{
	return nbd_get(data, len, "nvram", "get", key);
}

int nbd_nv_set(char const *key, char const *data)
{
	return nbd_set("nvram", "set", key, data);
}

int nbd_nv_commit(char const *xml)
{
	return nbd_set("nvram", "commit", xml);
}

unsigned int nbd_user_config_cursor_new(void)
{
	char buf[16];

	if (nbd_get(buf, sizeof(buf), "nvram", "cursor", "new") < 0)
		return 0;

	return strtol(buf, NULL, 10);
}

int nbd_user_config_cursor_close(unsigned int cid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%u", cid);

	return nbd_set("nvram", "cursor", "close", buf);
}

int nbd_user_config_cursor_revert(unsigned int cid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%u", cid);

	return nbd_set("nvram", "cursor", "revert", buf);
}

int nbd_user_config_cursor_commit(unsigned int cid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%u", cid);

	return nbd_set("nvram", "cursor", "commit", buf);
}

int nbd_user_config_cset(unsigned int cid, char const *key, char const *data)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%u", cid);

	return nbd_set("nvram", "cset", buf, key, data);
}

int nbd_system_xml_privateport(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "nvram", "privateport");
}
