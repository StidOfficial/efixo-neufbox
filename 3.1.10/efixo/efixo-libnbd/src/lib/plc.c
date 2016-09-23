/*
 * sfp.c
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
 * $Id: plc.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include "plc.h"

#include <string.h>
#include <stdlib.h>

#include "core.h"

int nbd_plc_add(char const *macaddr, char const *hostname)
{
	return nbd_set("plc", "add", macaddr, hostname);
}

int nbd_plc_list(char *data, size_t len)
{
	return nbd_get(data, len, "plc", "list");
}
