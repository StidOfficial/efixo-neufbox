/*
 * stb.c
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
 * $Id
 */

#include <string.h>
#include <stdlib.h>

#include "core.h"

/* nbd_stb_add
 *
 * @resume add STB
 */
int nbd_stb_add(char const *mac_addr, char const *ipaddr, char const *hostname)
{
	return nbd_set("stb", "add", mac_addr, ipaddr, hostname);
}

/* nbd_stb_add
 *
 * @resume this STB exist ?
 */
int nbd_stb_exist(char const *mac_addr, char const *ipaddr)
{
	return nbd_set("stb", "exist", mac_addr, ipaddr);
}

/* nbd_stb_list
 *
 * @resume count STB list
 */
int nbd_stb_list_count(void)
{
	char buf[16];

	if (nbd_get(buf, sizeof(buf), "stb", "list_count") < 0)
		return -1;

	return strtol(buf, NULL, 10);
}
