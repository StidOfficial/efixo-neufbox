/*
 * nat.c
 *
 * Copyright 2007 Evangelina LOLIVIER <evangelina.lolivier@efixo.com>
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
 * $Id: nat.c 21341 2011-08-31 09:38:17Z slr $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "nvram.h"
#include "nat.h"

int nbd_nat_upnp_list(char **buf, size_t * len)
{
	return nbd_get_new(buf, len, "nat", "upnp_list");
}

unsigned int nbd_nat_upnp_count(void)
{
	unsigned int count = 0;

	nbd_get(&count, sizeof(unsigned int), "nat", "upnp_count");

	return count;
}

int nbd_nat_add(const char *rulename, const char *proto, const char *ext_port,
		const char *dst_ip, const char *dst_port, const char *activated)
{
	return nbd_set("nat", "add", rulename, proto, ext_port, dst_ip,
		       dst_port, activated);
}

int nbd_nat_del_by_index(unsigned int idx)
{
	char buf[8];

	snprintf(buf, sizeof(buf), "%d", idx);

	return nbd_set("nat", "del", buf);
}

int nbd_nat_active(unsigned int idx, const char *activation)
{
	char str_idx[8];

	snprintf(str_idx, sizeof(str_idx), "%d", idx);

	return nbd_set("nat", "active", str_idx, activation);
}

int nbd_nat_dmz_setup(void)
{
	return nbd_set("nat", "dmz_setup");
}

int nbd_nat_sipalg(const char *target_state)
{
	return nbd_set("nat", "sipalg", target_state);
}
