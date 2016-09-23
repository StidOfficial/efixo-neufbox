/*
 * firewall.c
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "nvram.h"
#include "nat.h"
#include "firewall.h"

int nbd_firewall_add(const char *rulename, const char *proto,
		     const char *direction, const char *dstip,
		     const char *dstport, const char *srcip,
		     const char *srcport, const char *policy)
{
	return nbd_set("firewall", "add", rulename, proto, direction, dstip,
		       dstport, srcip, srcport, policy);
}

/**
 * TODO
 **/
int nbd_firewall_del_by_index(unsigned int idx)
{
	char buf[8];

	snprintf(buf, sizeof(buf), "%d", idx);
	return nbd_set("firewall", "del", buf);
}
