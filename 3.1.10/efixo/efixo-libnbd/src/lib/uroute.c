/*
 * route.c
 *
 * Copyright 2007 Evangelina LOLIVIER <evangelina.lolivier@efixo.com>
 *           2008 Anthony VIALLARD <anthony.viallard@efixo.com>
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
 * $Id: uroute.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "core.h"

int nbd_uroute_add(char *dest, char *netmsk, char *gw)
{
	return nbd_set("uroute", "add", dest, netmsk, gw);
}

int nbd_uroute_del(int idx)
{
	char id[4];

	snprintf(id, sizeof(id), "%d", idx);

	return nbd_set("uroute", "del", id);
}
