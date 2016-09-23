/*
 * ping.c
 *
 * Copyright 2007 Anthony VIALLARD <anthony.viallard@efixo.com>
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
 * $Id: uping.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include "ping.h"
#include <stdlib.h>

int nbd_ping_start(int *id, const char *source, const char *hostname,
		   unsigned int count)
{
	char buf[8];
	int err;

	snprintf(buf, sizeof(buf), "%u", count);

	err = nbd_get(buf, sizeof(buf), "uping", "start", source,
		      hostname, buf);

	if (err)
		return err;

	*id = strtol(buf, NULL, 10);
	return err;
}

extern int nbd_ping_stop(int id)
{
	char str_id[8];
	int res_return;

	snprintf(str_id, sizeof(str_id), "%d", id);

	return nbd_get(&res_return, sizeof(int), "uping", "stop", str_id);
}

extern int nbd_ping_status(int id, nbd_ping_status_t * ping_status)
{
	char str_id[8];

	snprintf(str_id, sizeof(str_id), "%d", id);

	return nbd_get(ping_status, sizeof(*ping_status), "uping",
		       "status", str_id);
}
