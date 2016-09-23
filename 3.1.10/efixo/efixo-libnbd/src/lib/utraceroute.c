/*
 * traceroute.c
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
 * $Id: utraceroute.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include "traceroute.h"

int nbd_traceroute_start(int *id, const char *src, const char *hostname)
{
	return nbd_get(id, sizeof(int), "trcrte", "start", src, hostname);
}

int nbd_traceroute_stop(int id)
{
	char buf[8];

	snprintf(buf, sizeof(buf), "%d", id);

	return nbd_set("trcrte", "stop", buf);
}

int nbd_hop_count(int id, int *count)
{
	char buf[8];

	snprintf(buf, sizeof(buf), "%d", id);

	return nbd_get(count, sizeof(int), "trcrte", "hop_count", buf);
}

int nbd_traceroute_get(int id, struct tr_result *res)
{
	char buf[8];

	snprintf(buf, sizeof(buf), "%d", id);

	return nbd_get(res, sizeof(*res), "trcrte", "get", buf);
}

int nbd_traceroute_get_hop(int id, struct tr_hop *hop, int n)
{
	char buf[8];
	char buf1[8];

	snprintf(buf, sizeof(buf), "%d", id);
	snprintf(buf1, sizeof(buf1), "%d", n);

	return nbd_get(hop, sizeof(*hop), "trcrte", "get_hop", buf, buf1);
}
