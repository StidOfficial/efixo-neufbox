/*!
 * traceroute.h
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
 * $Id: traceroute.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _PLUGIN_TRACEROUTE_H_
#define _PLUGIN_TRACEROUTE_H_

#define TRACEROUTE_MAX_HOPS 30
#define TRACEROUTE_HOP_WAIT_TIME 5
#define IP_ADDR_SIZE 16
#define HOSTNAME_SIZE 257

struct tr_hop {
	char hostname[HOSTNAME_SIZE];
	char ip[IP_ADDR_SIZE];
	int status;
	float rtt[3];
};

struct tr_result {
	char dst_ip[IP_ADDR_SIZE];
	int finished;
	int ret;
	int hop_count;
	struct tr_hop hops[TRACEROUTE_MAX_HOPS];
};

struct item {
	int used;		/* struct used */
	int id;			/* id of traceroute */
	struct tr_result result;	/* traceroute result */
};

struct tr_list {
	int alloc_size;		/* number of struct item allocated */
	struct item items[1];
};

#endif
