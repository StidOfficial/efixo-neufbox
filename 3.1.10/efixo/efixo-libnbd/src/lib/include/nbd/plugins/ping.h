/*!
 * ping.h
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
 * $Id: ping.h 18043 2010-10-11 09:13:32Z mgo $
 */

#ifndef _PLUGIN_PING_H_
#define _PLUGIN_PING_H_

#include <stdbool.h>

struct ping_status {
	bool used;
	bool done;
	/* number of packets sent */
	unsigned sent;
	/* number of packets received */
	unsigned received;
	/* average round trip time */
	float avgrtt;
};

#endif
