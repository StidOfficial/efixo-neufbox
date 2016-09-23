/*
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

#ifndef LIBNBD_TRACEROUTE_H
#define LIBNBD_TRACEROUTE_H

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "core.h"

#include "plugins/traceroute.h"

extern int nbd_traceroute_start(int *, const char *, const char *);
extern int nbd_traceroute_stop(int);
extern int nbd_traceroute_hop_count(int, int *);
extern int nbd_traceroute_get(int, struct tr_result *);
extern int nbd_traceroute_get_hop(int, struct tr_hop *, int);

#endif
