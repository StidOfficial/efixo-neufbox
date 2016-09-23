/*
 * lan.h
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
 * $Id: lan.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef LIBNBD_LAN_H
#define LIBNBD_LAN_H

#include "plugins/lan.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* lan conf */
int nbd_lan_set_ipaddr(const char *ip, const char *netmask);

/* dhcp */
int nbd_dhcpd_static_init(void);
int nbd_dhcpd_add_static_ip(const char *ip, const char *mac);
int nbd_dhcpd_del_static_ip(unsigned int idx);

/* dns hosts */
int nbd_dnshosts_add(const char *ip, const char *hostname);
int nbd_dnshosts_del(unsigned int idx);

/* conversion tools */
int nbd_lan_mac2ip(char const *mac, char *ip, size_t len);
int nbd_lan_ip2mac(char const *ip, char *mac, size_t len);

/* stats */
int nbd_lan_stats(char **xml, size_t * size, const char *filter);
int nbd_lan_fullstats(char **xml, size_t * size, const char *filter);

/* misc */
int nbd_lan_status(char **xml, size_t * size);

int nbd_lan_topology_update(char const *macaddr, char const *ipaddr,
			    char const *hostname);

#endif
