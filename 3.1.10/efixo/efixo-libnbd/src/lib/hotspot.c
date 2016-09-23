/*
 * \file hotspot.c
 *
 * \note Copyright 2007 Arnaud REBILLOUT <arnaud.rebillout@efixo.com>
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
 * $Id: hotspot.c 19606 2011-03-02 10:12:30Z avd $
 */

#include <stdlib.h>

#include "core.h"
#include "hotspot.h"

int nbd_hotspot_start(void)
{
	return nbd_set("hotspot", "start");
}

int nbd_hotspot_stop(void)
{
	return nbd_set("hotspot", "stop");
}

int nbd_hotspot_restart(void)
{
	return nbd_set("hotspot", "restart");
}

int nbd_hotspot_ssid(char *buf, size_t buf_size)
{
	return nbd_get(buf, buf_size, "hotspot", "ssid");
}

int nbd_hotspot_client_add(char const *ipaddr, char const *macaddr)
{
	return nbd_set("hotspot", "client_add", ipaddr, macaddr);
}

int nbd_hotspot_client_del(char const *i)
{
	return nbd_set("hotspot", "client_del", i);
}

int nbd_hotspot_mac2ip(char const *macaddr, char *buf, size_t buf_size)
{
	return nbd_get(buf, buf_size, "hotspot", "mac2ip", macaddr);
}
