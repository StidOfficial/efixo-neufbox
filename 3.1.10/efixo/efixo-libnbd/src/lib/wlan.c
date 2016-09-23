/*
 * wlan.c
 *
 * Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: wlan.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "core.h"
#include "wlan.h"

int nbd_wlan_active(char *data, size_t data_size)
{
	return nbd_get(data, data_size, "wlan", "active");
}

int nbd_wlan_enable(void)
{
	return nbd_set("wlan", "active", "on");
}

int nbd_wlan_disable(void)
{
	return nbd_set("wlan", "active", "off");
}

int nbd_wlan_start(void)
{
	return nbd_set("wlan", "start");
}

int nbd_wlan_stop(void)
{
	return nbd_set("wlan", "stop");
}

int nbd_wlan_restart(void)
{
	return nbd_set("wlan", "restart");
}

int nbd_wlan_ses_done(void)
{
	return nbd_set("wlan", "ses_done");
}

int nbd_wlan_add_mac(char const *mac)
{
	return nbd_set("wlan", "add", "mac", mac);
}

int nbd_wlan_del_mac(char const *mac)
{
	return nbd_set("wlan", "del", "mac", mac);
}

int nbd_wlan_macfiltering(char const *mode)
{
	return nbd_set("wlan", "macfiltering", mode);
}

int nbd_wlan_macfiltering_mode(char *data, size_t len)
{
	return nbd_get(data, len, "wlan", "macfiltering");
}

int nbd_wlan_list_assoc(char const *ifname, char **xml, size_t * xml_size)
{
	return nbd_get_new(xml, xml_size, "wlan", "list", "assoc", ifname);
}

int nbd_wlan_assoc_count(char const *ifname)
{
	char buf[4];

	if (nbd_get(buf, sizeof(buf), "wlan", "list", "assoc_count", ifname) <
	    0)
		return -1;

	return strtol(buf, NULL, 10);
}

int nbd_wlan_list_contains_mac(char const *mac)
{
	return nbd_set("wlan", "list_contains", "mac", mac);
}

int nbd_wlan_list_contains_assoc(char const *mac, char const *ifname)
{
	return nbd_set("wlan", "list_contains", "assoc", mac, ifname);
}

int nbd_wlan_get_current_channel(char *data, size_t len)
{
	return nbd_get(data, len, "wlan", "currentchannel");
}

int nbd_wlan_diag_host(char **out, size_t * size, const char *mac_addr)
{
	return nbd_get_new(out, size, "wlan", "diag_host", mac_addr);
}

int nbd_wlan_get_diag_host(wl_host_diag_t ** wl_host_diag, const char *mac_addr)
{
	return nbd_get_new((char **)wl_host_diag,
			   NULL, "wlan", "get_diag_host", mac_addr);
}

int nbd_wlan_get_rssi(uint32_t * val, const char *mac_addr)
{
	return nbd_get(val, sizeof(*val), "wlan", "get_rssi", mac_addr);
}

int nbd_wlan_get_counters(char **buf, size_t * size)
{
	return nbd_get_new(buf, size, "wlan", "get_counters");
}

int nbd_wlan_bss(char *mac, size_t len, char const *idx)
{
	return nbd_get(mac, len, "wlan", "bss", idx);
}
