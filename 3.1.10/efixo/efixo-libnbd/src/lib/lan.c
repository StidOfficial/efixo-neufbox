/*
 * lan.c
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

#include "lan.h"

#include "nvram.h"
#include "core.h"

int nbd_lan_set_ipaddr(const char *ip, const char *netmask)
{
	return nbd_set("lan", "set_ipaddr", ip, netmask);
}

int nbd_dhcpd_static_init(void)
{
	return nbd_set("lan", "dhcpd_static_init");
}

int nbd_dhcpd_add_static_ip(const char *ip, const char *mac)
{
	return nbd_set("lan", "dhcpd_add_static_ip", ip, mac);
}

int nbd_dhcpd_del_static_ip(unsigned int idx)
{
	char str_idx[8];

	snprintf(str_idx, sizeof(str_idx), "%d", idx);

	return nbd_set("lan", "dhcpd_del_static_ip", str_idx);
}

int nbd_lan_topology_update(char const *macaddr, char const *ipaddr,
			    char const *hostname)
{
	return nbd_set("lan", "topology_update", macaddr, ipaddr, hostname);
}

int nbd_dnshosts_add(const char *ipaddr, const char *domain)
{
	return nbd_set("lan", "dnshosts_add", ipaddr, domain);
}

int nbd_dnshosts_del(unsigned int idx)
{
	char str_idx[8];

	snprintf(str_idx, sizeof(str_idx), "%d", idx);

	return nbd_set("lan", "dnshosts_del", str_idx);
}

/* conversion tools */
int nbd_lan_mac2ip(char const *mac, char *ip, size_t len)
{
	return nbd_get(ip, len, "lan", "mac2ip", mac);
}

int nbd_lan_ip2mac(char const *ip, char *mac, size_t len)
{
	return nbd_get(mac, len, "lan", "ip2mac", ip);
}

/* stats */
int nbd_lan_stats(char **xml, size_t * size, const char *filter)
{
	return nbd_get_new(xml, size, "lan", "stats", filter);
}

int nbd_lan_fullstats(char **xml, size_t * size, const char *filter)
{
	return nbd_get_new(xml, size, "lan", "fullstats", filter);
}
