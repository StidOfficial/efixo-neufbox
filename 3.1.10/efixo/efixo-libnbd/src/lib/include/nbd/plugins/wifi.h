/*!
 * \file plugins/include/plugins/wifi.h
 *
 * \brief  wifi plugin header.
 *
 * \author Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: status.h 8219 2008-09-16 08:17:00Z mgo $
 */

#ifndef _PLUGINS_WIFI_
#define _PLUGINS_WIFI_

struct xml;

/* wifi facilities */
#ifdef DEBUG
void wifi_buf_dump(char const *title, void const *data, size_t len);
#endif /* DEBUG */

char const *wifi_get_ifname(char const *bss);

int wifi_xml_add(struct xml *xml, char const *bss, char const *key,
		 char const *new, char const *data);

int wifi_xml_add_int(struct xml *xml, char const *bss, char const *key,
		     char const *new, int val);

int wifi_xml_del(struct xml *xml, char const *bss, char const *key);

int wifi_xml_set(struct xml *xml, char const *bss, char const *key,
		 char const *data);

/* wifi HAL features */
int hal_wifi_deauthenticate_mac(char const *ifname, struct ether_addr *addr);

int hal_wifi_set_macmode(char const *ifname, char const *macmode);

int hal_wifi_add_mac(char const *ifname, struct ether_addr *addr);

int hal_wifi_del_mac(char const *ifname, struct ether_addr *addr);

int hal_wifi_add_wds(char const *ifname, struct ether_addr *addr);

int hal_wifi_del_wds(char const *ifname, struct ether_addr *addr);

int hal_wifi_update_currentchannel(void);

int hal_wifi_update_macmode(char const *bss);

int hal_wifi_update_counters(char const *bss);

int hal_wifi_update_stations(char const *bss);

int hal_wifi_update_maclist(char const *bss);

enum wifi_error_enum {
	wifi_error_mac_invalid = -1000,
	wifi_error_mac_already_used,
};
#endif /* _PLUGINS_WIFI_ */
