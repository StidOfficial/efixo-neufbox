/*!
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

#ifndef _PLUGIN_LAN_H_
#define _PLUGIN_LAN_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#ifndef NB5
/* diag */
#include <linux/sockios.h>
#include <net/if.h>
#ifndef X86
typedef uint64_t __u64;
#endif
#include <linux/types.h>
#include <linux/ethtool.h>
#endif

#ifdef SERVER
#include <plugins/nvram.h>
#endif /* SERVER */

#include <etk/net.h>

#define BUFFER_HOSTNAME_SIZE 256
#define NBD_BUFFER_SIZE 256

extern struct plugin lan_plugin;

/* dhcpd definitions */
typedef struct {
	char ip_addr[16];
	char mac_addr[18];
} dhcpd_static_ip_t;

typedef struct {
	size_t size;
	dhcpd_static_ip_t items[0];
} dhcpd_static_ip_list_t;

/* dns definition */
typedef struct {
	char hostname[BUFFER_HOSTNAME_SIZE];
	char ip[16];
} dnshost_t;

#ifdef SERVER

bool in_lan_network(char const *);
char const *lan_bridge_port(char const *);

/* conversion tools */
static inline int lan_arp_ip_addr(char const *mac_addr, char *ip_addr,
				  size_t len)
{
	char const *lan_ifname = system_config_txt_safe("lan_ifname");

	return arp_ip_from_mac(lan_ifname, mac_addr, ip_addr, len);
}

static inline int lan_arp_mac_addr(char const *ip_addr, char *mac_addr,
				   size_t len)
{
	char const *lan_ifname = system_config_txt_safe("lan_ifname");

	return arp_mac_from_ip(lan_ifname, ip_addr, mac_addr, len);
}

static inline int lan_arp_add_entry(char const *ip_addr, char const *mac_addr)
{
	char const *lan_ifname = system_config_txt_safe("lan_ifname");

	return arp_add_entry(lan_ifname, ip_addr, mac_addr);
}

static inline int lan_arp_del_entry(char const *ip_addr, char const *mac_addr)
{
	char const *lan_ifname = system_config_txt_safe("lan_ifname");

	return arp_del_entry(lan_ifname, ip_addr, mac_addr);
}

#endif /* SERVER */

#ifndef NB5
/********** diag **********/

/* eth stats */
typedef struct {
	uint16_t tx_good_pkts;
	uint16_t tx_good_bytes;
	uint16_t tx_unicast_pkts;
	uint16_t tx_collisions;
	uint16_t rx_good_pkts;
	uint16_t rx_good_bytes;
	uint16_t rx_unicast_pkts;
	uint16_t rx_fcs_errors;
} stats_eth_t;

typedef struct {
	char name[ETH_GSTRING_LEN];
	uint64_t value;
} gstats_eth_item_t;

typedef struct {
	unsigned int n_stats;
	gstats_eth_item_t items[0];
} gstats_eth_t;
#endif

#endif /* _PLUGIN_LAN_H_ */
