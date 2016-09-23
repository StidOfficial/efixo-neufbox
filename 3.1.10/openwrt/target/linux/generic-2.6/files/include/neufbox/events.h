/*
 *      neufbox/events.h
 *
 *      Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _NEUFBOX_EVENT_H_
#define _NEUFBOX_EVENT_H_

enum event_id {
	event_id_dummy,

	event_id_sw_reset_pushed,
	event_id_sw_reset_released,
	event_id_sw_reset_held,

	event_id_sw_clip_pushed,
	event_id_sw_clip_released,
	event_id_sw_clip_held,

	event_id_sw_service_pushed,
	event_id_sw_service_released,
	event_id_sw_service_held,

	event_id_sw_eco_pushed,
	event_id_sw_eco_released,
	event_id_sw_eco_held,

	event_id_sw_wlan_pushed,
	event_id_sw_wlan_released,
	event_id_sw_wlan_held,

	event_id_sw_wps_pushed,
	event_id_sw_wps_released,
	event_id_sw_wps_held,

	event_id_eth0_up,
	event_id_eth0_down,
	event_id_eth1_up,
	event_id_eth1_down,
	event_id_port0_up,
	event_id_port0_down,
	event_id_port1_up,
	event_id_port1_down,
	event_id_port2_up,
	event_id_port2_down,
	event_id_port3_up,
	event_id_port3_down,
	event_id_port4_up,
	event_id_port4_down,
	event_id_usb0_up,
	event_id_usb0_down,

	event_id_wlan_up,
	event_id_wlan_down,
	event_id_wps_up,
	event_id_wps_down,

	event_id_data_up,
	event_id_data_down,
	event_id_voip_up,
	event_id_voip_down,
	event_id_voip_login_up,
	event_id_voip_login_down,
	event_id_voip_line_up,
	event_id_voip_line_down,
	event_id_voip_onhook,
	event_id_voip_offhook,
	event_id_voip_missed_call,
	event_id_voip_stop_missed_call,
	event_id_voip_reset_counters,
	event_id_tv_up,
	event_id_tv_down,

	event_id_dhcp_wan_up,
	event_id_dhcp_wan_down,
	event_id_dhcp_voip_up,
	event_id_dhcp_voip_down,
	event_id_dhcp_tv_up,
	event_id_dhcp_tv_down,

	event_id_ppp_adsl_up,
	event_id_ppp_adsl_down,
	event_id_ppp_gprs_up,
	event_id_ppp_gprs_down,

	event_id_adsl_up,
	event_id_adsl_down,

	event_id_boot_succeeded,
	event_id_boot_failed,

	event_id_ipv6_up,
	event_id_ipv6_down,

	event_id_last
};

static inline char const *event_c_str(enum event_id id)
{
	switch (id) {
	case event_id_dummy:
		return "dummy";

	case event_id_sw_reset_pushed:
		return "sw-reset-pushed";
	case event_id_sw_reset_released:
		return "sw-reset-released";
	case event_id_sw_reset_held:
		return "sw-reset-held";

	case event_id_sw_clip_pushed:
		return "sw-clip-pushed";
	case event_id_sw_clip_released:
		return "sw-clip-released";
	case event_id_sw_clip_held:
		return "sw-clip-held";

	case event_id_sw_service_pushed:
		return "sw-service-pushed";
	case event_id_sw_service_released:
		return "sw-service-released";
	case event_id_sw_service_held:
		return "sw-service-held";

	case event_id_sw_eco_pushed:
		return "sw-eco-pushed";
	case event_id_sw_eco_released:
		return "sw-eco-released";
	case event_id_sw_eco_held:
		return "sw-eco-held";

	case event_id_sw_wlan_pushed:
		return "sw-wlan-pushed";
	case event_id_sw_wlan_released:
		return "sw-wlan-released";
	case event_id_sw_wlan_held:
		return "sw-wlan-held";

	case event_id_sw_wps_pushed:
		return "sw-wps-pushed";
	case event_id_sw_wps_released:
		return "sw-wps-released";
	case event_id_sw_wps_held:
		return "sw-wps-held";

	case event_id_eth0_up:
		return "eth0-up";
	case event_id_eth0_down:
		return "eth0-down";
	case event_id_eth1_up:
		return "eth1-up";
	case event_id_eth1_down:
		return "eth1-down";
	case event_id_port0_up:
		return "port0-up";
	case event_id_port0_down:
		return "port0-down";
	case event_id_port1_up:
		return "port1-up";
	case event_id_port1_down:
		return "port1-down";
	case event_id_port2_up:
		return "port2-up";
	case event_id_port2_down:
		return "port2-down";
	case event_id_port3_up:
		return "port3-up";
	case event_id_port3_down:
		return "port3-down";
	case event_id_port4_up:
		return "port4-up";
	case event_id_port4_down:
		return "port4-down";
	case event_id_usb0_up:
		return "usb0-up";
	case event_id_usb0_down:
		return "usb0-down";

	case event_id_wlan_up:
		return "wlan-up";
	case event_id_wlan_down:
		return "wlan-down";
	case event_id_wps_up:
		return "wps-up";
	case event_id_wps_down:
		return "wps-down";

	case event_id_data_up:
		return "data-up";
	case event_id_data_down:
		return "data-down";
	case event_id_voip_up:
		return "voip-up";
	case event_id_voip_down:
		return "voip-down";
	case event_id_voip_login_up:
		return "voip-login-up";
	case event_id_voip_login_down:
		return "voip-login-down";
	case event_id_voip_line_up:
		return "voip-line-up";
	case event_id_voip_line_down:
		return "voip-line-down";
	case event_id_voip_reset_counters:
		return "voip-reset-counters";
	case event_id_voip_onhook:
		return "voip-onhook";
	case event_id_voip_offhook:
		return "voip-offhook";
	case event_id_voip_missed_call:
		return "voip-missed-call";
	case event_id_voip_stop_missed_call:
		return "voip-stop-missed-call";
	case event_id_tv_up:
		return "tv-up";
	case event_id_tv_down:
		return "tv-down";

	case event_id_dhcp_wan_up:
		return "dhcp-wan-up";
	case event_id_dhcp_wan_down:
		return "dhcp-wan-down";
	case event_id_dhcp_voip_up:
		return "dhcp-voip-up";
	case event_id_dhcp_voip_down:
		return "dhcp-voip-down";
	case event_id_dhcp_tv_up:
		return "dhcp-tv-up";
	case event_id_dhcp_tv_down:
		return "dhcp-tv-down";

	case event_id_ppp_adsl_up:
		return "ppp_adsl-up";
	case event_id_ppp_adsl_down:
		return "ppp_adsl-down";
	case event_id_ppp_gprs_up:
		return "ppp_gprs-up";
	case event_id_ppp_gprs_down:
		return "ppp_gprs-down";

	case event_id_adsl_up:
		return "adsl-up";
	case event_id_adsl_down:
		return "adsl-down";

	case event_id_boot_succeeded:
		return "boot-succeeded";
	case event_id_boot_failed:
		return "boot-failed";

	case event_id_ipv6_up:
		return "ipv6-up";
	case event_id_ipv6_down:
		return "ipv6-down";

	case event_id_last:
		return "";
	}
	
	return "";
}

#ifdef __KERNEL__
void event_enqueue(unsigned id);
#endif

#endif
