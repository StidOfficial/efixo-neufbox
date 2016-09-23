/*!
 * \file core.h
 *
 * \note Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: core.h 20152 2011-04-07 13:34:51Z avd $
 */

#ifndef _CORE_H_
#define _CORE_H_

#include <stddef.h>
#include "plugins.h"

#define NBD_CMDLEN      (512)
#define NBD_64K_BUFFER  (64 << 10)

/*! \enum query_status_enum
 *  \brief Enum query error code
 */
enum query_status_enum {
	/* backup3g errors */
	backup3g_error_invalid_puk = -1000,
	backup3g_error_invalid_newpin,
	/* sambactl errors */
	sambactl_error_invalid_name,
	/* nat errors */
	nat_error_invalid_protocol,
	nat_error_invalid_ip,
	nat_error_invalid_dstport,
	nat_error_invalid_dstportrange,
	nat_error_invalid_extport,
	nat_error_invalid_extportrange,
	nat_error_extport_already_use,
	nat_error_extport_reserved,
	/* lan errors */
	lan_error_dhcpd_static_ip_already_exist,
	lan_error_dhcpd_static_mac_already_exist,
	lan_error_dhcpd_static_del_error,
	lan_error_ip_invalid,
	lan_error_mac_invalid,
	lan_error_dnshost_already_exist,
	lan_error_dnshost_hostname_already_used,
	/* disk errors */
	disk_error_umount_failed,
	disk_error_umount_failed_invalid,
	disk_error_umount_failed_busy,
	/* standard errors */
	query_status_invalid_format = -4,
	query_status_internal_error = -3,
	query_status_usage = -2,
	query_status_failed = -1,
	query_status_succeeded = 0,
	query_status_unchanged = 1,
};

/*! \fn int nbd_open (void)
    \brief Open nbd connection.
    \return: 0: success  -1: failure
 */
int nbd_open(void);

/*! \fn void nbd_close (void)
    \brief Close nbd connection.
    \return: 0
 */
void nbd_close(void);

/*! \fn int nbd_query (char const *plugin, char const *cmd, char const *arg1, char const *arg2, void *out, size_t olen)
    \brief Send command to nbd.
    \param out output data.
    \param olen sizeof output data.
    \param plugin Plugin target id.
    \param ... list of arguments.
    \return: 0: success  -1: failure
 */
int nbd_query(void *out, size_t outlen, char const *plugin, ...);

/*! \fn int nbd_query (char const *plugin, char const *cmd, char const *arg1, char const *arg2, void *out, size_t olen)
    \brief Send command to nbd.
    \param out output data.
    \param olen sizeof output data.
    \param plugin Plugin target id.
    \param ... list of arguments.
    \return: 0: success  -1: failure
 */
int nbd_query_new(char **out, size_t * outlen, char const *plugin, ...);

/*! \def int nbd_set(plugin, ...)
    \brief Send "set" command to nbd.
    \param plugin Plugin target id.
    \param ... list of arguments.
    \return: 0: success  -1: failure
 */
#define nbd_set(plugin, ...)           nbd_query(NULL, 0, plugin, __VA_ARGS__, NULL)

/*! \def int nbd_get(out, len, plugin, ...)
    \brief Send "set" command to nbd.
    \param out output data.
    \param olen sizeof output data.
    \param plugin Plugin target id.
    \param ... list of arguments.
    \return: 0: success  -1: failure
 */
#define nbd_get(out, len, plugin, ...) nbd_query(out, len, plugin, __VA_ARGS__, NULL)

/*! \def int nbd_get(out, len, plugin, ...)
    \brief Send "set" command to nbd.
    \param out output data.
    \param olen sizeof output data.
    \param plugin Plugin target id.
    \param ... list of arguments.
    \return: 0: success  -1: failure
 */
#define nbd_get_new(out, len, plugin, ...) nbd_query_new(out, len, plugin, __VA_ARGS__, NULL)

#endif /* _CORE_H_ */
