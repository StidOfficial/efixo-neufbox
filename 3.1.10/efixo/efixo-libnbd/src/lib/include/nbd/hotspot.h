/*!
 * \file hotspot.h
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
 * $Id: hotspot.h 19606 2011-03-02 10:12:30Z avd $
 */

#ifndef _HOTSPOT_H
#define _HOTSPOT_H

#include <stddef.h>

/*! \fn int nbd_hotspot_start (void)
    \brief Start hotspot.
    \return: 0: success  -1: failure
 */
int nbd_hotspot_start(void);

/*! \fn int nbd_hotspot_stop (void)
    \brief Stop hotspot.
    \return: 0: success  -1: failure
 */
int nbd_hotspot_stop(void);

/*! \fn int nbd_hotspot_stop (void)
    \brief Restart hotspot.
    \return: 0: success  -1: failure
 */
int nbd_hotspot_restart(void);

/* \fn int nbd_hotspot_ssid(void)
   \brief Get hotspot ssid.
    \return: 0: success  -1: failure
 */
int nbd_hotspot_ssid(char *, size_t);

int nbd_hotspot_client_add(char const *, char const *);
int nbd_hotspot_client_del(char const *);

int nbd_hotspot_mac2ip(char const *macaddr, char *buf, size_t buf_size);

#endif /* _HOTSPOT_H */
