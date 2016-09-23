/*!
 * \file nat.h
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
 * $Id: nat.h 21347 2011-08-31 12:48:36Z slr $
 */

#ifndef LIBNBD_NAT_H
#define LIBNBD_NAT_H

#include <sys/types.h>

extern int nbd_nat_add(const char *rulename, const char *proto,
		       const char *ext_port, const char *dst_ip,
		       const char *dst_port, const char *activated);
extern int nbd_nat_del_by_index(unsigned int idx);

extern int nbd_nat_active(unsigned int idx, const char *activation);

extern int nbd_nat_dmz_setup(void);

extern int nbd_nat_upnp_list(char **buf, size_t * len);
extern unsigned int nbd_nat_upnp_count(void);

extern int nbd_nat_sipalg(const char *target_state);

#endif
