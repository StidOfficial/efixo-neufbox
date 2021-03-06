/*!
 * \file eco.h
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
 * $Id: eco.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _LIBNBD_PLC_H_
#define _LIBNBD_PLC_H_

#include <stddef.h>

int nbd_eco_update(void);
int nbd_eco_show(char *buf, size_t len);

#endif
