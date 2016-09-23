/*!
 * \file plugins/disk.h
 *
 * \brief  Declare hotspot interface
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
 * $Id: disk.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _PLUGINNBD_DISK_H_
#define _PLUGINNBD_DISK_H_
/*
 * add info on a partition uuid
 */
int disk_stockage_add(const char *uuid);

/*
 * remove info of a partition uuid with his index
 */
int disk_stockage_del(const char *uuid);

/*
 * get availability about a partition uuid
 */
int disk_part_uuid_available(const char *uuid);

#endif
