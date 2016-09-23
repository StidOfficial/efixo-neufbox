/*!
 * \file disk.h
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
 * $Id: disk.h 20228 2011-04-12 15:37:14Z vbx $
 */

#ifndef _LIBNBD_DISK_H_
#define _LIBNBD_DISK_H_

#include "plugins/disk.h"

/*
 * get list of disk and their partitions
 */
int nbd_disk_get_list(char **, size_t *);

/*
 * Umount all partitions of a disk with his devname (/dev/sda, /dev/sdb, ..)
 */
int nbd_disk_umount(const char *devpath);

/*
 * Umount all partitions of a disk with his devname (/dev/sda, /dev/sdb, ..)
 */
int nbd_disk_umount_force(const char *devpath);

/*
 * get list of part uuid present on system
 */
int nbd_disk_get_partition_uuid_list(char **, size_t *);

/*
 * get list of part uuid present on system with fs mounted
 */
int nbd_disk_get_mount_partition_uuid_list(char **, size_t *);

/*
 * get mount path from an uuid
 */
int nbd_disk_get_mntpath_from_uuid(const char *uuid, char *buf_mnt_path,
				   size_t buf_mnt_path_size);

/*
 * part uuid is online ?
 */
int nbd_disk_part_uuid_is_online(const char *uuid);

/*
 * dir listing of an partition
 */
int nbd_disk_get_dirlisting(const char *, char **, size_t *);

/*
 * add stockage information
 */
int nbd_disk_stockage_add(const char *uuid);

/*
 * del stockage information
 */
int nbd_disk_stockage_del(const char *uuid);

/*
 * get stockage information
 */
int nbd_disk_stockage_get(const char *uuid, char **buf_xml,
			  size_t * buf_xml_size);

#endif
