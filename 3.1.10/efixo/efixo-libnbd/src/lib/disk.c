/*
 * disk.c
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

#include <stdlib.h>
#include <stdio.h>

#include "core.h"

int nbd_disk_get_list(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "disk", "get_list");
}

int nbd_disk_umount(const char *devpath)
{
	return nbd_set("disk", "umount", devpath);
}

int nbd_disk_umount_force(const char *devpath)
{
	return nbd_set("disk", "umount", devpath, "--force");
}

int nbd_disk_get_partition_uuid_list(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "disk", "get_partition_uuid_list");
}

int nbd_disk_get_mount_partition_uuid_list(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "disk", "get_mount_partition_uuid_list");
}

int nbd_disk_get_mntpath_from_uuid(const char *uuid, char *buf_mnt_path,
				   size_t buf_mnt_path_size)
{
	char *buf;

	if (nbd_get_new(&buf, NULL, "disk", "get_mntpath_from_uuid", uuid) < 0)
		return -1;

	snprintf(buf_mnt_path, buf_mnt_path_size, "%s", (char *)buf);
	free(buf);

	return 0;
}

int nbd_disk_part_uuid_is_online(const char *uuid)
{
	char buf[16];

	nbd_get(buf, sizeof(buf), "disk", "part_uuid_is_online", uuid);

	return strtol(buf, NULL, 10);
}

int nbd_disk_get_dirlisting(const char *uuid, char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "disk", "get_dirlisting", uuid);
}

int nbd_disk_stockage_add(const char *uuid)
{
	return nbd_set("disk", "stockage_add", uuid);
}

int nbd_disk_stockage_del(const char *uuid)
{
	return nbd_set("disk", "stockage_del", uuid);
}

int nbd_disk_stockage_get(const char *uuid, char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "disk", "stockage_get", uuid);
}
