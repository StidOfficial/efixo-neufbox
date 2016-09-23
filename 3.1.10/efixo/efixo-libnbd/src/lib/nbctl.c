/*
 * nbctl.c
 *
 * Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
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
 * $Id: nbctl.c 18304 2010-11-04 10:15:09Z mgo $
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "core.h"
#include "nbctl.h"

int nbd_sys_reboot(void)
{
	return nbd_set("nbctl", "reboot");
}

int nbd_sys_hard_reboot(void)
{
	return nbd_set("nbctl", "reboot", "now");
}

int nbd_sys_dump(char const *file)
{
	return nbd_set("nbctl", "diag_report", file);
}

int nbd_sys_mac(char const *offset, char const *format, char *data, size_t len)
{
	return nbd_get(data, len, "nbctl", "mac", offset, format);
}

int nbd_sys_set_rootfs(char const *target)
{
	return nbd_set("nbctl", "rootfs", target);
}

int nbd_sys_delay_run(char const *delay, char const *script, char const *arg)
{
	return nbd_set("nbctl", "delay_run", delay, script, arg);
}

int nbd_sys_async_run(char const *script, char const *arg)
{
	return nbd_set("nbctl", "async_run", script, arg);
}

int nbd_sys_sync_run(char const *script, char const *arg)
{
	return nbd_set("nbctl", "sync_run", script, arg);
}

int nbd_halt_webautologin(void)
{
	return nbd_set("nbctl", "halt_webautologin");
}

int nbd_notify_failure(int errcode)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", errcode);
	return nbd_set("nbctl", "failure", buf);
}

int nbd_gruiks(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "nbctl", "gruiks");
}
