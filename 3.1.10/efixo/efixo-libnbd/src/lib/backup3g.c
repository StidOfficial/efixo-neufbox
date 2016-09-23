/*
 * \file backup3g.c
 *
 * \note Copyright 2009 Severin Lageder <severin.lageder@efixo.com>
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
 * $Id: backup3g.c 8781 2008-10-13 13:42:59Z mgo $
 */

#include <stdlib.h>
#include "core.h"
#include "backup3g.h"

int nbd_backup3g_start(char *option)
{
	return nbd_set("backup3g", "start", option);
}

int nbd_backup3g_stop(char *option)
{
	return nbd_set("backup3g", "stop", option);
}

int nbd_backup3g_restart(void)
{
	return nbd_set("backup3g", "restart");
}

int nbd_backup3g_getInfo(char **info, size_t * length)
{
	return nbd_get_new(info, length, "backup3g", "getInfo");
}

int nbd_backup3g_puk_unlock(const char const *puk, const char const *newpin)
{
	return nbd_set("backup3g", "puk_unlock", puk, newpin);
}

int nbd_backup3g_unlock_simprotect(void)
{
	return nbd_set("backup3g", "unlock_simprotect");
}

int nbd_backup3g_init_session(void)
{
	return nbd_set("backup3g", "init_session");
}

int nbd_backup3g_end_session(void)
{
	return nbd_set("backup3g", "end_session");
}
