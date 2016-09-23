/*
 * This file is part of the NB4 project.
 *
 * Copyright (C) 2007 NeufCegetel - Efixo, Inc.
 * Written by Severin Lageder <severin.lageder@efixo.com> for NeufCegetel - Efixo, Inc.
 * 03-2007
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * $Id: vSStest.c 18304 2010-11-04 10:15:09Z mgo $
 */

 /*
  * nbdlib interface to the vSS module. purpose: Diag tools for phone HW
  */

#include <string.h>

#include "core.h"
#include "vSStest.h"

int nbd_vSStest_initScript(void)
{
	return nbd_set("vSStest", "initScript");
}

int nbd_vSStest_init(void)
{
	return nbd_set("vSStest", "initTest");
}

int nbd_vSStest_gr909(void)
{
	return nbd_set("vSStest", "gr909");
}

int nbd_vSStest_ring(void)
{
	return nbd_set("vSStest", "ring");
}

int nbd_vSStest_hookntone(void)
{
	return nbd_set("vSStest", "hookntone");
}

int nbd_vSStest_dtmf(void)
{
	return nbd_set("vSStest", "dtmf");
}

int nbd_vSStest_getResult(vSS_testResults * ptestResults)
{
	return nbd_get(ptestResults, sizeof(vSS_testResults),
		       "vSStest", "getResult");
}

int nbd_vSStest_resetResult(void)
{
	return nbd_set("vSStest", "resetResult");
}
