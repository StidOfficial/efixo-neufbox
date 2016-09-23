/*!
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
 * $Id: vSS_core.h 17865 2010-09-30 14:45:34Z mgo $
 */

/*!
 * nbd interface to the vSS module. purpose: Diag tools for phone HW
 */

#ifndef _VSS_CORE_H
#define _VSS_CORE_H

#include <stdint.h>

#include "vSStest.h"

#include "query.h"

#define VSS_OFF     0
#define VSS_ON      1
#define VSS_SEQ     2
#define VSS_VOIP    3
#define VSS_PSTN    4
#define VSS_OPEN    5
#define VSS_FWA     6
#define VSS_FWOHT   7
#define VSS_TIPO    8
#define VSS_RNG     9
#define VSS_RVA     10
#define VSS_RVOHT   11
#define VSS_RNGO    12

#define VSS_ONHOOK     1
#define VSS_OFFHOOK    2
#define VSS_HOOKCHG    VSS_SEQ

#define ONHOOK_VMAX     54
#define ONHOOK_VMIN     45
#define ONHOOK_IMAX     5
#define ONHOOK_IMIN     0
#define OFFHOOK_VMAX    25
#define OFFHOOK_VMIN    1
#define OFFHOOK_IMAX    34
#define OFFHOOK_IMIN    2

/* Error defs */
#define VSS_ERR_DEVOPEN	1
#define VSS_ERR_MALLOC	2
#define VSS_ERR_CMD	3
#define VSS_ERR_IOCTL	4

/* GR909 voltage errors */
#define VSS_VOLTAGES_AC_HAZARDOUS	1
#define VSS_VOLTAGES_DC_HAZARDOUS	2
#define VSS_VOLTAGES_AC_FOREIGN		4
#define VSS_VOLTAGES_DC_FOREIGN		8

/* GR909 resistive errors */
#define VSS_RESISTIVE_FAULT_RTG		1
#define VSS_RESISTIVE_FAULT_RRG		2
#define VSS_RESISTIVE_FAULT_RTR		4

typedef enum VSS_EVENTS {
	VSSEV_NO_EVENT,
	VSSEV_SLIC_ONHOOK,
	VSSEV_SLIC_OFFHOOK,
	VSSEV_UNKNOWN,
	VSSEV_MAX
} VSS_EVENTS;

typedef enum VSS_TEST_IDS {
	VSS_INIT,
	VSS_GR909,
	VSS_RING,
	VSS_HOOKNTONE,
	VSS_DTMF,
	VSS_MAX_ID
} VSS_TEST_IDS;

typedef struct {
	char result[RESULT_MAX_CHAR];
} vSS_resultTable;

int vSS_ring(void);
int vSS_init(void);
int vSS_gr909(void);
int vSS_hookntone(void);
int vSS_dtmf(void);
int vSS_exploitResults(void);
int vSS_createResultsStr(char **str);

#endif
