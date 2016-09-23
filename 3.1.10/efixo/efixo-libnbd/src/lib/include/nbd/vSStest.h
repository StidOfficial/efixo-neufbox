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
 * $Id: vSStest.h 17865 2010-09-30 14:45:34Z mgo $
 */

#ifndef _VSS_TEST_H_
#define _VSS_TEST_H_

#include "plugins/vSStest.h"

int nbd_vSStest_init(void);
int nbd_vSStest_gr909(void);
int nbd_vSStest_ring(void);
int nbd_vSStest_hookntone(void);
int nbd_vSStest_dtmf(void);
int nbd_vSStest_getResult(vSS_testResults * ptestResults);
int nbd_vSStest_resetResult(void);
int nbd_vSStest_initScript(void);

#endif /* _VSS_TEST_H_ */
