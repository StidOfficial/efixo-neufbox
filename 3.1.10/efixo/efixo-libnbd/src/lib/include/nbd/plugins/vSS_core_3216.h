/*!
 * \file plugins/vSS_core_3216.h
 * This file is part of the NB4 project.
 *
 * Copyright (C) 2010 NeufCegetel - Efixo, Inc.
 * Written by Tanguy Bouzéloc <tanguy.bouzeloc@efixo.com> for NeufCegetel - Efixo, Inc.
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
 * $Id$
 */
#ifndef _VSS_CORE_3216_H_
#define _VSS_CORE_3216_H_

int slicTone(int param);
int slicGetReg(char type, int number);
int slicWriteReg(char type, int number, int value);
int slicMode(int param);
int gr909Voltage(void);
int gr909ResistiveFault(void);
int gr909ReceiverOffHook(void);
int gr909Ren(void);
float slicLineVoltage(void);
float slicLineCapacitance(void);
const char *slicStrError(int err);

#endif /* _VSS_CORE_3216_H_ */
