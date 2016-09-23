/*
 *      nb5/board.h
 *
 *      Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _NEUFBOX_BOARD_H_
#define _NEUFBOX_BOARD_H_

#include <linux/types.h>

/*! \struct serialization
 *  \brief
 */
struct serialization {
	char vendorid[16];
	char pid[16];
	unsigned char mac_address[6];
	char wpa_key[20];
	unsigned char auth_key[32];
	char dummy[34];
	__u32 cc;
};

#ifdef __KERNEL__

void neufbox_pid(char *pid, size_t len);

#endif

#endif
