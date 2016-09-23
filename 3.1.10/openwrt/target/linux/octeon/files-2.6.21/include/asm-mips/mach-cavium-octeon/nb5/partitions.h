/*
 *      neufbox/flash.h
 *
 *      Copyright 2006 Miguel GAIO <miguel.gaio@efixo.com>
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

#ifndef _NEUFBOX_FLASH_H_
#define _NEUFBOX_FLASH_H_

/*!
 *  \note jffs2 needs at least 5 erase blocks
 * 
 * +----------------------------------+
 * |  Partition mapping               |
 * |                                  |
 * +-0x00000000-----------------------+
 * |            bootloader            | 384 kb
 * +-0x00060000-----------------------+
 * |            NvRam bootloader      | 128 kb
 * +-0x00080000-----------------------+
 * |            main firmware         | 12 Mb
 * +-0x00C80000-----------------------+
 * |            rescue firmware       | 3 Mb - 512 kb
 * +-0x00F00000-----------------------+
 * |            nvram                 | 1 Mb
 * +-0x01000000-----------------------+
 *
 */

#define kB(X) ( (X) << 10 )
#define MB(X) ( (X) << 20 )

#define NEUFBOX_FLASH_BASE		( 0x1EC00000 + (1ULL<<48) )
#define NEUFBOX_FLASH_SIZE		( MB(16ul) )

#define NEUFBOX_BOOTLOADER_OFFSET	( 0ul )
#define NEUFBOX_BOOTLOADER_SIZE		( kB(384ul) )

#define NEUFBOX_UBOOTNVRAM_OFFSET	( NEUFBOX_BOOTLOADER_OFFSET + NEUFBOX_BOOTLOADER_SIZE )
#define NEUFBOX_UBOOTNVRAM_SIZE		( kB(128ul) )

#define NEUFBOX_MAINFIRMWARE_OFFSET	( NEUFBOX_UBOOTNVRAM_OFFSET + NEUFBOX_UBOOTNVRAM_SIZE )
#define NEUFBOX_MAINFIRMWARE_SIZE	( MB(12ul) )

#define NEUFBOX_RESCUEFIRMWARE_OFFSET	( NEUFBOX_MAINFIRMWARE_OFFSET + NEUFBOX_MAINFIRMWARE_SIZE )
#define NEUFBOX_RESCUEFIRMWARE_SIZE	( MB(3ul) - kB(512ul) )

#define NEUFBOX_JFFS2_OFFSET		( NEUFBOX_RESCUEFIRMWARE_OFFSET + NEUFBOX_RESCUEFIRMWARE_SIZE )
#define NEUFBOX_JFFS2_SIZE		( MB(1ul) )

#endif				/* _NEUFBOX_FLASH_H_ */
