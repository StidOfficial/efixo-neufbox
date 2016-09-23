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

#define kB(X) ( (X) << 10 )
#define MB(X) ( (X) << 20 )

/*
 *       NB4 MAPPING
 * 
 * +----------------------------------+
 * |  Partition mapping               |
 * |                                  |
 * +-0x00000000-----------------------+
 * |            bootloader            | 64 kb
 * +-0x00010000-----------------------+
 * |            main firmware         | 5.3125 Mb
 * +-0x00560000-----------------------+
 * |            read/write partition  | 640 kb
 * +-0x00600000-----------------------+
 * |            rescue firmware       | 1.5 Mb
 * +-0x00780000-----------------------+
 * |            read only partition   | 448 kb
 * +-0x007f0000-----------------------+
 * |            bootloader config     | 64 kb
 * +-0x007f0000-----------------------+
 *
 * Be careful, partitions must be aligned on flash blocks (64k)
 */

#define NEUFBOX_FLASH_SIZE		( MB(8ul) )

#define NEUFBOX_BOOTLOADER_OFFSET	( 0ul )
#define NEUFBOX_BOOTLOADER_SIZE		( kB(64ul) )

#define NEUFBOX_MAINFIRMWARE_OFFSET	( NEUFBOX_BOOTLOADER_OFFSET + NEUFBOX_BOOTLOADER_SIZE )
#define NEUFBOX_MAINFIRMWARE_SIZE	( MB(5ul) + kB(320ul) )

#define NEUFBOX_JFFS2_OFFSET		( NEUFBOX_MAINFIRMWARE_OFFSET + NEUFBOX_MAINFIRMWARE_SIZE )
#define NEUFBOX_JFFS2_SIZE		( kB(640ul) )

#define NEUFBOX_RESCUEFIRMWARE_OFFSET	( NEUFBOX_JFFS2_OFFSET + NEUFBOX_JFFS2_SIZE )
#define NEUFBOX_RESCUEFIRMWARE_SIZE	( MB(1ul) + kB(512ul) )

#define NEUFBOX_ADSLFIRMWARE_OFFSET	( NEUFBOX_RESCUEFIRMWARE_OFFSET + NEUFBOX_RESCUEFIRMWARE_SIZE )
#define NEUFBOX_ADSLFIRMWARE_SIZE	( kB(448ul) )

#define NEUFBOX_BOOTLOADER_CFG_OFFSET	( NEUFBOX_ADSLFIRMWARE_OFFSET + NEUFBOX_ADSLFIRMWARE_SIZE )
#define NEUFBOX_BOOTLOADER_CFG_SIZE	( kB(64ul) )

#if ((NEUFBOX_BOOTLOADER_CFG_OFFSET + NEUFBOX_BOOTLOADER_CFG_SIZE) != (NEUFBOX_FLASH_SIZE))
#error Invalid Flash Mapping! Please fix
#endif

#endif
